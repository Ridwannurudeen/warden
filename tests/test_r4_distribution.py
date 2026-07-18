"""The installable root wheel retains scanner runtime data away from the checkout."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INDEX"] = "1"
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _copy_minimal_project(repo_root: Path, project: Path) -> None:
    project.mkdir()
    for name in ("pyproject.toml", "MANIFEST.in", "README.md"):
        shutil.copy2(repo_root / name, project / name)
    shutil.copytree(repo_root / "audit", project / "audit")
    shutil.copytree(repo_root / "warden", project / "warden")


def test_clean_wheel_install_imports_runtime_data(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    project = tmp_path / "project"
    _copy_minimal_project(repo_root, project)
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()

    build = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(project),
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
        ],
        cwd=tmp_path,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    wheels = list(wheel_dir.glob("warden-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        assert "warden/analyzers/bip39_words.txt" in archive.namelist()
        assert "warden/corpus_fingerprint.txt" in archive.namelist()
        assert "audit/warden-core-http-2026-07.json" in archive.namelist()

    target = tmp_path / "site-packages"
    install = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-compile",
            "--target",
            str(target),
            str(wheel),
        ],
        cwd=tmp_path,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    verify = _run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from pathlib import Path; "
                f"target = Path({str(target)!r}).resolve(); sys.path.insert(0, str(target)); "
                "import warden; "
                "from warden.analyzers.exfiltration import BIP39_WORDS; "
                "from warden.auditor import "
                "AUDIT_BATTERY_PATH, AUDIT_BATTERY_SHA256, AUDIT_BATTERY_SIZE; "
                "from warden.feedback_store import corpus_fingerprint; "
                "assert Path(warden.__file__).resolve().is_relative_to(target); "
                "assert AUDIT_BATTERY_PATH.resolve().is_relative_to(target); "
                "assert AUDIT_BATTERY_PATH.is_file(); "
                "assert AUDIT_BATTERY_SHA256 == "
                "'7e18f89d7249fe97e007f37dc91839492cfb7a40af4d7b660309645c0fe33f3f'; "
                "assert AUDIT_BATTERY_SIZE == 20; "
                "assert len(BIP39_WORDS) == 2048; "
                "assert corpus_fingerprint() == "
                "'sha256:b095d7653635dfa734ee21a52afe93e5716be520a2340719b2b3465bb85c58fc'"
            ),
        ],
        cwd=tmp_path,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr


def test_clean_sdist_contains_endpoint_audit_battery(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    project = tmp_path / "project"
    _copy_minimal_project(repo_root, project)
    dist = tmp_path / "dist"

    build = _run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(dist),
        ],
        cwd=project,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    sdists = list(dist.glob("warden-*.tar.gz"))
    assert len(sdists) == 1
    with tarfile.open(sdists[0], "r:gz") as archive:
        assert any(
            name.endswith("/audit/warden-core-http-2026-07.json") for name in archive.getnames()
        )


def test_packaged_corpus_fingerprint_matches_source_corpus() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    content = b"".join(
        (repo_root / "corpus" / filename).read_bytes()
        for filename in ("attacks.jsonl", "benign.jsonl")
    )
    content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    assert (repo_root / "warden" / "corpus_fingerprint.txt").read_text(
        encoding="ascii"
    ).strip() == hashlib.sha256(content).hexdigest()
