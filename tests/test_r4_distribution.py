"""The installable root wheel retains scanner runtime data away from the checkout."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
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


def test_clean_wheel_install_imports_bip39_wordlist(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy2(repo_root / "pyproject.toml", project / "pyproject.toml")
    shutil.copy2(repo_root / "MANIFEST.in", project / "MANIFEST.in")
    shutil.copytree(repo_root / "warden", project / "warden")
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
            "-I",
            "-c",
            (
                "import sys; from pathlib import Path; "
                f"target = Path({str(target)!r}).resolve(); sys.path.insert(0, str(target)); "
                "import warden; "
                "from warden.analyzers.exfiltration import BIP39_WORDS; "
                "assert Path(warden.__file__).resolve().is_relative_to(target); "
                "assert len(BIP39_WORDS) == 2048"
            ),
        ],
        cwd=tmp_path,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
