"""Framework-neutral pipeline callable and typed-wheel regressions."""

from __future__ import annotations

from importlib.metadata import version
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

from warden_guard import (
    AsyncTextGuard,
    AsyncWardenClient,
    GuardedText,
    ScanResult,
    TextGuard,
    WardenBlocked,
    WardenClient,
    __version__,
)
from warden_guard import __all__ as public_exports

SDK_ROOT = Path(__file__).resolve().parents[1]


class StubSyncClient(WardenClient):
    def __init__(self, safe_text: str | None = None) -> None:
        self.safe_text = safe_text
        self.payloads: list[str] = []

    def guard(self, payload: str, **kwargs: object) -> str:
        self.payloads.append(payload)
        if self.safe_text is None:
            raise WardenBlocked(
                ScanResult(
                    verdict="BLOCK",
                    risk_level="HIGH",
                    threat_classes=["PROMPT_INJECTION"],
                )
            )
        return self.safe_text


class StubAsyncClient(AsyncWardenClient):
    def __init__(self, safe_text: str) -> None:
        self.safe_text = safe_text
        self.payloads: list[str] = []

    async def guard(self, payload: str, **kwargs: object) -> str:
        self.payloads.append(payload)
        return self.safe_text


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INDEX"] = "1"
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_sync_text_guard_is_a_strict_reusable_callable() -> None:
    client = StubSyncClient("sanitized")
    guard = TextGuard(client)

    safe = guard("untrusted")

    assert safe == "sanitized"
    assert type(safe) is str
    assert GuardedText.__supertype__ is str
    assert client.payloads == ["untrusted"]
    with pytest.raises(TypeError, match="payload must be a string"):
        guard(42)  # type: ignore[arg-type]
    assert client.payloads == ["untrusted"]


def test_sync_text_guard_preserves_block_enforcement() -> None:
    guard = TextGuard(StubSyncClient())

    with pytest.raises(WardenBlocked) as blocked:
        guard("poison")

    assert blocked.value.result.threat_classes == ["PROMPT_INJECTION"]


async def test_async_text_guard_has_the_same_typed_contract() -> None:
    client = StubAsyncClient("sanitized async")
    guard = AsyncTextGuard(client)

    safe = await guard("untrusted async")

    assert safe == "sanitized async"
    assert type(safe) is str
    assert client.payloads == ["untrusted async"]
    with pytest.raises(TypeError, match="payload must be a string"):
        await guard(None)  # type: ignore[arg-type]
    assert client.payloads == ["untrusted async"]


def test_package_exports_distribution_version_and_pipeline_types() -> None:
    assert __version__ == version("warden-agent-guard") == "0.1.2"
    assert {"AsyncTextGuard", "GuardedText", "TextGuard", "__version__"} <= set(public_exports)


def test_clean_sdk_wheel_contains_typing_marker_and_version(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    shutil.copy2(SDK_ROOT / "pyproject.toml", project / "pyproject.toml")
    shutil.copy2(SDK_ROOT / "README.md", project / "README.md")
    shutil.copytree(SDK_ROOT / "warden_guard", project / "warden_guard")
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

    wheels = list(wheel_dir.glob("warden_agent_guard-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        assert "warden_guard/py.typed" in archive.namelist()

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
                "import warden_guard; "
                "from importlib.metadata import version; "
                "assert Path(warden_guard.__file__).resolve().is_relative_to(target); "
                "assert warden_guard.__version__ == version('warden-agent-guard') == '0.1.2'; "
                "assert warden_guard.GuardedText.__supertype__ is str"
            ),
        ],
        cwd=tmp_path,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
