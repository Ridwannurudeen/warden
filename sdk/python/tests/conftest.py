"""Test setup for the warden-agent-guard SDK.

Makes `warden_guard` (sdk/python) and the repo root (`warden`, `spec/`)
importable, and isolates the guard key + scan-counter state into tmp dirs so
tests never touch `~/.warden`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
for entry in (str(SDK_ROOT), str(REPO_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)


@pytest.fixture(autouse=True)
def isolated_guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("WARDEN_GUARD_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("WARDEN_GUARD_KEY", str(tmp_path / "guard_key"))
    return tmp_path
