"""Executable hardening-loop demo coverage."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))

from run_hardening_loop import run_loop  # noqa: E402


def test_run_loop_produces_verified_f_to_a_evidence() -> None:
    result = asyncio.run(run_loop())

    assert result["mode"] == "local-no-funds"
    assert result["before"]["grade"] == "F"
    assert result["after"]["grade"] == "A"
    assert result["after"]["score"] > result["before"]["score"]
    assert result["hardening_pack"]["addressed_classes"]
    assert result["hardening_pack"]["signature_verified"] is True
    assert result["transparency"] == {
        "events": [
            "audit-issued",
            "hardening-pack-issued",
            "audit-issued",
        ],
        "checkpoint_seq": 3,
        "chain_verified": True,
    }
    assert "does not prove" in result["limitations"]


def test_compact_cli_is_valid_json_and_no_funds() -> None:
    completed = subprocess.run(
        [sys.executable, "demo/run_hardening_loop.py", "--compact"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    result = json.loads(completed.stdout)
    assert result["mode"] == "local-no-funds"
    assert result["before"]["grade"] == "F"
    assert result["after"]["grade"] == "A"
