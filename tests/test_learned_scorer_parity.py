"""The learned advisory layer must be verdict-inert across the whole held-out set."""

import json
from pathlib import Path

import pytest

from warden.engine import WardenEngine
from warden.scanner.learned import build_learned_scorer_from_env

ROOT = Path(__file__).resolve().parents[1]
HELD_OUT = (
    ROOT / "benchmark" / "held_out_attacks.jsonl",
    ROOT / "benchmark" / "held_out_benign.jsonl",
)


def held_out_payloads() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in HELD_OUT:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                rows.append((str(record["id"]), str(record["payload"])))
    return rows


def comparable(verdict) -> dict[str, object]:
    return {
        "verdict": verdict.verdict,
        "risk_level": verdict.risk_level,
        "threat_classes": [reason.value for reason in verdict.threat_classes],
        "detections": verdict.detections,
        "sanitized_payload": verdict.sanitized_payload,
        "recommendation": verdict.recommendation,
        "failed_checks": [reason.value for reason in verdict.failed_checks],
        "checks": {key: value for key, value in verdict.checks.items() if key != "learned_scorer"},
    }


@pytest.mark.parametrize("depth", ["fast", "thorough"])
async def test_shipped_model_changes_no_held_out_verdict(depth: str) -> None:
    scorer = build_learned_scorer_from_env({"WARDEN_LEARNED_SCORER_ENABLED": "1"})
    assert scorer is not None
    baseline_engine = WardenEngine()
    advised_engine = WardenEngine(learned_scorer=scorer)
    assert baseline_engine.learned_scorer_enabled is False
    assert advised_engine.learned_scorer_enabled is True

    differences: list[str] = []
    scored = 0
    for case_id, payload in held_out_payloads():
        baseline = await baseline_engine.scan(payload, depth=depth)
        advised = await advised_engine.scan(payload, depth=depth)
        if comparable(baseline) != comparable(advised):
            differences.append(case_id)
        assert baseline.attack_probability is None
        if advised.attack_probability is not None:
            assert 0.0 <= advised.attack_probability <= 1.0
            scored += 1

    assert differences == []
    # Every non-empty payload gets a score, so the parity above is not vacuous.
    assert scored == len(held_out_payloads())
