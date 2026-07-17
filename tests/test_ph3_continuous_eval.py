"""PH3 continuous evaluation and human-reviewed Gauntlet regressions."""

import json
from pathlib import Path

import pytest

from scripts import review_gauntlet
from scripts.benchmark_recall import evaluate_benchmark, record_benchmark
from warden import gauntlet_store
from warden.core.verdict import ReasonCode
from warden.models import GauntletRequest, ScanResponse

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_benchmark_harness_records_dated_history_and_public_current_result(tmp_path):
    result = await evaluate_benchmark()
    history = tmp_path / "history.jsonl"
    public = tmp_path / "evaluation.json"

    record = record_benchmark(
        result,
        measured_at="2026-07-16T16:30:00Z",
        history_path=history,
        public_path=public,
    )

    assert json.loads(history.read_text(encoding="utf-8")) == record
    published = json.loads(public.read_text(encoding="utf-8"))
    assert published["current"] == record
    assert published["methodology"] == {
        "attack_success": "non-ALLOW decision with the expected threat class",
        "benign_false_positive": "any non-ALLOW decision",
        "held_out": True,
        "semantic_enabled": False,
    }
    assert record["measured_at"] == "2026-07-16T16:30:00Z"
    assert record["attack_recall_percent"] == 67.86
    assert record["false_positive_rate_percent"] == 0.0
    assert len(record["result_sha256"]) == 64


def _allow_response() -> ScanResponse:
    return ScanResponse(
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        detections=[],
        sanitized_payload="A novel indirect authorization bypass.",
        recommendation="No implemented detector fired.",
        checks={},
        latency_ms=0.2,
    )


def test_human_confirmed_bypass_appends_only_to_held_out_set(tmp_path, monkeypatch):
    store = tmp_path / "attempts.jsonl"
    held_out = tmp_path / "held_out_attacks.jsonl"
    held_out.write_text("", encoding="utf-8")
    monkeypatch.setattr(gauntlet_store, "_STORE_PATH", store)
    training_before = (ROOT / "corpus" / "attacks.jsonl").read_bytes()
    patterns_before = (ROOT / "warden" / "scanner" / "patterns.py").read_bytes()
    request = GauntletRequest(
        intent="indirect policy bypass",
        payload="A novel indirect authorization bypass.",
        finder="reviewer.example",
    )
    status, claim_id = gauntlet_store.record_attempt(request, _allow_response())
    assert status == "pending"
    assert claim_id is not None

    first = gauntlet_store.confirm_bypass(
        claim_id,
        ReasonCode.PROMPT_INJECTION,
        benchmark_path=held_out,
        confirmed_at="2026-07-16T16:31:00Z",
    )
    second = gauntlet_store.confirm_bypass(
        claim_id,
        ReasonCode.PROMPT_INJECTION,
        benchmark_path=held_out,
        confirmed_at="2026-07-16T16:32:00Z",
    )

    [case] = [
        json.loads(line)
        for line in held_out.read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert first == second == case
    assert case == {
        "category": "PROMPT_INJECTION",
        "id": f"gauntlet-{claim_id[:16]}",
        "payload": "A novel indirect authorization bypass.",
        "source": "human-reviewed-gauntlet",
    }
    records = [
        json.loads(line) for line in store.read_text(encoding="utf-8").splitlines() if line
    ]
    assert records[0]["status"] == "confirmed"
    assert records[0]["benchmark_case_id"] == case["id"]
    assert records[0]["confirmed_at"] == "2026-07-16T16:31:00Z"
    assert (ROOT / "corpus" / "attacks.jsonl").read_bytes() == training_before
    assert (ROOT / "warden" / "scanner" / "patterns.py").read_bytes() == patterns_before


def test_confirmation_rejects_unknown_or_nonpending_claims(tmp_path, monkeypatch):
    monkeypatch.setattr(gauntlet_store, "_STORE_PATH", tmp_path / "attempts.jsonl")

    with pytest.raises(ValueError, match="pending Gauntlet claim"):
        gauntlet_store.confirm_bypass(
            "0" * 64,
            ReasonCode.PROMPT_INJECTION,
            benchmark_path=tmp_path / "held_out.jsonl",
        )


def test_review_cli_requires_explicit_human_confirmation():
    with pytest.raises(SystemExit, match="--confirm-human-review"):
        review_gauntlet.main(["0" * 64, "PROMPT_INJECTION"])
