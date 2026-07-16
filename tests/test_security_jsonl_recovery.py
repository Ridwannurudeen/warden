import json

from warden import badge_store, gauntlet_store
from warden.badges import issue_badge
from warden.core.verdict import ReasonCode
from warden.models import GauntletRequest, ScanResponse


def _allow_response(payload):
    return ScanResponse(
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        detections=[],
        sanitized_payload=payload,
        recommendation="clean",
        checks={},
        latency_ms=0.1,
    )


def test_badge_jsonl_readers_skip_truncated_and_non_object_records(tmp_path, monkeypatch):
    path = tmp_path / "issued.jsonl"
    monkeypatch.setattr(badge_store, "_STORE_PATH", path)
    badge = issue_badge(
        target_host="api.example.org",
        score=100.0,
        grade="A",
        blocked=2,
        total=2,
        issued_at="2026-07-16",
        secret="test-badge-secret",
    )
    path.write_text(
        '{"audit_id":\n[]\n' + json.dumps(badge, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert badge_store.get_badge(str(badge["audit_id"])) == badge
    assert badge_store.list_badges() == [badge]


def test_gauntlet_jsonl_readers_skip_truncated_and_non_object_records(tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    benchmark = tmp_path / "held_out.jsonl"
    monkeypatch.setattr(gauntlet_store, "_STORE_PATH", path)
    payload = "A locally reviewed unusual alpha-epsilon authorization note."
    _, claim_id = gauntlet_store.record_attempt(
        GauntletRequest(intent="indirect bypass", payload=payload),
        _allow_response(payload),
    )
    valid_line = path.read_text(encoding="utf-8")
    path.write_text("[]\n{\"broken\":\n" + valid_line, encoding="utf-8")

    assert gauntlet_store.get_stats(118)["attempts"] == 1
    case = gauntlet_store.confirm_bypass(
        str(claim_id),
        ReasonCode.PROMPT_INJECTION,
        benchmark_path=benchmark,
        confirmed_at="2026-07-16T16:31:00Z",
    )

    assert case["payload"] == payload
