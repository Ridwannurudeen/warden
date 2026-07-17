"""Regression coverage for the versioned signed audit-evidence guarantees.

These close the deferred High findings D-01 (exact-target identity), D-02
(benign/liveness control), and D-03 (prompt-provenance separation).
"""

from urllib.parse import urlparse

import pytest

from warden.auditor import BENIGN_CONTROLS, AgentAuditor, AuditOutcome


def _stub_auditor(monkeypatch, auditor, attacks, outcome_for):
    async def validate(target_url):
        parsed = urlparse(target_url)
        return f"https://93.184.216.34{parsed.path or '/'}", "example.org", parsed

    async def consent(*args):
        return True

    async def target_outcome(_client, _connect, _authority, payload, *, sni_hostname):
        return outcome_for(payload)

    monkeypatch.setenv("WARDEN_BADGE_SECRET", "audit-evidence-test-secret")
    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(auditor, "_load_representative_attacks", lambda: list(attacks))
    monkeypatch.setattr(auditor, "_target_outcome", target_outcome)


def _all_blocked_attacks(count=20):
    return [
        {"id": f"a{i}", "category": "PROMPT_INJECTION", "payload": f"attack-{i}"}
        for i in range(count)
    ]


@pytest.mark.asyncio
async def test_two_paths_on_same_host_get_distinct_signed_identities(monkeypatch):
    auditor = AgentAuditor()
    captured: list[dict[str, object]] = []
    monkeypatch.setattr("warden.auditor.record_badge", captured.append)

    def outcome_for(payload):
        if payload in BENIGN_CONTROLS:
            return AuditOutcome.NOT_BLOCKED
        return AuditOutcome.BLOCKED

    _stub_auditor(monkeypatch, auditor, _all_blocked_attacks(), outcome_for)

    path_a = await auditor.audit("https://example.org/service-a")
    path_b = await auditor.audit("https://example.org/service-b")

    assert path_a.badge_record is not None and path_b.badge_record is not None
    assert path_a.badge_record.audit_id != path_b.badge_record.audit_id
    assert len(captured) == 2
    assert captured[0]["target"]["path"] != captured[1]["target"]["path"]
    assert captured[0]["signature"] != captured[1]["signature"]


@pytest.mark.asyncio
async def test_target_that_blocks_everything_earns_no_signed_grade(monkeypatch):
    auditor = AgentAuditor()
    monkeypatch.setattr(
        "warden.auditor.record_badge",
        lambda badge: pytest.fail("a blind-rejecting target must not earn a signed badge"),
    )

    # The target rejects every probe including the benign controls: liveness fails.
    _stub_auditor(
        monkeypatch, auditor, _all_blocked_attacks(), lambda payload: AuditOutcome.BLOCKED
    )

    response = await auditor.audit("https://example.org/reject-all")

    assert response.badge_record is None
    assert "no signed badge issued" in response.badge.lower()
    assert "liveness" in response.badge.lower()


@pytest.mark.asyncio
async def test_caller_prompt_dilution_cannot_raise_the_signed_grade(monkeypatch):
    auditor = AgentAuditor()

    # Fixed battery: 16 of 20 blocked -> signed B/80. Caller prompts all "block".
    attacks = [
        {"id": f"a{i}", "category": "PROMPT_INJECTION", "payload": f"block-{i}"} for i in range(16)
    ] + [
        {"id": f"a{i}", "category": "PROMPT_INJECTION", "payload": f"miss-{i}"}
        for i in range(16, 20)
    ]

    def outcome_for(payload):
        if payload in BENIGN_CONTROLS:
            return AuditOutcome.NOT_BLOCKED
        if payload.startswith("miss-"):
            return AuditOutcome.NOT_BLOCKED
        return AuditOutcome.BLOCKED

    monkeypatch.setattr("warden.auditor.record_badge", lambda badge: None)
    _stub_auditor(monkeypatch, auditor, attacks, outcome_for)

    baseline = await auditor.audit("https://example.org/scan")
    diluted = await auditor.audit(
        "https://example.org/scan", [f"custom-block-{i}" for i in range(20)]
    )

    assert baseline.badge_record is not None and diluted.badge_record is not None
    # The signed grade is battery-only: 20 trivially blocked caller prompts do not
    # raise it above the fixed-battery result.
    assert baseline.badge_record.grade == "B"
    assert baseline.badge_record.score == 80
    assert diluted.badge_record.grade == "B"
    assert diluted.badge_record.score == 80
    assert diluted.badge_record.blocked == 16
    assert diluted.badge_record.total == 20
