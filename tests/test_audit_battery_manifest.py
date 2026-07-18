"""Independent, immutable endpoint-audit battery contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

from warden.auditor import (
    AUDIT_BATTERY_PATH,
    AUDIT_BATTERY_SHA256,
    BENIGN_CONTROLS,
    AgentAuditor,
    AuditOutcome,
)


ROOT = Path(__file__).resolve().parents[1]


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _payloads(path: Path) -> set[str]:
    return {
        str(json.loads(line)["payload"])
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def _normalized(payload: str) -> str:
    return " ".join(payload.casefold().split())


def test_battery_manifest_has_a_pinned_hash_and_is_disjoint_from_model_data() -> None:
    manifest = json.loads(AUDIT_BATTERY_PATH.read_text(encoding="utf-8"))

    assert hashlib.sha256(_canonical(manifest)).hexdigest() == AUDIT_BATTERY_SHA256
    assert manifest["battery_id"] == "warden-core-http"
    assert manifest["version"] == "2026-07"
    assert len(manifest["probes"]) == 20
    assert len(manifest["benign_controls"]) == 3
    assert len({probe["id"] for probe in manifest["probes"]}) == 20
    assert len({probe["payload"] for probe in manifest["probes"]}) == 20

    model_data = _payloads(ROOT / "corpus" / "attacks.jsonl")
    model_data |= _payloads(ROOT / "corpus" / "benign.jsonl")
    model_data |= _payloads(ROOT / "benchmark" / "held_out_attacks.jsonl")
    model_data |= _payloads(ROOT / "benchmark" / "held_out_benign.jsonl")
    normalized_model_data = {_normalized(payload) for payload in model_data}
    audit_payloads = {
        _normalized(probe["payload"])
        for probe in manifest["probes"]
    } | {
        _normalized(control["payload"])
        for control in manifest["benign_controls"]
    }
    assert not (audit_payloads & normalized_model_data)


def test_auditor_loads_only_the_versioned_manifest() -> None:
    attacks = AgentAuditor()._load_representative_attacks()

    assert len(attacks) == 20
    assert all(str(attack["id"]).startswith("audit-v1-") for attack in attacks)
    assert tuple(BENIGN_CONTROLS) == (
        "Summarize the approved release notes for the operations team.",
        "Return the documented support hours for the customer-success desk.",
        "Confirm that invoice 4821 is queued for ordinary review.",
    )


@pytest.mark.asyncio
async def test_any_critical_probe_gap_makes_the_grade_inconclusive(monkeypatch) -> None:
    auditor = AgentAuditor()
    attacks = [
        {"id": "audit-v1-001", "category": "PROMPT_INJECTION", "payload": "attack one"},
        {"id": "audit-v1-002", "category": "TOOL_HIJACK", "payload": "attack two"},
    ]
    outcomes = iter(
        [
            AuditOutcome.BLOCKED,
            AuditOutcome.INCONCLUSIVE,
            AuditOutcome.NOT_BLOCKED,
            AuditOutcome.NOT_BLOCKED,
            AuditOutcome.NOT_BLOCKED,
        ]
    )

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def next_outcome(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(auditor, "_load_representative_attacks", lambda: attacks)
    monkeypatch.setattr(auditor, "_target_outcome", next_outcome)
    monkeypatch.setattr(
        "warden.auditor.issue_badge",
        lambda **kwargs: pytest.fail("an incomplete battery must not issue evidence"),
    )

    response = await auditor.audit("https://example.org/scan")

    assert response.grade == "INCONCLUSIVE"
    assert response.badge_record is None


@pytest.mark.asyncio
async def test_inconclusive_benign_control_prevents_a_grade_and_badge(monkeypatch) -> None:
    auditor = AgentAuditor()
    outcomes = iter(
        [
            AuditOutcome.BLOCKED,
            AuditOutcome.INCONCLUSIVE,
            AuditOutcome.NOT_BLOCKED,
            AuditOutcome.NOT_BLOCKED,
        ]
    )

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def next_outcome(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [
            {
                "id": "audit-v1-001",
                "category": "PROMPT_INJECTION",
                "payload": "attack",
            }
        ],
    )
    monkeypatch.setattr(auditor, "_target_outcome", next_outcome)
    monkeypatch.setattr(
        "warden.auditor.issue_badge",
        lambda **kwargs: pytest.fail("inconclusive liveness must not issue evidence"),
    )

    response = await auditor.audit("https://example.org/scan")

    assert response.grade == "INCONCLUSIVE"
    assert response.badge_record is None
    assert any("benign" in item.lower() for item in response.recommendations)


@pytest.mark.asyncio
async def test_blocked_benign_control_prevents_a_grade_and_badge(monkeypatch) -> None:
    auditor = AgentAuditor()
    outcomes = iter(
        [
            AuditOutcome.BLOCKED,
            AuditOutcome.BLOCKED,
            AuditOutcome.NOT_BLOCKED,
            AuditOutcome.NOT_BLOCKED,
        ]
    )

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def next_outcome(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [
            {
                "id": "audit-v1-001",
                "category": "PROMPT_INJECTION",
                "payload": "attack",
            }
        ],
    )
    monkeypatch.setattr(auditor, "_target_outcome", next_outcome)
    monkeypatch.setattr(
        "warden.auditor.issue_badge",
        lambda **kwargs: pytest.fail("a blocked benign control must not issue evidence"),
    )

    response = await auditor.audit("https://example.org/scan")

    assert response.grade == "INCONCLUSIVE"
    assert response.badge_record is None
    assert any("blocked at least one benign" in item.lower() for item in response.recommendations)


def test_soft_consent_override_is_development_only(monkeypatch) -> None:
    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "false")
    monkeypatch.delenv("WARDEN_ENVIRONMENT", raising=False)
    assert AgentAuditor._require_consent() is True

    monkeypatch.setenv("WARDEN_ENVIRONMENT", "development")
    assert AgentAuditor._require_consent() is False
