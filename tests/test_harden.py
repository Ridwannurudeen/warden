"""Audit-findings persistence and deterministic hardening-pack regressions."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi import HTTPException

from warden import api, audit_findings
from warden.audit_findings import get_findings, record_findings
from warden.auditor import AgentAuditor, AuditOutcome
from warden.core.verdict import ReasonCode
from warden.hardening import build_pack
from warden.models import HardenRequest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _isolated_findings_store(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_findings, "_STORE_PATH", tmp_path / "findings.jsonl")


def _record(
    audit_id: str,
    findings: list[dict[str, object]],
) -> dict[str, object]:
    return record_findings(
        audit_id=audit_id,
        target_host="agent.example",
        findings=findings,
        battery_id="warden-core-http",
        battery_version="2026-07",
        observed_on="2026-07-24",
    )


async def _run_audit(
    monkeypatch,
    *,
    consent_verified: bool,
    attack_outcome: AuditOutcome,
):
    auditor = AgentAuditor()

    async def validate(target_url):
        return "https://93.184.216.34/scan", "agent.example", urlparse(target_url)

    async def consent(*args):
        return consent_verified

    async def outcome(*args, **kwargs):
        payload = str(args[3])
        if payload == "audit attack":
            return attack_outcome
        return AuditOutcome.NOT_BLOCKED

    monkeypatch.setenv("WARDEN_BADGE_SECRET", "harden-test-secret")
    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [
            {
                "id": "test-attack",
                "category": "PROMPT_INJECTION",
                "payload": "audit attack",
            }
        ],
    )
    monkeypatch.setattr(auditor, "_target_outcome", outcome)
    monkeypatch.setattr("warden.auditor.record_badge", lambda record: None)
    return await auditor.audit("https://agent.example/scan")


@pytest.mark.asyncio
async def test_conclusive_consented_audit_records_findings(monkeypatch):
    response = await _run_audit(
        monkeypatch,
        consent_verified=True,
        attack_outcome=AuditOutcome.NOT_BLOCKED,
    )

    assert response.badge_record is not None
    assert get_findings(response.badge_record.audit_id) == {
        "schema_version": 1,
        "audit_id": response.badge_record.audit_id,
        "target_host": "agent.example",
        "battery_id": "warden-core-http",
        "battery_version": "2026-07",
        "observed_on": response.badge_record.issued_at,
        "findings": [
            {
                "attack_class": "PROMPT_INJECTION",
                "total": 1,
                "blocked": 0,
                "missed": 1,
            }
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("consent_verified", "attack_outcome"),
    [
        (True, AuditOutcome.INCONCLUSIVE),
        (False, AuditOutcome.NOT_BLOCKED),
    ],
)
async def test_unsigned_audit_records_no_findings(
    monkeypatch,
    consent_verified,
    attack_outcome,
):
    response = await _run_audit(
        monkeypatch,
        consent_verified=consent_verified,
        attack_outcome=attack_outcome,
    )

    assert response.badge_record is None
    assert not audit_findings._STORE_PATH.exists()


def test_harden_returns_exactly_the_missed_classes():
    audit_id = "0123456789abcdef"
    _record(
        audit_id,
        [
            {"attack_class": "PROMPT_INJECTION", "total": 2, "blocked": 1},
            {"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 0},
            {"attack_class": "TOOL_HIJACK", "total": 1, "blocked": 1},
        ],
    )

    response = asyncio.run(api.harden(HardenRequest(audit_id=audit_id)))

    assert response.addressed_classes == ["PROMPT_INJECTION", "SECRET_EXFIL"]
    assert [entry.attack_class for entry in response.remediation] == [
        "PROMPT_INJECTION",
        "SECRET_EXFIL",
    ]


def test_fully_passing_audit_yields_an_empty_pack():
    audit_id = "1111111111111111"
    _record(
        audit_id,
        [{"attack_class": "PROMPT_INJECTION", "total": 2, "blocked": 2}],
    )

    response = asyncio.run(api.harden(HardenRequest(audit_id=audit_id)))

    assert response.addressed_classes == []
    assert response.remediation == []


def test_unknown_audit_id_returns_404():
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(api.harden(HardenRequest(audit_id="2222222222222222")))

    assert exc_info.value.status_code == 404


def test_no_held_out_attack_appears_in_an_all_class_pack():
    audit_id = "3333333333333333"
    record = _record(
        audit_id,
        [
            {"attack_class": reason.value, "total": 1, "blocked": 0}
            for reason in ReasonCode
        ],
    )

    serialized_pack = json.dumps(build_pack(record), ensure_ascii=False, sort_keys=True)
    with (ROOT / "benchmark" / "held_out_attacks.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            held_out = json.loads(line)
            assert held_out["id"] not in serialized_pack
            assert held_out["payload"] not in serialized_pack


def test_pack_generation_is_byte_identical_for_the_same_audit():
    audit_id = "4444444444444444"
    _record(
        audit_id,
        [{"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 1}],
    )

    first = asyncio.run(api.harden(HardenRequest(audit_id=audit_id)))
    second = asyncio.run(api.harden(HardenRequest(audit_id=audit_id)))

    assert first.model_dump_json() == second.model_dump_json()


def test_identical_findings_record_is_idempotent():
    audit_id = "5555555555555555"
    findings = [{"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 1}]

    first = _record(audit_id, findings)
    second = _record(audit_id, findings)

    assert first == second
    assert audit_findings._STORE_PATH.read_text(encoding="utf-8").count("\n") == 1


def test_conflicting_findings_record_is_rejected():
    audit_id = "6666666666666666"
    _record(
        audit_id,
        [{"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 1}],
    )

    with pytest.raises(ValueError, match="conflict"):
        _record(
            audit_id,
            [{"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 0}],
        )


@pytest.mark.parametrize(
    "finding",
    [
        {"attack_class": "SECRET_EXFIL", "total": 0, "blocked": 0},
        {"attack_class": "SECRET_EXFIL", "total": 1, "blocked": 2},
        {"attack_class": "SECRET_EXFIL", "total": True, "blocked": 1},
        {"attack_class": "secret-exfil", "total": 1, "blocked": 0},
    ],
)
def test_malformed_findings_counts_are_rejected(finding):
    with pytest.raises(ValueError):
        _record("7777777777777777", [finding])


def test_duplicate_findings_classes_are_rejected():
    finding = {"attack_class": "SECRET_EXFIL", "total": 1, "blocked": 0}

    with pytest.raises(ValueError, match="duplicate class"):
        _record("8888888888888888", [finding, finding])
