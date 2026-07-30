"""Security passport binding, signature, and lifecycle contracts."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from warden.badges import b64u_encode
from warden.models import AgentServiceBinding, SecurityPassportRecord
from warden.security_passports import (
    PASSPORT_FIELDS,
    PASSPORT_TTL_SECONDS,
    build_agent_service_binding,
    effective_status,
    issue_security_passport,
    service_revision_hash,
    verify_security_passport,
)

ISSUED_AT = 1_800_000_000
EVIDENCE_HASHES = {
    "audit_evidence_sha256": "a" * 64,
    "hardening_evidence_sha256": "b" * 64,
    "protection_evidence_sha256": "c" * 64,
    "shield_evidence_sha256": "d" * 64,
}


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)


def _snapshot() -> dict[str, object]:
    return {
        "schema_version": 2,
        "captured_at": "2026-07-30T12:00:00Z",
        "agent": {
            "agentId": "1152",
            "services": [
                {
                    "serviceId": "33460",
                    "serviceType": "A2MCP",
                    "endpoint": "https://warden.gudman.xyz/mcp",
                    "feeAmount": 0.01,
                }
            ],
        },
    }


def _binding() -> AgentServiceBinding:
    return build_agent_service_binding(
        agent_id="1152",
        service_id="33460",
        chain_id="eip155:196",
        endpoint="https://warden.gudman.xyz/mcp",
        observed_at=ISSUED_AT,
        marketplace_snapshot=_snapshot(),
    )


def _passport() -> dict[str, object]:
    return issue_security_passport(
        binding=_binding(),
        issued_at=ISSUED_AT,
        **EVIDENCE_HASHES,
    )


def test_service_revision_is_deterministic_over_canonical_snapshot() -> None:
    snapshot = _snapshot()
    reordered = {
        "agent": snapshot["agent"],
        "captured_at": snapshot["captured_at"],
        "schema_version": snapshot["schema_version"],
    }

    first = build_agent_service_binding(
        agent_id="1152",
        service_id="33460",
        chain_id="eip155:196",
        endpoint="https://warden.gudman.xyz/mcp",
        observed_at=ISSUED_AT,
        marketplace_snapshot=snapshot,
    )
    second = build_agent_service_binding(
        agent_id="1152",
        service_id="33460",
        chain_id="eip155:196",
        endpoint="https://warden.gudman.xyz/mcp",
        observed_at=ISSUED_AT + 60,
        marketplace_snapshot=reordered,
    )

    assert first.marketplace_snapshot_sha256 == second.marketplace_snapshot_sha256
    assert first.service_revision_sha256 == second.service_revision_sha256
    assert first.service_revision_sha256 == service_revision_hash(
        agent_id=first.agent_id,
        service_id=first.service_id,
        chain_id=first.chain_id,
        endpoint=first.endpoint,
        marketplace_snapshot=snapshot,
    )

    changed = json.loads(json.dumps(snapshot))
    changed["agent"]["services"][0]["feeAmount"] = 0.02
    assert (
        service_revision_hash(
            agent_id="1152",
            service_id="33460",
            chain_id="eip155:196",
            endpoint="https://warden.gudman.xyz/mcp",
            marketplace_snapshot=changed,
        )
        != first.service_revision_sha256
    )


def test_binding_is_strict_and_requires_canonical_identifiers_and_endpoint() -> None:
    binding = _binding()

    with pytest.raises(ValidationError):
        AgentServiceBinding.model_validate({**binding.model_dump(), "payload": "raw task"})
    with pytest.raises(ValidationError):
        AgentServiceBinding.model_validate({**binding.model_dump(), "agent_id": " 1152"})
    with pytest.raises(ValidationError):
        AgentServiceBinding.model_validate(
            {**binding.model_dump(), "endpoint": "https://WARDEN.GUDMAN.XYZ:443/mcp"}
        )
    with pytest.raises(ValueError, match="finite canonical JSON"):
        build_agent_service_binding(
            agent_id="1152",
            service_id="33460",
            chain_id="eip155:196",
            endpoint="https://warden.gudman.xyz/mcp",
            observed_at=ISSUED_AT,
            marketplace_snapshot={"score": float("nan")},
        )


def test_issue_creates_a_strict_signed_hash_only_composite() -> None:
    passport = _passport()

    assert set(passport) == PASSPORT_FIELDS
    assert verify_security_passport(passport) is True
    assert SecurityPassportRecord.model_validate(passport).model_dump() == passport
    assert passport["expires_at"] == ISSUED_AT + PASSPORT_TTL_SECONDS
    assert {field: passport[field] for field in EVIDENCE_HASHES} == EVIDENCE_HASHES
    assert "payload" not in json.dumps(passport).lower()
    assert "not certification" in str(passport["limitations"])


@pytest.mark.parametrize("field", sorted(EVIDENCE_HASHES))
def test_every_evidence_reference_is_mandatory(field: str) -> None:
    passport = _passport()
    incomplete = json.loads(json.dumps(passport))
    incomplete.pop(field)

    assert verify_security_passport(incomplete) is False
    assert effective_status(incomplete, now=ISSUED_AT) == "invalid"
    with pytest.raises(ValidationError):
        SecurityPassportRecord.model_validate(incomplete)


@pytest.mark.parametrize("field", sorted(PASSPORT_FIELDS))
def test_mutating_any_passport_field_breaks_verification(field: str) -> None:
    passport = _passport()
    mutations: dict[str, object] = {
        "spec_version": "warden-security-passport/999",
        "predicate_type": "https://attacker.example/passport",
        "passport_id": "0" * 64,
        "issuer": "attacker",
        "binding": {**passport["binding"], "service_id": "99999"},
        "audit_evidence_sha256": "0" * 64,
        "hardening_evidence_sha256": "0" * 64,
        "protection_evidence_sha256": "0" * 64,
        "shield_evidence_sha256": "0" * 64,
        "issued_at": ISSUED_AT + 1,
        "expires_at": ISSUED_AT + PASSPORT_TTL_SECONDS + 1,
        "limitations": "all systems safe",
        "issuer_sig": "sig:AAAA",
    }
    tampered = {**json.loads(json.dumps(passport)), field: mutations[field]}

    assert tampered[field] != passport[field]
    assert verify_security_passport(tampered) is False
    assert effective_status(tampered, now=ISSUED_AT) == "invalid"


def test_status_is_active_stale_revoked_or_superseded_from_current_facts() -> None:
    passport = _passport()
    revision = str(passport["binding"]["service_revision_sha256"])

    assert effective_status(passport, now=passport["expires_at"]) == "active"
    assert effective_status(passport, now=int(passport["expires_at"]) + 1) == "stale"
    assert effective_status(passport, revoked=True, now=ISSUED_AT) == "revoked"
    assert (
        effective_status(
            passport,
            current_service_revision_sha256=revision,
            now=ISSUED_AT,
        )
        == "active"
    )
    assert (
        effective_status(
            passport,
            current_service_revision_sha256="f" * 64,
            now=ISSUED_AT,
        )
        == "superseded"
    )


def test_status_inputs_and_issue_times_fail_closed() -> None:
    passport = _passport()

    assert effective_status(passport, now=True) == "invalid"
    assert (
        effective_status(
            passport,
            current_service_revision_sha256="not-a-hash",
            now=ISSUED_AT,
        )
        == "invalid"
    )
    with pytest.raises(ValueError, match="before the service observation"):
        issue_security_passport(
            binding=_binding(),
            issued_at=ISSUED_AT - 1,
            **EVIDENCE_HASHES,
        )
    with pytest.raises(ValidationError):
        SecurityPassportRecord.model_validate({**passport, "task_payload": "secret"})
