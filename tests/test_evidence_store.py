"""Durable storage and revocation coverage for signed evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.badges import b64u_encode
from warden.evidence_store import (
    get_security_passport,
    get_task_safety_receipt,
    revoke_security_passport,
    revoke_task_safety_receipt,
    store_security_passport,
    store_task_safety_receipt,
)
from warden.safety_receipts import canonical_sha256, issue_task_safety_receipt, verify_task_safety_receipt
from warden.security_passports import (
    build_agent_service_binding,
    issue_security_passport,
    verify_security_passport,
)


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(private_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)
    monkeypatch.setenv("WARDEN_EVIDENCE_DB", str(tmp_path / "evidence.db"))


def _passport() -> dict[str, object]:
    binding = build_agent_service_binding(
        agent_id="3808",
        service_id="33460",
        chain_id="eip155:196",
        endpoint="https://warden.gudman.xyz/mcp",
        observed_at=1_800_000_000,
        marketplace_snapshot={
            "agent": {
                "agentId": "3808",
                "services": [{"serviceId": "33460", "endpoint": "https://warden.gudman.xyz/mcp"}],
            }
        },
    )
    return issue_security_passport(
        binding=binding,
        audit_evidence_sha256="a" * 64,
        hardening_evidence_sha256="b" * 64,
        protection_evidence_sha256="c" * 64,
        shield_evidence_sha256="d" * 64,
        issued_at=1_800_000_000,
    )


def _receipt() -> dict[str, object]:
    return issue_task_safety_receipt(
        task_id="private-task",
        agent_id="3808",
        service_id="33460",
        service_revision_sha256="c" * 64,
        request_sha256=canonical_sha256({"payload": "private"}),
        result_sha256=canonical_sha256({"verdict": "ALLOW"}),
        decision_sha256=canonical_sha256({"decision": "ALLOW"}),
        verdict="ALLOW",
        outcome="result-produced",
        issued_at=1_800_000_000,
    )


def test_store_is_idempotent_and_rejects_identifier_conflicts():
    passport = _passport()
    first = store_security_passport(passport, validator=verify_security_passport)
    second = store_security_passport(copy.deepcopy(passport), validator=verify_security_passport)

    assert first == second
    conflicting = copy.deepcopy(passport)
    conflicting["limitations"] = "different"
    with pytest.raises(ValueError, match="already bound"):
        store_security_passport(conflicting, validator=lambda record: True)


def test_get_and_revoke_passport_persist_across_calls():
    passport = _passport()
    store_security_passport(passport, validator=verify_security_passport)
    assert get_security_passport(passport["passport_id"], validator=verify_security_passport)["status"] == "active"

    assert (
        revoke_security_passport(
            passport["passport_id"],
            revoked_at=1_800_000_001,
            validator=verify_security_passport,
        )
        == 1_800_000_001
    )
    stored = get_security_passport(passport["passport_id"], validator=verify_security_passport)
    assert stored["status"] == "revoked"
    assert stored["revoked_at"] == 1_800_000_001


def test_receipts_use_the_same_durable_lifecycle():
    receipt = _receipt()
    store_task_safety_receipt(receipt, validator=verify_task_safety_receipt)
    stored = get_task_safety_receipt(receipt["receipt_id"], validator=verify_task_safety_receipt)
    assert stored["record"] == receipt
    assert stored["status"] == "active"

    revoke_task_safety_receipt(
        receipt["receipt_id"],
        revoked_at=1_800_000_001,
        validator=verify_task_safety_receipt,
    )
    assert (
        get_task_safety_receipt(
            receipt["receipt_id"],
            validator=verify_task_safety_receipt,
        )["status"]
        == "revoked"
    )


def test_store_never_serializes_raw_private_material(tmp_path: Path):
    receipt = _receipt()
    store_task_safety_receipt(receipt, validator=verify_task_safety_receipt)
    database_text = (tmp_path / "evidence.db").read_bytes()
    assert b"private-task" not in database_text
    assert b"private" not in database_text
    assert b"task_id_sha256" in database_text
    assert json.dumps(receipt).encode() not in database_text
