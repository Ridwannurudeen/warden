"""APA transparency-log bindings for passports and task receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import evidence_store, protection, protection_store
from warden.badges import _canonical_json, b64u_encode
from warden.safety_receipts import (
    canonical_sha256,
    issue_task_safety_receipt,
    verify_task_safety_receipt,
)
from warden.security_passports import (
    build_agent_service_binding,
    issue_security_passport,
    verify_security_passport,
)

ISSUED_AT = 1_800_000_000
TASK_ID = "private-okx-task"
PRIVATE_PAYLOAD = "customer-private-payload"


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(private_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)
    monkeypatch.delenv("WARDEN_PROTECTION_DB", raising=False)
    monkeypatch.setenv("WARDEN_EVIDENCE_DB", str(tmp_path / "evidence.db"))


def _passport() -> dict[str, object]:
    endpoint = "https://warden.gudman.xyz/mcp"
    binding = build_agent_service_binding(
        agent_id="3808",
        service_id="33460",
        chain_id="eip155:196",
        endpoint=endpoint,
        observed_at=ISSUED_AT,
        marketplace_snapshot={
            "agent": {
                "agentId": "3808",
                "services": [{"serviceId": "33460", "endpoint": endpoint}],
            }
        },
    )
    return issue_security_passport(
        binding=binding,
        audit_evidence_sha256="a" * 64,
        hardening_evidence_sha256="b" * 64,
        protection_evidence_sha256="c" * 64,
        shield_evidence_sha256="d" * 64,
        issued_at=ISSUED_AT,
    )


def _receipt() -> dict[str, object]:
    return issue_task_safety_receipt(
        task_id=TASK_ID,
        agent_id="3808",
        service_id="33460",
        service_revision_sha256="c" * 64,
        request_sha256=canonical_sha256({"payload": PRIVATE_PAYLOAD}),
        result_sha256=canonical_sha256({"verdict": "ALLOW"}),
        decision_sha256=canonical_sha256({"decision": "ALLOW"}),
        verdict="ALLOW",
        outcome="result-produced",
        issued_at=ISSUED_AT,
    )


def test_stored_evidence_is_hash_bound_into_the_anchored_apa_log() -> None:
    passport = _passport()
    receipt = _receipt()

    evidence_store.store_security_passport(
        passport,
        validator=verify_security_passport,
    )
    evidence_store.store_task_safety_receipt(
        receipt,
        validator=verify_task_safety_receipt,
    )

    entries = protection_store.read_log()
    checkpoint = protection_store.read_log_checkpoint()
    assert entries == [
        {
            "seq": 1,
            "ts": ISSUED_AT,
            "event": "security-passport-issued",
            "record_type": "security-passport",
            "passport_id": passport["passport_id"],
            "record_hash": hashlib.sha256(_canonical_json(passport).encode("utf-8")).hexdigest(),
            "prev_hash": protection_store.GENESIS_PREV_HASH,
        },
        {
            "seq": 2,
            "ts": ISSUED_AT,
            "event": "task-safety-receipt-issued",
            "record_type": "task-safety-receipt",
            "receipt_id": receipt["receipt_id"],
            "record_hash": hashlib.sha256(_canonical_json(receipt).encode("utf-8")).hexdigest(),
            "prev_hash": hashlib.sha256(_canonical_json(entries[0]).encode("utf-8")).hexdigest(),
        },
    ]
    assert protection.verify_log_checkpoint(checkpoint)
    assert protection_store.verify_log_chain(entries, checkpoint)

    serialized_log = json.dumps(entries, sort_keys=True)
    assert TASK_ID not in serialized_log
    assert PRIVATE_PAYLOAD not in serialized_log
    for forbidden_field in (
        "task_id_sha256",
        "request_sha256",
        "result_sha256",
        "decision_sha256",
    ):
        assert forbidden_field not in serialized_log


def test_idempotent_stores_do_not_append_duplicate_log_entries() -> None:
    passport = _passport()

    first = evidence_store.store_security_passport(
        passport,
        validator=verify_security_passport,
    )
    second = evidence_store.store_security_passport(
        passport,
        validator=verify_security_passport,
    )

    assert first == second
    assert len(protection_store.read_log()) == 1


@pytest.mark.parametrize(
    ("store", "revoke", "validator", "record_factory", "record_type", "event"),
    [
        (
            evidence_store.store_security_passport,
            evidence_store.revoke_security_passport,
            verify_security_passport,
            _passport,
            "security-passport",
            "security-passport-revoked",
        ),
        (
            evidence_store.store_task_safety_receipt,
            evidence_store.revoke_task_safety_receipt,
            verify_task_safety_receipt,
            _receipt,
            "task-safety-receipt",
            "task-safety-receipt-revoked",
        ),
    ],
)
def test_revocation_is_hash_only_checkpointed_and_idempotent(
    store,
    revoke,
    validator,
    record_factory,
    record_type: str,
    event: str,
) -> None:
    record = record_factory()
    record_id = str(record["passport_id" if record_type == "security-passport" else "receipt_id"])
    store(record, validator=validator)

    first = revoke(record_id, revoked_at=ISSUED_AT + 1, validator=validator)
    second = revoke(record_id, revoked_at=ISSUED_AT + 2, validator=validator)

    assert first == second == ISSUED_AT + 1
    entries = protection_store.read_log()
    assert [entry["event"] for entry in entries] == [
        f"{record_type}-issued",
        event,
    ]
    assert entries[1]["record_hash"] == entries[0]["record_hash"]
    assert protection_store.verify_log_chain(
        entries,
        protection_store.read_log_checkpoint(),
    )


def test_record_reads_fail_closed_if_the_log_binding_is_repointed() -> None:
    passport = _passport()
    receipt = _receipt()
    evidence_store.store_security_passport(passport, validator=verify_security_passport)
    evidence_store.store_task_safety_receipt(receipt, validator=verify_task_safety_receipt)

    with protection_store._connect() as connection:
        connection.execute(
            "UPDATE security_passports SET log_seq = 2 WHERE passport_id = ?",
            (passport["passport_id"],),
        )

    with pytest.raises(
        protection_store.ProtectionStateConflict,
        match="matching transparency-log entry",
    ):
        evidence_store.get_security_passport(
            str(passport["passport_id"]),
            validator=verify_security_passport,
        )


def test_log_failure_rolls_back_the_evidence_record() -> None:
    protection_store.commit_attestation_events(
        [
            (
                "issued",
                {
                    "attestation_id": "legacy-attestation",
                    "endpoint_host": "legacy.example",
                    "status": "active",
                },
            )
        ]
    )
    with protection_store._connect() as connection:
        connection.execute("DELETE FROM log_checkpoint")

    passport = _passport()
    with pytest.raises(protection_store.LogCheckpointMissing):
        evidence_store.store_security_passport(
            passport,
            validator=verify_security_passport,
        )

    with protection_store._connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM security_passports WHERE passport_id = ?",
                (passport["passport_id"],),
            ).fetchone()[0]
            == 0
        )


def test_new_entry_types_preserve_legacy_apa_log_contiguity() -> None:
    protection_store.commit_attestation_events(
        [
            (
                "issued",
                {
                    "attestation_id": "before",
                    "endpoint_host": "legacy.example",
                    "status": "active",
                },
            )
        ]
    )
    evidence_store.store_security_passport(
        _passport(),
        validator=verify_security_passport,
    )
    protection_store.commit_attestation_events(
        [
            (
                "refreshed",
                {
                    "attestation_id": "after",
                    "endpoint_host": "legacy.example",
                    "status": "active",
                },
            )
        ]
    )

    entries = protection_store.read_log()
    assert [entry["record_type"] if "record_type" in entry else None for entry in entries] == [
        None,
        "security-passport",
        None,
    ]
    assert protection_store.verify_log_chain(
        entries,
        protection_store.read_log_checkpoint(),
    )
