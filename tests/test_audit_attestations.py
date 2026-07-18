"""Issuer-signed, transparency-logged endpoint-audit evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit_attestations, badge_store, protection, protection_store
from warden.badges import b64u_encode, issue_badge

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _audit_evidence_environment(tmp_path, monkeypatch):
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))


def _record(log_seq: int, *, issued_at: int = 1_784_000_000) -> dict[str, object]:
    return audit_attestations.issue_audit_attestation(
        audit_id="0123456789abcdef",
        subject="https://agent.example/scan?mode=strict",
        endpoint_host="agent.example",
        battery_id="warden-core-http",
        battery_version="2026-07",
        battery_sha256="a" * 64,
        blocked=19,
        total=20,
        benign_total=3,
        benign_passed=3,
        observed_on="2026-07-18",
        issued_at=issued_at,
        log_seq=log_seq,
    )


def test_audit_attestation_round_trip_binds_issuer_history_and_limitations() -> None:
    record = _record(7)

    assert audit_attestations.verify_audit_attestation(record)
    assert record["grade"] == "A"
    assert record["conclusive"] == 20
    assert record["inconclusive"] == 0
    assert record["consent_verified"] is True
    assert record["liveness_passed"] is True
    assert record["expires_at"] == record["issued_at"] + 2_592_000
    assert "point-in-time" in str(record["limitations"]).lower()

    tampered = dict(record)
    tampered["blocked"] = 20
    assert not audit_attestations.verify_audit_attestation(tampered)


def test_audit_attestation_requires_a_canonical_endpoint_host() -> None:
    with pytest.raises(ValueError, match="fields are invalid"):
        audit_attestations.issue_audit_attestation(
            audit_id="0123456789abcdef",
            subject="https://agent.example/scan",
            endpoint_host="Agent.Example.",
            battery_id="warden-core-http",
            battery_version="2026-07",
            battery_sha256="a" * 64,
            blocked=19,
            total=20,
            benign_total=3,
            benign_passed=3,
            observed_on="2026-07-18",
            issued_at=1_784_000_000,
            log_seq=1,
        )


def test_audit_attestation_is_committed_with_a_signed_log_head() -> None:
    record = protection_store.commit_audit_attestation(
        audit_id="0123456789abcdef",
        record_factory=_record,
        record_validator=audit_attestations.verify_audit_attestation,
    )

    stored = protection_store.get_audit_attestation_with_evidence(
        "0123456789abcdef",
        record_validator=audit_attestations.verify_audit_attestation,
    )
    entries = protection_store.read_log()
    checkpoint = protection_store.read_log_checkpoint()

    assert stored == {
        "attestation": record,
        "status": "active",
        "revoked_at": None,
    }
    assert entries == [
        {
            "seq": 1,
            "ts": record["issued_at"],
            "event": "audit-issued",
            "record_type": "endpoint-audit-attestation",
            "audit_id": record["audit_id"],
            "endpoint_host": record["endpoint_host"],
            "record_hash": audit_attestations.record_sha256(record),
            "prev_hash": "0" * 64,
        }
    ]
    assert protection.verify_log_checkpoint(checkpoint)
    assert protection_store.verify_log_chain(entries, checkpoint)


def test_audit_attestation_commit_and_revocation_are_idempotent() -> None:
    first = protection_store.commit_audit_attestation(
        audit_id="0123456789abcdef",
        record_factory=_record,
        record_validator=audit_attestations.verify_audit_attestation,
    )
    second = protection_store.commit_audit_attestation(
        audit_id="0123456789abcdef",
        record_factory=lambda seq: pytest.fail("idempotent commit must reuse the record"),
        record_validator=audit_attestations.verify_audit_attestation,
    )
    revoked = protection_store.revoke_audit_attestation(
        "0123456789abcdef",
        revoked_at=1_784_000_100,
        record_validator=audit_attestations.verify_audit_attestation,
    )
    repeated = protection_store.revoke_audit_attestation(
        "0123456789abcdef",
        revoked_at=1_784_000_200,
        record_validator=audit_attestations.verify_audit_attestation,
    )

    assert second == first
    assert repeated == revoked == 1_784_000_100
    assert protection_store.get_audit_attestation_with_evidence(
        "0123456789abcdef",
        record_validator=audit_attestations.verify_audit_attestation,
    ) == {
        "attestation": first,
        "status": "revoked",
        "revoked_at": 1_784_000_100,
    }
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "audit-issued",
        "audit-revoked",
    ]


def test_audit_attestation_revocation_cannot_predate_issuance() -> None:
    protection_store.commit_audit_attestation(
        audit_id="0123456789abcdef",
        record_factory=_record,
        record_validator=audit_attestations.verify_audit_attestation,
    )

    with pytest.raises(ValueError, match="predate"):
        protection_store.revoke_audit_attestation(
            "0123456789abcdef",
            revoked_at=1_783_999_999,
            record_validator=audit_attestations.verify_audit_attestation,
        )

    assert [entry["event"] for entry in protection_store.read_log()] == [
        "audit-issued"
    ]


def test_publish_from_legacy_v2_badge_uses_exact_target_and_manifest_hash(monkeypatch) -> None:
    monkeypatch.setattr(audit_attestations.time, "time", lambda: 1_784_000_000)
    badge = {
        "audit_id": "0123456789abcdef",
        "target_host": "agent.example",
        "grade": "A",
        "score": 95.0,
        "blocked": 19,
        "total": 20,
        "issued_at": "2026-07-18",
        "consent_verified": True,
        "badge_version": 2,
        "target": {
            "scheme": "https",
            "host": "agent.example",
            "port": None,
            "path": "/scan",
            "query": "mode=strict",
        },
        "battery": {
            "id": "warden-core-http",
            "version": "2026-07",
            "size": 20,
            "prompt_source": "fixed-battery",
            "hash": "a" * 64,
            "benign_total": 3,
            "benign_passed": 3,
            "caller_prompts": 0,
        },
        "signature": "legacy-hmac-is-verified-separately",
    }

    record = audit_attestations.publish_from_badge(badge)

    assert record["subject"] == "https://agent.example/scan?mode=strict"
    assert record["battery_sha256"] == "a" * 64
    assert audit_attestations.verify_audit_attestation(record)


def test_recording_a_versioned_badge_publishes_portable_audit_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(badge_store, "_STORE_PATH", tmp_path / "issued.jsonl")
    monkeypatch.setattr(audit_attestations.time, "time", lambda: 1_784_000_000)
    badge = issue_badge(
        target_host="agent.example",
        score=95.0,
        grade="A",
        blocked=19,
        total=20,
        issued_at="2026-07-18",
        target={
            "scheme": "https",
            "host": "agent.example",
            "port": None,
            "path": "/scan",
            "query": "mode=strict",
        },
        battery={
            "id": "warden-core-http",
            "version": "2026-07",
            "size": 20,
            "prompt_source": "fixed-battery",
            "hash": "a" * 64,
            "benign_total": 3,
            "benign_passed": 3,
            "caller_prompts": 0,
        },
        secret="badge-test-secret",
    )
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "badge-test-secret")

    badge_store.record_badge(badge)
    badge_store.record_badge(badge)

    evidence = protection_store.get_audit_attestation_with_evidence(
        str(badge["audit_id"]),
        record_validator=audit_attestations.verify_audit_attestation,
    )
    assert evidence is not None
    assert evidence["status"] == "active"
    assert evidence["attestation"]["audit_id"] == badge["audit_id"]
    assert evidence["attestation"]["subject"] == (
        "https://agent.example/scan?mode=strict"
    )
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "audit-issued"
    ]


def test_invalid_versioned_badge_is_not_persisted(tmp_path, monkeypatch) -> None:
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr(badge_store, "_STORE_PATH", store_path)
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "badge-test-secret")
    badge = issue_badge(
        target_host="agent.example",
        score=95.0,
        grade="A",
        blocked=19,
        total=20,
        issued_at="2026-07-18",
        target={
            "scheme": "https",
            "host": "agent.example",
            "port": None,
            "path": "/scan",
            "query": "",
        },
        battery={
            "id": "warden-core-http",
            "version": "2026-07",
            "size": 20,
            "prompt_source": "fixed-battery",
            "hash": "a" * 64,
            "benign_total": 3,
            "benign_passed": 3,
            "caller_prompts": 0,
        },
    )
    badge["blocked"] = 20

    with pytest.raises(ValueError, match="integrity"):
        badge_store.record_badge(badge)

    assert not store_path.exists()


def test_audit_attestation_store_rejects_conflicting_reissue() -> None:
    protection_store.commit_audit_attestation(
        audit_id="0123456789abcdef",
        record_factory=_record,
        record_validator=audit_attestations.verify_audit_attestation,
    )

    with pytest.raises(protection_store.ProtectionStateConflict):
        protection_store.commit_audit_attestation(
            audit_id="0123456789abcdef",
            record_factory=_record,
            record_validator=lambda record: False,
        )


def test_audit_attestation_script_is_machine_readable() -> None:
    script = (ROOT / "scripts" / "revoke_audit_attestation.py").read_text(
        encoding="utf-8"
    )

    assert "revoke_audit_attestation" in script
    assert "json.dumps" in script
    assert "private key" not in script.lower()
