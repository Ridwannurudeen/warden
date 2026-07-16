"""Regression coverage for signed APA transparency-log checkpoints."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import _canonical_json, b64u_encode


@pytest.fixture(autouse=True)
def _apa_env(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "0")


def _record(attestation_id: str) -> dict[str, object]:
    return {
        "attestation_id": attestation_id,
        "endpoint_host": "asp.example.org",
        "status": "active",
    }


def _append_two_entries() -> tuple[list[dict[str, object]], dict[str, object]]:
    protection_store.commit_attestation_events(
        [("issued", _record("first")), ("issued", _record("second"))]
    )
    return protection_store.read_log(), protection_store.read_log_checkpoint()


def test_signed_checkpoint_accepts_the_honest_contiguous_chain():
    entries, checkpoint = _append_two_entries()

    assert [entry["seq"] for entry in entries] == [1, 2]
    assert protection.verify_log_checkpoint(checkpoint) is True
    assert protection_store.verify_log_chain(entries, checkpoint) is True

    with TestClient(app) as client:
        response = client.get("/apa/log/checkpoint")

    assert response.status_code == 200
    assert response.json() == checkpoint


def test_sequence_gap_and_truncation_fail_against_the_signed_head():
    entries, checkpoint = _append_two_entries()
    gap = [dict(entries[0]), dict(entries[1])]
    gap[1]["seq"] = 3

    assert protection_store.verify_log_chain(gap, checkpoint) is False
    assert protection_store.verify_log_chain(entries[:-1], checkpoint) is False


def test_internally_consistent_full_rewrite_cannot_reuse_the_signed_head():
    entries, checkpoint = _append_two_entries()
    rewritten = [dict(entry) for entry in entries]
    rewritten[0]["endpoint_host"] = "rewritten.example.org"
    rewritten[1]["prev_hash"] = hashlib.sha256(
        _canonical_json(rewritten[0]).encode("utf-8")
    ).hexdigest()

    assert protection_store.verify_log_chain(rewritten, checkpoint) is False

    forged_checkpoint = dict(checkpoint)
    forged_checkpoint["head_hash"] = hashlib.sha256(
        _canonical_json(rewritten[-1]).encode("utf-8")
    ).hexdigest()
    assert protection.verify_log_checkpoint(forged_checkpoint) is False
    assert protection_store.verify_log_chain(rewritten, forged_checkpoint) is False


def test_missing_checkpoint_on_a_nonempty_log_fails_closed_until_explicit_migration():
    entries, _ = _append_two_entries()
    with protection_store._connect() as connection:
        connection.execute("DELETE FROM log_checkpoint")
        connection.execute("DELETE FROM log_anchor")

    with pytest.raises(protection_store.LogCheckpointMissing):
        protection_store.read_log_checkpoint()
    assert protection_store.verify_log_chain(entries) is False
    with pytest.raises(protection_store.LogCheckpointMissing):
        protection_store.commit_attestation_events([("issued", _record("third"))])
    assert protection_store.read_log() == entries

    migrated = protection_store.migrate_log_checkpoint()

    assert protection.verify_log_checkpoint(migrated) is True
    assert protection_store.verify_log_chain(entries, migrated) is True


def test_checkpoint_read_never_initializes_pristine_state():
    with pytest.raises(protection_store.LogCheckpointMissing):
        protection_store.read_log_checkpoint()

    with protection_store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM log_checkpoint").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM log_anchor").fetchone()[0] == 0

    protection_store.commit_attestation_events([("issued", _record("first"))])

    assert protection.verify_log_checkpoint(protection_store.read_log_checkpoint()) is True


def test_deleting_log_and_checkpoint_cannot_reset_an_initialized_anchor():
    _append_two_entries()
    with protection_store._connect() as connection:
        anchor = connection.execute(
            "SELECT checkpoint_hash FROM log_anchor WHERE singleton = 1"
        ).fetchone()
        connection.execute("DELETE FROM log")
        connection.execute("DELETE FROM log_checkpoint")

    assert anchor is not None
    with pytest.raises(protection_store.LogCheckpointMissing):
        protection_store.read_log_checkpoint()
    assert protection_store.verify_log_chain([]) is False
    with TestClient(app) as client:
        response = client.get("/apa/log/checkpoint")
    assert response.status_code == 503
    with pytest.raises(protection_store.LogCheckpointMissing):
        protection_store.commit_attestation_events([("issued", _record("replacement"))])
    with pytest.raises(protection_store.ProtectionStateConflict):
        protection_store.migrate_log_checkpoint()

    with protection_store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM log_checkpoint").fetchone()[0] == 0
