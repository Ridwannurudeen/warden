import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import b64u_encode, ed25519_sign_record


@pytest.fixture(autouse=True)
def _apa_environment(tmp_path, monkeypatch):
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "0")
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )


def _revoke(attestation_id, endpoint_key):
    return ed25519_sign_record(
        {
            "attestation_id": attestation_id,
            "ts": int(time.time()),
            "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
        },
        endpoint_key,
        "sig",
    )


def test_repeated_revocation_is_idempotent_and_appends_once():
    endpoint_host = "guard.example"
    endpoint_key = Ed25519PrivateKey.generate()
    endpoint_pub = b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")
    record = protection.issue_attestation(endpoint_host, endpoint_pub, 7)
    protection_store.commit_attestation_events(
        [("issued", record)],
        new_binding=(endpoint_host, endpoint_pub),
    )

    with TestClient(app) as client:
        first = client.post(
            "/apa/revoke",
            json=_revoke(str(record["attestation_id"]), endpoint_key),
        )
        second = client.post(
            "/apa/revoke",
            json=_revoke(str(record["attestation_id"]), endpoint_key),
        )

    assert first.status_code == second.status_code == 200
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "revoked",
    ]
