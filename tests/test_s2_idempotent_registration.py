"""Regression coverage for idempotent same-key APA registration."""

import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import b64u_encode, ed25519_sign_record


@pytest.fixture(autouse=True)
def _apa_env(tmp_path, monkeypatch):
    issuer_seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(issuer_seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "0")


def _proof(endpoint_key: Ed25519PrivateKey, scans: int) -> dict[str, object]:
    now = int(time.time())
    record = {
        "spec_version": "apa/0.1",
        "protector": "warden",
        "endpoint_host": "asp.example.org",
        "pub": b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519"),
        "ts": now,
        "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
        "window_s": 86_400,
        "window_start": now - 86_400,
        "scans_served": scans,
    }
    return ed25519_sign_record(record, endpoint_key, "sig")


def _stub_proof(monkeypatch, proof: dict[str, object]) -> None:
    async def fetch_proof(endpoint: str) -> tuple[str, dict[str, object]]:
        return "asp.example.org", proof

    monkeypatch.setattr(protection, "_fetch_proof", fetch_proof)


def test_same_key_registration_reuses_active_record_and_logs_only_a_refresh(monkeypatch):
    endpoint_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        _stub_proof(monkeypatch, _proof(endpoint_key, 10))
        first = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

        _stub_proof(monkeypatch, _proof(endpoint_key, 11))
        second = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

        first_record = first.json()["attestation"]
        expired = protection.refresh_attestation(
            first_record,
            10,
            verified_at=int(time.time()) - protection.ATTESTATION_TTL_SECONDS - 1,
        )
        protection_store.store_attestation(expired)

        _stub_proof(monkeypatch, _proof(endpoint_key, 12))
        refreshed = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert refreshed.status_code == 200
    assert second.json()["attestation"] == first_record
    assert refreshed.json()["attestation"]["attestation_id"] == first_record["attestation_id"]
    assert refreshed.json()["attestation"]["scans_24h"] == 12
    with protection_store._connect() as connection:
        count = connection.execute("SELECT COUNT(*) FROM attestations").fetchone()[0]
    assert count == 1
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "refreshed",
    ]
