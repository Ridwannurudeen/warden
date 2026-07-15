"""APA protection core tests: TOFU registration, attestation crypto, log, revoke.

The heartbeat fixture generates a real Ed25519 endpoint key in-test, signs a
spec-shaped Protection Proof, and serves it through a stubbed fetch layer
(a real localhost HTTP server is — correctly — rejected by the SSRF validator,
so the stub replaces only the transport, never the crypto checks).
"""

from __future__ import annotations

import importlib.util
import secrets
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import b64u_encode, ed25519_sign_record

_ROOT = Path(__file__).resolve().parents[1]


def _load_spec_verifier():
    spec = importlib.util.spec_from_file_location("verify_apa", _ROOT / "spec" / "verify_apa.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_apa"] = module
    spec.loader.exec_module(module)
    return module


verify_apa = _load_spec_verifier()


@pytest.fixture(autouse=True)
def _apa_env(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "0")


@pytest.fixture
def endpoint_key():
    return Ed25519PrivateKey.generate()


def _make_proof(
    endpoint_key: Ed25519PrivateKey,
    host: str = "asp.example.org",
    **overrides,
) -> dict[str, object]:
    proof = {
        "spec_version": "apa/0.1",
        "protector": "warden",
        "endpoint_host": host,
        "pub": b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519"),
        "ts": int(time.time()),
        "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
        "window_s": 86400,
        "scans_served": 41207,
    }
    proof.update(overrides)
    return ed25519_sign_record(proof, endpoint_key, "sig")


def _stub_fetch(monkeypatch, proof: dict[str, object], host: str = "asp.example.org"):
    async def _fetch_proof(endpoint: str):
        return host, proof

    monkeypatch.setattr(protection, "_fetch_proof", _fetch_proof)


def test_register_tofu_happy_path_verifies_with_spec_verifier(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    record = body["attestation"]
    assert record["tier"] == "guard-live"
    assert record["status"] == "active"
    assert record["scans_24h"] == 41207
    assert "agent_id" not in record

    # Objective gate: the spec's reference verifier must accept it offline.
    ok, message = verify_apa.verify_attestation(record, protection.issuer_public_key())
    assert ok, message


def test_tampered_attestation_fails_spec_verifier(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]

    tampered = dict(record)
    tampered["scans_24h"] = 999_999
    ok, _ = verify_apa.verify_attestation(tampered, protection.issuer_public_key())
    assert not ok
    assert protection.verify_attestation_record(tampered) is False
    assert protection.verify_attestation_record(record) is True


def test_stale_heartbeat_rejected(monkeypatch, endpoint_key):
    stale_ts = int(time.time()) - protection.PROOF_TTL_SECONDS - 60
    _stub_fetch(monkeypatch, _make_proof(endpoint_key, ts=stale_ts))
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert response.status_code == 400
    assert "stale" in response.json()["detail"]


def test_bad_heartbeat_signature_rejected(monkeypatch, endpoint_key):
    proof = _make_proof(endpoint_key)
    proof["scans_served"] = 1  # mutate after signing
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert response.status_code == 400
    assert "signature" in response.json()["detail"]


def test_nonce_replay_rejected(monkeypatch, endpoint_key):
    proof = _make_proof(endpoint_key)
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        first = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        second = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert first.status_code == 200
    assert second.status_code == 400
    assert "replayed" in second.json()["detail"]


def test_key_changed_flagged_on_differing_pub(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        first = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        assert first.json()["attestation"]["status"] == "active"

        other_key = Ed25519PrivateKey.generate()
        _stub_fetch(monkeypatch, _make_proof(other_key))
        second = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert second.status_code == 200
    assert second.json()["attestation"]["status"] == "key-changed"
    binding = protection_store.get_binding("asp.example.org")
    assert binding["key_changed"] is True
    # The original binding is never silently replaced.
    assert binding["pub"] == b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")


def test_ssrf_private_host_rejected():
    # No fetch stub here: the real validator must refuse before any request.
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "http://127.0.0.1:9/agent"})
    assert response.status_code == 400
    assert "blocked internal address" in response.json()["detail"]


def test_expired_attestation_reads_stale_and_badge_never_lies(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    monkeypatch.setattr(protection, "ATTESTATION_TTL_SECONDS", -10)
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        detail = client.get(f"/apa/attestation/{record['attestation_id']}")
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")
    assert detail.json()["status"] == "stale"
    assert badge.status_code == 200
    assert badge.headers["cache-control"] == "no-store"
    assert "stale" in badge.text
    assert "41207/24h" not in badge.text


def test_badge_svg_active_renders_honest_label(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")
    assert badge.status_code == 200
    assert badge.headers["content-type"].startswith("image/svg+xml")
    assert badge.headers["cache-control"] == "no-store"
    assert "Warden Guard Live" in badge.text
    assert "41207/24h" in badge.text
    assert "Protected" not in badge.text


def test_transparency_log_hash_chain_verifies(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        _stub_fetch(monkeypatch, _make_proof(endpoint_key))
        client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        log = client.get("/apa/log").json()

    entries = log["entries"]
    assert log["total"] == len(entries) == 2
    assert entries[0]["prev_hash"] == protection_store.GENESIS_PREV_HASH
    assert protection_store.verify_log_chain(entries) is True

    corrupted = [dict(entry) for entry in entries]
    corrupted[0]["status"] = "forged"
    assert protection_store.verify_log_chain(corrupted) is False


def test_revoke_requires_endpoint_key_signature(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        attestation_id = record["attestation_id"]

        core = {
            "attestation_id": attestation_id,
            "ts": int(time.time()),
            "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
        }
        forged = ed25519_sign_record(core, Ed25519PrivateKey.generate(), "sig")
        rejected = client.post("/apa/revoke", json=forged)
        assert rejected.status_code == 400
        assert "signature" in rejected.json()["detail"]

        signed = ed25519_sign_record(core, endpoint_key, "sig")
        accepted = client.post("/apa/revoke", json=signed)
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "revoked"

        detail = client.get(f"/apa/attestation/{attestation_id}")
        badge = client.get(f"/apa/attestation/{attestation_id}/badge.svg")
    assert detail.json()["status"] == "revoked"
    assert "revoked" in badge.text
    log_entries = protection_store.read_log()
    assert log_entries[-1]["event"] == "revoked"
    assert protection_store.verify_log_chain(log_entries) is True


def test_issuer_wellknown_key_verifies_attestations(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        issuer_doc = client.get("/.well-known/apa-issuer.json").json()

    assert issuer_doc["issuer"] == "warden"
    published_pub = issuer_doc["keys"][0]["pub"]
    ok, message = verify_apa.verify_attestation(record, published_pub)
    assert ok, message
