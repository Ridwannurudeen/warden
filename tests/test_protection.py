"""APA protection core tests: TOFU registration, attestation crypto, log, revoke.

The heartbeat fixture generates a real Ed25519 endpoint key in-test, signs a
spec-shaped Protection Proof, and serves it through a stubbed fetch layer
(a real localhost HTTP server is — correctly — rejected by the SSRF validator,
so the stub replaces only the transport, never the crypto checks).
"""

from __future__ import annotations

import importlib.util
import json
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import b64u_encode, ed25519_sign_record, ed25519_verify_record

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
    now = int(time.time())
    proof = {
        "spec_version": "apa/0.1",
        "protector": "warden",
        "endpoint_host": host,
        "pub": b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519"),
        "ts": now,
        "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
        "window_s": 86400,
        "window_start": now - 86400,
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


def test_register_copies_a_signed_unavailable_counter_as_null(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key, scans_served=None))
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
        record = response.json()["attestation"]
        detail = client.get(f"/apa/attestation/{record['attestation_id']}")
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")

    assert response.status_code == 200
    assert record["scans_24h"] is None
    assert response.json()["scope"] == protection.ATTESTATION_SCOPE
    assert detail.json()["scope"] == protection.ATTESTATION_SCOPE
    ok, message = verify_apa.verify_attestation(record, protection.issuer_public_key())
    assert ok, message
    assert "count unavailable" in badge.text
    assert f"<desc>{protection.ATTESTATION_SCOPE}</desc>" in badge.text
    assert ">live<" not in badge.text


def test_first_registration_failure_rolls_back_binding_and_allows_different_key_retry(
    monkeypatch, endpoint_key
):
    protection_store.read_log()
    with protection_store._connect() as connection:
        connection.execute(
            "CREATE TRIGGER fail_log BEFORE INSERT ON log "
            "BEGIN SELECT RAISE(ABORT, 'forced log failure'); END"
        )

    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        with pytest.raises(sqlite3.IntegrityError, match="forced log failure"):
            client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})

        assert protection_store.get_binding("asp.example.org") is None
        with protection_store._connect() as connection:
            connection.execute("DROP TRIGGER fail_log")

        replacement_key = Ed25519PrivateKey.generate()
        _stub_fetch(monkeypatch, _make_proof(replacement_key))
        retry = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})

    with protection_store._connect() as connection:
        stored = connection.execute("SELECT COUNT(*) FROM attestations").fetchone()[0]
    binding = protection_store.get_binding("asp.example.org")
    assert retry.status_code == 200
    assert retry.json()["attestation"]["status"] == "active"
    assert binding == {
        "endpoint_host": "asp.example.org",
        "pub": b64u_encode(replacement_key.public_key().public_bytes_raw(), "ed25519"),
        "bound_at": binding["bound_at"],
        "key_changed": False,
        "pending_replacement_pub": None,
    }
    assert stored == 1
    assert [entry["event"] for entry in protection_store.read_log()] == ["issued"]


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


def test_future_heartbeat_rejected(monkeypatch, endpoint_key):
    future_ts = int(time.time()) + protection.PROOF_TTL_SECONDS + 60
    _stub_fetch(
        monkeypatch,
        _make_proof(endpoint_key, ts=future_ts, window_start=future_ts - 86400),
    )
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
    assert response.status_code == 400
    assert "outside TTL" in response.json()["detail"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"spec_version": "apa/9.9"}, "spec_version"),
        ({"protector": ""}, "protector"),
        ({"ts": True}, "integer 'ts'"),
        ({"window_s": True}, "window_s"),
        ({"window_s": 3600}, "window_s"),
        ({"window_start": True}, "window_start"),
        ({"window_start": 1}, "window_start"),
        ({"scans_served": True}, "scans_served"),
        ({"scans_served": -1}, "scans_served"),
    ],
)
def test_nonconforming_signed_heartbeat_rejected(monkeypatch, endpoint_key, overrides, message):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key, **overrides))
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
    assert response.status_code == 400
    assert message in response.json()["detail"]


def test_missing_signed_scan_counter_is_rejected(monkeypatch, endpoint_key):
    proof = _make_proof(endpoint_key)
    proof.pop("scans_served")
    proof = ed25519_sign_record(proof, endpoint_key, "sig")
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

    assert response.status_code == 400
    assert "scans_served is required" in response.json()["detail"]


def test_non_warden_protector_is_rejected_by_the_warden_issuer(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key, protector="other-firewall"))
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
    assert response.status_code == 400
    assert "protector" in response.json()["detail"]


def test_bad_heartbeat_signature_rejected(monkeypatch, endpoint_key):
    proof = _make_proof(endpoint_key)
    proof["scans_served"] = 1  # mutate after signing
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert response.status_code == 400
    assert "signature" in response.json()["detail"]


@pytest.mark.parametrize("field", ["pub", "sig"])
def test_noncanonical_proof_key_and_signature_prefixes_rejected(monkeypatch, endpoint_key, field):
    proof = _make_proof(endpoint_key)
    proof[field] = "other:" + str(proof[field]).split(":", 1)[1]
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
    assert response.status_code == 400
    assert field in response.json()["detail"]


def test_nonce_replay_rejected(monkeypatch, endpoint_key):
    proof = _make_proof(endpoint_key)
    _stub_fetch(monkeypatch, proof)
    with TestClient(app) as client:
        first = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        second = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
    assert first.status_code == 200
    assert second.status_code == 400
    assert "replayed" in second.json()["detail"]


def test_rejected_shape_does_not_consume_the_proof_nonce(monkeypatch, endpoint_key):
    nonce = b64u_encode(secrets.token_bytes(16), "nonce")
    _stub_fetch(monkeypatch, _make_proof(endpoint_key, nonce=nonce, scans_served=-1))
    with TestClient(app) as client:
        rejected = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
        _stub_fetch(monkeypatch, _make_proof(endpoint_key, nonce=nonce))
        accepted = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

    assert rejected.status_code == 400
    assert "scans_served" in rejected.json()["detail"]
    assert accepted.status_code == 200


def test_key_changed_flagged_on_differing_pub(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        first = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        first_record = first.json()["attestation"]
        assert first_record["status"] == "active"
        with protection_store._connect() as connection:
            connection.execute(
                "UPDATE attestations SET created_at = 123 WHERE attestation_id = ?",
                (first_record["attestation_id"],),
            )

        other_key = Ed25519PrivateKey.generate()
        _stub_fetch(monkeypatch, _make_proof(other_key))
        second = client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        prior = client.get(f"/apa/attestation/{first_record['attestation_id']}").json()
    assert second.status_code == 200
    assert second.json()["attestation"]["status"] == "key-changed"
    assert prior["status"] == "key-changed"
    assert prior["verified"] is True
    assert prior["attestation"]["status"] == "key-changed"
    binding = protection_store.get_binding("asp.example.org")
    assert binding["key_changed"] is True
    # The original binding is never silently replaced.
    assert binding["pub"] == b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")
    with protection_store._connect() as connection:
        created_at = connection.execute(
            "SELECT created_at FROM attestations WHERE attestation_id = ?",
            (first_record["attestation_id"],),
        ).fetchone()[0]
    assert created_at == 123
    entries = protection_store.read_log()
    assert [entry["event"] for entry in entries] == ["issued", "key-changed", "issued"]
    assert entries[1]["attestation_id"] == first_record["attestation_id"]
    assert entries[1]["status"] == "key-changed"
    assert protection_store.verify_log_chain(entries) is True


def test_key_change_batch_rolls_back_when_log_append_fails(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        first = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        with protection_store._connect() as connection:
            connection.execute(
                "CREATE TRIGGER fail_log BEFORE INSERT ON log "
                "BEGIN SELECT RAISE(ABORT, 'forced key-change log failure'); END"
            )

        _stub_fetch(monkeypatch, _make_proof(Ed25519PrivateKey.generate()))
        with pytest.raises(sqlite3.IntegrityError, match="forced key-change log failure"):
            client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        prior = client.get(f"/apa/attestation/{first['attestation_id']}").json()

    assert prior["status"] == "active"
    assert protection_store.get_binding("asp.example.org")["key_changed"] is False
    with protection_store._connect() as connection:
        stored = connection.execute("SELECT COUNT(*) FROM attestations").fetchone()[0]
    assert stored == 1
    assert [entry["event"] for entry in protection_store.read_log()] == ["issued"]


def test_key_changed_binding_remains_sticky_when_original_key_returns(monkeypatch, endpoint_key):
    original_pub = b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")
    changed_pub = b64u_encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    pubs = iter((original_pub, changed_pub, original_pub))

    async def probe_guard(endpoint: str):
        return "asp.example.org", next(pubs), 1

    monkeypatch.setattr(protection, "probe_guard", probe_guard)
    with TestClient(app) as client:
        responses = [
            client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
            for _ in range(3)
        ]

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert [response.json()["attestation"]["status"] for response in responses] == [
        "active",
        "key-changed",
        "key-changed",
    ]
    assert protection_store.get_binding("asp.example.org")["key_changed"] is True


def test_ssrf_private_host_rejected():
    # No fetch stub here: the real validator must refuse before any request.
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://127.0.0.1:9/agent"})
    assert response.status_code == 400
    assert "blocked internal address" in response.json()["detail"]


def test_public_plaintext_http_endpoint_rejected_before_fetch(monkeypatch):
    async def unexpected_fetch(endpoint: str):
        raise AssertionError(f"must not fetch plaintext APA endpoint: {endpoint}")

    monkeypatch.setattr(protection, "_fetch_proof", unexpected_fetch)
    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "http://asp.example.org/agent"})
    assert response.status_code == 400
    assert "HTTPS" in response.json()["detail"]


def test_expired_attestation_reads_stale_and_badge_never_lies(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        monkeypatch.setattr(protection.time, "time", lambda: record["expires_at"] + 1)
        detail = client.get(f"/apa/attestation/{record['attestation_id']}")
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")
    assert detail.json()["status"] == "stale"
    assert badge.status_code == 200
    assert badge.headers["cache-control"] == "no-store"
    assert "stale" in badge.text
    assert "41207/24h" not in badge.text


@pytest.mark.parametrize(
    "stored_status",
    ["key-changed", "revoked"],
)
def test_expiry_overrides_every_valid_stored_status(stored_status, monkeypatch):
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        41_207,
        status=stored_status,
    )
    protection_store.store_attestation(record)

    monkeypatch.setattr(protection.time, "time", lambda: record["expires_at"] + 1)
    with TestClient(app) as client:
        detail = client.get(f"/apa/attestation/{record['attestation_id']}")
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")

    assert detail.json()["status"] == "stale"
    assert "stale" in badge.text
    assert stored_status not in badge.text


@pytest.mark.parametrize(
    "endpoint",
    ["https://asp.example.org/agent", "https://asp.example.org:443/agent"],
)
@pytest.mark.asyncio
async def test_default_https_port_has_one_canonical_endpoint_identity(monkeypatch, endpoint):
    calls = []

    async def validate(target: str):
        parsed = urlparse(target)
        return "https://203.0.113.10:443/agent", "asp.example.org", parsed

    class Response:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def aiter_bytes(self):
            yield b"{}"

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        def stream(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return Response()

    monkeypatch.setattr(protection, "validate_public_http_url", validate)
    monkeypatch.setattr(protection.httpx, "AsyncClient", lambda **kwargs: Client())

    endpoint_host, proof = await protection._fetch_proof(endpoint)

    assert endpoint_host == "asp.example.org"
    assert proof == {}
    assert calls[0][2]["extensions"]["sni_hostname"] == "asp.example.org"


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


def test_tampered_attestation_reads_invalid_and_badge_never_renders_active(
    monkeypatch, endpoint_key
):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        record = client.post(
            "/apa/register", json={"endpoint": "https://asp.example.org/agent"}
        ).json()["attestation"]
        tampered = dict(record)
        tampered["scans_24h"] = 999_999
        protection_store.store_attestation(tampered)

        detail = client.get(f"/apa/attestation/{record['attestation_id']}")
        badge = client.get(f"/apa/attestation/{record['attestation_id']}/badge.svg")

    assert detail.json()["verified"] is False
    assert detail.json()["status"] == "invalid"
    assert "invalid" in badge.text
    assert "Warden Guard Live" not in badge.text
    assert "999999/24h" not in badge.text


def test_transparency_log_hash_chain_verifies(monkeypatch, endpoint_key):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        _stub_fetch(monkeypatch, _make_proof(endpoint_key))
        client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        log = client.get("/apa/log").json()

    entries = log["entries"]
    assert log["total"] == len(entries) == 1
    assert entries[0]["prev_hash"] == protection_store.GENESIS_PREV_HASH
    assert protection_store.verify_log_chain(entries) is True

    corrupted = [dict(entry) for entry in entries]
    corrupted[0]["status"] = "forged"
    assert protection_store.verify_log_chain(corrupted) is False


def test_transparency_log_defaults_to_json_and_serves_html_only_when_requested(
    monkeypatch, endpoint_key
):
    _stub_fetch(monkeypatch, _make_proof(endpoint_key))
    with TestClient(app) as client:
        client.post("/apa/register", json={"endpoint": "https://asp.example.org/agent"})
        default = client.get("/apa/log")
        explicit_json = client.get("/apa/log", headers={"accept": "application/json"})
        wildcard = client.get("/apa/log", headers={"accept": "*/*"})
        html = client.get("/apa/log", headers={"accept": "text/html"})

    expected = {"entries": protection_store.read_log(), "total": 1}
    assert default.headers["content-type"].startswith("application/json")
    assert default.json() == expected
    assert explicit_json.json() == expected
    assert wildcard.json() == expected
    assert html.headers["content-type"].startswith("text/html")
    assert "data-apa-log" in html.text


def test_revoke_requires_endpoint_key_and_resigns_revoked_record(monkeypatch, endpoint_key):
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
    detail_body = detail.json()
    revoked = detail_body["attestation"]
    assert detail_body["status"] == "revoked"
    assert detail_body["verified"] is True
    assert protection.verify_attestation_record(revoked) is True

    ok, status_message = verify_apa.verify_attestation(revoked, protection.issuer_public_key())
    assert ok is False
    assert status_message == "signature valid but status is 'revoked'"

    tampered = dict(revoked)
    tampered["scans_24h"] = 999_999
    tampered_ok, tampered_message = verify_apa.verify_attestation(
        tampered, protection.issuer_public_key()
    )
    assert tampered_ok is False
    assert tampered_message.startswith("issuer signature INVALID")

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


def _set_issuer_history(tmp_path, monkeypatch, payload):
    history_path = tmp_path / "issuer-history.json"
    history_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("WARDEN_ISSUER_HISTORY", str(history_path))
    return history_path


def test_issuer_document_publishes_current_then_recent_public_keys(tmp_path, monkeypatch):
    older_key = Ed25519PrivateKey.generate()
    newer_key = Ed25519PrivateKey.generate()
    older_pub = b64u_encode(older_key.public_key().public_bytes_raw(), "ed25519")
    newer_pub = b64u_encode(newer_key.public_key().public_bytes_raw(), "ed25519")
    _set_issuer_history(
        tmp_path,
        monkeypatch,
        {
            "keys": [
                {"kid": "retired-older", "pub": older_pub, "not_after": 100},
                {"kid": "retired-newer", "pub": newer_pub, "not_after": 200},
            ]
        },
    )
    monkeypatch.setenv("WARDEN_ISSUER_KID", "current-2026-07")

    document = protection.issuer_document()

    assert document["issuer"] == "warden"
    assert [key["kid"] for key in document["keys"]] == [
        "current-2026-07",
        "retired-newer",
        "retired-older",
    ]
    assert document["keys"][0]["pub"] == protection.issuer_public_key()
    assert document["keys"][0]["not_after"] == protection.MAX_SAFE_UNIX_SECONDS
    assert all(key["not_after"] < protection.MAX_SAFE_UNIX_SECONDS for key in document["keys"][1:])
    assert all(type(key["not_after"]) is int for key in document["keys"])
    assert len({key["kid"] for key in document["keys"]}) == 3
    assert len({key["pub"] for key in document["keys"]}) == 3


def test_retired_issuer_key_uses_signed_verified_at_cutoff(tmp_path, monkeypatch):
    retired_key = Ed25519PrivateKey.generate()
    retired_pub = b64u_encode(retired_key.public_key().public_bytes_raw(), "ed25519")
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        41_207,
    )
    record = ed25519_sign_record(record, retired_key, "issuer_sig")
    _set_issuer_history(
        tmp_path,
        monkeypatch,
        {
            "keys": [
                {
                    "kid": "retired-issuer",
                    "pub": retired_pub,
                    "not_after": record["verified_at"],
                }
            ]
        },
    )

    assert protection.verify_attestation_record(record) is True

    _set_issuer_history(
        tmp_path,
        monkeypatch,
        {
            "keys": [
                {
                    "kid": "retired-issuer",
                    "pub": retired_pub,
                    "not_after": record["verified_at"] - 1,
                }
            ]
        },
    )
    assert protection.verify_attestation_record(record) is False


def test_retired_issuer_key_cannot_extend_a_backdated_attestation_lifetime(
    tmp_path,
    monkeypatch,
):
    retired_key = Ed25519PrivateKey.generate()
    retired_pub = b64u_encode(retired_key.public_key().public_bytes_raw(), "ed25519")
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        41_207,
    )
    record["expires_at"] = protection.MAX_SAFE_UNIX_SECONDS
    record = ed25519_sign_record(record, retired_key, "issuer_sig")
    _set_issuer_history(
        tmp_path,
        monkeypatch,
        {
            "keys": [
                {
                    "kid": "retired-issuer",
                    "pub": retired_pub,
                    "not_after": record["verified_at"],
                }
            ]
        },
    )

    assert protection.verify_attestation_record(record) is False
    assert protection.effective_status(record) == "invalid"


def test_status_refresh_is_resigned_only_by_current_issuer_key(tmp_path, monkeypatch):
    retired_key = Ed25519PrivateKey.generate()
    retired_pub = b64u_encode(retired_key.public_key().public_bytes_raw(), "ed25519")
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        41_207,
    )
    record = ed25519_sign_record(record, retired_key, "issuer_sig")
    _set_issuer_history(
        tmp_path,
        monkeypatch,
        {
            "keys": [
                {
                    "kid": "retired-issuer",
                    "pub": retired_pub,
                    "not_after": record["verified_at"],
                }
            ]
        },
    )

    resigned = protection.resign_attestation_status(record, "revoked")
    refreshed = protection.refresh_attestation(record, 9, verified_at=record["verified_at"] + 1)

    assert protection.verify_attestation_record(resigned) is True
    assert ed25519_verify_record(resigned, protection.issuer_public_key(), "issuer_sig") is True
    assert ed25519_verify_record(resigned, retired_pub, "issuer_sig") is False
    assert protection.verify_attestation_record(refreshed) is True
    assert ed25519_verify_record(refreshed, protection.issuer_public_key(), "issuer_sig") is True
    assert ed25519_verify_record(refreshed, retired_pub, "issuer_sig") is False


@pytest.mark.parametrize(
    "payload",
    [
        {"keys": [{"kid": "old", "pub": "ed25519:not-a-key", "not_after": 1}]},
        {"keys": [{"kid": "old", "pub": "ed25519:" + "A" * 43, "not_after": None}]},
        {"keys": [{"kid": "old", "pub": "ed25519:" + "A" * 43, "not_after": True}]},
        {
            "keys": [
                {
                    "kid": "old",
                    "pub": b64u_encode(
                        Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                        "ed25519",
                    ),
                    "not_after": protection.MAX_SAFE_UNIX_SECONDS,
                }
            ]
        },
        {"keys": "not-a-list"},
        [],
    ],
)
def test_malformed_issuer_history_fails_closed(tmp_path, monkeypatch, payload):
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        1,
    )
    _set_issuer_history(tmp_path, monkeypatch, payload)

    with pytest.raises(ValueError):
        protection.issuer_document()
    assert protection.verify_attestation_record(record) is False


@pytest.mark.parametrize("duplicate", ["kid", "pub"])
def test_duplicate_issuer_history_fails_closed(tmp_path, monkeypatch, duplicate):
    first = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate()
    first_pub = b64u_encode(first.public_key().public_bytes_raw(), "ed25519")
    second_pub = b64u_encode(second.public_key().public_bytes_raw(), "ed25519")
    keys = [
        {"kid": "retired-1", "pub": first_pub, "not_after": 200},
        {"kid": "retired-2", "pub": second_pub, "not_after": 100},
    ]
    keys[1][duplicate] = keys[0][duplicate]
    record = protection.issue_attestation(
        "asp.example.org",
        b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        1,
    )
    _set_issuer_history(tmp_path, monkeypatch, {"keys": keys})

    with pytest.raises(ValueError, match="duplicate"):
        protection.issuer_document()
    assert protection.verify_attestation_record(record) is False
