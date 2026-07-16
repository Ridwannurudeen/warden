"""Explicit APA endpoint-key rotation and transaction regressions."""

from __future__ import annotations

import secrets
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection, protection_store
from warden.api import app
from warden.badges import b64u_encode, ed25519_sign_record

SDK_ROOT = Path(__file__).resolve().parents[1] / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from warden_guard.apa import sign_revocation, verify_document  # noqa: E402


@pytest.fixture(autouse=True)
def _apa_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "0")


def _pub(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.public_key().public_bytes_raw(), "ed25519")


def _proof(key: Ed25519PrivateKey, *, host: str = "asp.example.org") -> dict[str, object]:
    now = int(time.time())
    return ed25519_sign_record(
        {
            "spec_version": "apa/0.1",
            "protector": "warden",
            "endpoint_host": host,
            "pub": _pub(key),
            "ts": now,
            "nonce": b64u_encode(secrets.token_bytes(16), "nonce"),
            "window_s": 86_400,
            "window_start": now - 86_400,
            "scans_served": 7,
        },
        key,
        "sig",
    )


def _stub_proof(
    monkeypatch: pytest.MonkeyPatch,
    proof: dict[str, object],
    *,
    host: str = "asp.example.org",
) -> None:
    async def fetch_proof(endpoint: str) -> tuple[str, dict[str, object]]:
        return host, proof

    monkeypatch.setattr(protection, "_fetch_proof", fetch_proof)


def _register(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    key: Ed25519PrivateKey,
) -> dict[str, object]:
    _stub_proof(monkeypatch, _proof(key))
    response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})
    assert response.status_code == 200, response.text
    return response.json()["attestation"]


def _signed_revoke(
    key: Ed25519PrivateKey,
    attestation_id: str,
    *,
    replacement_pub: str | None = None,
    nonce: str | None = None,
    timestamp: int | None = None,
) -> dict[str, object]:
    core: dict[str, object] = {
        "attestation_id": attestation_id,
        "ts": int(time.time()) if timestamp is None else timestamp,
        "nonce": nonce or b64u_encode(secrets.token_bytes(16), "nonce"),
    }
    if replacement_pub is not None:
        core["replacement_pub"] = replacement_pub
    return ed25519_sign_record(core, key, "sig")


def test_plain_revoke_remains_compatible_without_rotation_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)
        response = client.post(
            "/apa/revoke",
            json=_signed_revoke(old_key, str(record["attestation_id"])),
        )

    assert response.status_code == 200
    assert response.json() == {
        "attestation_id": record["attestation_id"],
        "status": "revoked",
    }
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pub"] == _pub(old_key)
    assert binding["pending_replacement_pub"] is None


def test_old_key_authorizes_exact_replacement_and_live_probe_completes_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        first = _register(client, monkeypatch, old_key)
        second = _register(client, monkeypatch, old_key)
        authorization = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(first["attestation_id"]),
                replacement_pub=_pub(new_key),
            ),
        )

        pending = protection_store.get_binding("asp.example.org")
        assert pending is not None
        assert pending["pub"] == _pub(old_key)
        assert pending["pending_replacement_pub"] == _pub(new_key)

        rotated = _register(client, monkeypatch, new_key)
        first_detail = client.get(f"/apa/attestation/{first['attestation_id']}").json()
        second_detail = client.get(f"/apa/attestation/{second['attestation_id']}").json()

    assert authorization.status_code == 200
    assert authorization.json()["replacement_pub"] == _pub(new_key)
    assert rotated["status"] == "active"
    assert rotated["pub"] == _pub(new_key)
    assert first_detail["attestation"]["status"] == "revoked"
    assert second_detail["attestation"]["status"] == "revoked"
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pub"] == _pub(new_key)
    assert binding["pending_replacement_pub"] is None
    assert binding["key_changed"] is False
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "issued",
        "rotation-authorized",
        "revoked",
        "rotated",
    ]


def test_wrong_probed_key_preserves_pending_authorization_then_approved_key_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    approved_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)
        authorized = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(record["attestation_id"]),
                replacement_pub=_pub(approved_key),
            ),
        )
        assert authorized.status_code == 200

        wrong = _register(client, monkeypatch, wrong_key)
        pending = protection_store.get_binding("asp.example.org")
        assert pending is not None
        assert wrong["status"] == "key-changed"
        assert pending["pub"] == _pub(old_key)
        assert pending["pending_replacement_pub"] == _pub(approved_key)
        assert pending["key_changed"] is True

        accepted = _register(client, monkeypatch, approved_key)

    assert accepted["status"] == "active"
    assert accepted["pub"] == _pub(approved_key)
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pub"] == _pub(approved_key)
    assert binding["pending_replacement_pub"] is None
    assert binding["key_changed"] is False


@pytest.mark.parametrize(
    "replacement_pub",
    [
        "other:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ed25519:short",
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ],
)
def test_rotation_rejects_noncanonical_replacement_pub(
    monkeypatch: pytest.MonkeyPatch,
    replacement_pub: str,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)
        response = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(record["attestation_id"]),
                replacement_pub=replacement_pub,
            ),
        )

    assert response.status_code == 400
    assert "replacement_pub" in response.json()["detail"]
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pending_replacement_pub"] is None


def test_probe_rejects_noncanonical_padded_endpoint_pub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    proof = _proof(key)
    proof["pub"] = f"{proof['pub']}="
    proof = ed25519_sign_record(proof, key, "sig")
    _stub_proof(monkeypatch, proof)

    with TestClient(app) as client:
        response = client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

    assert response.status_code == 400
    assert "canonical" in response.json()["detail"]
    assert protection_store.get_binding("asp.example.org") is None


def test_rotation_authorization_enforces_ttl_signature_and_nonce_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)
        stale = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(record["attestation_id"]),
                replacement_pub=_pub(new_key),
                timestamp=int(time.time()) - protection.PROOF_TTL_SECONDS - 1,
            ),
        )
        forged = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                Ed25519PrivateKey.generate(),
                str(record["attestation_id"]),
                replacement_pub=_pub(new_key),
            ),
        )
        signed = _signed_revoke(
            old_key,
            str(record["attestation_id"]),
            replacement_pub=_pub(new_key),
        )
        accepted = client.post("/apa/revoke", json=signed)
        replayed = client.post("/apa/revoke", json=signed)

    assert stale.status_code == 400
    assert "TTL" in stale.json()["detail"]
    assert forged.status_code == 400
    assert "signature" in forged.json()["detail"]
    assert accepted.status_code == 200
    assert replayed.status_code == 400
    assert "replayed" in replayed.json()["detail"]


def test_rotation_never_resigns_a_tampered_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)
        tampered = dict(record)
        tampered["scans_24h"] = 999_999
        protection_store.store_attestation(tampered)

        response = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(record["attestation_id"]),
                replacement_pub=_pub(new_key),
            ),
        )

    assert response.status_code == 409
    stored = protection_store.get_attestation(str(record["attestation_id"]))
    assert stored == tampered
    assert protection.verify_attestation_record(stored) is False
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pending_replacement_pub"] is None


def test_approved_rotation_rolls_back_if_any_old_active_attestation_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        first = _register(client, monkeypatch, old_key)
        second = _register(client, monkeypatch, old_key)
        authorization = client.post(
            "/apa/revoke",
            json=_signed_revoke(
                old_key,
                str(first["attestation_id"]),
                replacement_pub=_pub(new_key),
            ),
        )
        assert authorization.status_code == 200

        tampered = dict(second)
        tampered["scans_24h"] = 999_999
        protection_store.store_attestation(tampered)
        log_before = protection_store.read_log()

        _stub_proof(monkeypatch, _proof(new_key))
        response = client.post(
            "/apa/register",
            json={"endpoint": "https://asp.example.org"},
        )

    assert response.status_code == 409
    assert "active attestation failed issuer verification" in response.json()["detail"]
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pub"] == _pub(old_key)
    assert binding["pending_replacement_pub"] == _pub(new_key)
    assert binding["key_changed"] is False
    assert protection_store.get_attestation(str(second["attestation_id"])) == tampered
    assert protection_store.read_log() == log_before


def test_rotation_transactions_roll_back_binding_record_log_and_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        first = _register(client, monkeypatch, old_key)
        second = _register(client, monkeypatch, old_key)
        authorization = _signed_revoke(
            old_key,
            str(first["attestation_id"]),
            replacement_pub=_pub(new_key),
        )

        with protection_store._connect() as connection:
            connection.execute(
                "CREATE TRIGGER fail_log BEFORE INSERT ON log "
                "BEGIN SELECT RAISE(ABORT, 'forced rotation log failure'); END"
            )
        with pytest.raises(sqlite3.IntegrityError, match="forced rotation log failure"):
            client.post("/apa/revoke", json=authorization)

        binding = protection_store.get_binding("asp.example.org")
        assert binding is not None
        assert binding["pending_replacement_pub"] is None
        assert protection_store.get_attestation(str(first["attestation_id"]))["status"] == "active"

        with protection_store._connect() as connection:
            connection.execute("DROP TRIGGER fail_log")
        assert client.post("/apa/revoke", json=authorization).status_code == 200

        with protection_store._connect() as connection:
            connection.execute(
                "CREATE TRIGGER fail_log BEFORE INSERT ON log "
                "BEGIN SELECT RAISE(ABORT, 'forced rotation log failure'); END"
            )
        _stub_proof(monkeypatch, _proof(new_key))
        with pytest.raises(sqlite3.IntegrityError, match="forced rotation log failure"):
            client.post("/apa/register", json={"endpoint": "https://asp.example.org"})

        binding = protection_store.get_binding("asp.example.org")
        assert binding is not None
        assert binding["pub"] == _pub(old_key)
        assert binding["pending_replacement_pub"] == _pub(new_key)
        assert protection_store.get_attestation(str(second["attestation_id"]))["status"] == "active"

        with protection_store._connect() as connection:
            connection.execute("DROP TRIGGER fail_log")
        rotated = _register(client, monkeypatch, new_key)

    assert rotated["status"] == "active"
    assert protection_store.get_binding("asp.example.org")["pub"] == _pub(new_key)


def test_concurrent_register_and_revoke_never_silently_rebinds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    with TestClient(app) as client:
        record = _register(client, monkeypatch, old_key)

    authorization = _signed_revoke(
        old_key,
        str(record["attestation_id"]),
        replacement_pub=_pub(new_key),
    )

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        return "asp.example.org", _pub(new_key), 9

    monkeypatch.setattr(protection, "probe_guard", probe_guard)
    barrier = Barrier(2)

    def authorize() -> int:
        barrier.wait()
        with TestClient(app) as client:
            return client.post("/apa/revoke", json=authorization).status_code

    def register() -> int:
        barrier.wait()
        with TestClient(app) as client:
            return client.post(
                "/apa/register",
                json={"endpoint": "https://asp.example.org"},
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        authorization_result = executor.submit(authorize)
        registration_result = executor.submit(register)
        statuses = sorted((authorization_result.result(), registration_result.result()))

    assert statuses == [200, 200]
    binding = protection_store.get_binding("asp.example.org")
    assert binding is not None
    assert binding["pub"] in {_pub(old_key), _pub(new_key)}
    if binding["pub"] == _pub(old_key):
        assert binding["pending_replacement_pub"] == _pub(new_key)
        assert binding["key_changed"] is True
        with TestClient(app) as client:
            recovered = client.post(
                "/apa/register",
                json={"endpoint": "https://asp.example.org"},
            )
        assert recovered.status_code == 200
        assert recovered.json()["attestation"]["status"] == "active"
    final_binding = protection_store.get_binding("asp.example.org")
    assert final_binding is not None
    assert final_binding["pub"] == _pub(new_key)
    assert final_binding["pending_replacement_pub"] is None


def test_sdk_revocation_helper_preserves_plain_body_and_signs_exact_replacement() -> None:
    old_key = Ed25519PrivateKey.generate()
    new_pub = _pub(Ed25519PrivateKey.generate())
    nonce = b64u_encode(secrets.token_bytes(16), "nonce")
    attestation_id = "0123456789abcdef0123456789abcdef"

    plain = sign_revocation(
        attestation_id,
        old_key,
        ts=1_900_000_000,
        nonce=nonce,
    )
    rotating = sign_revocation(
        attestation_id,
        old_key,
        replacement_pub=new_pub,
        ts=1_900_000_000,
        nonce=nonce,
    )

    assert set(plain) == {"attestation_id", "ts", "nonce", "sig"}
    assert rotating["replacement_pub"] == new_pub
    verify_document(plain, _pub(old_key))
    verify_document(rotating, _pub(old_key))
    with pytest.raises(ValueError, match="nonce"):
        sign_revocation(attestation_id, old_key, nonce="")
    with pytest.raises(ValueError, match="differ"):
        sign_revocation(attestation_id, old_key, replacement_pub=_pub(old_key))
