"""Objective gate: the SDK heartbeat MUST verify with spec/verify_apa.py's crypto."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from warden_guard.apa import validate_protection_proof
from warden_guard.keys import key_path, load_or_create_key, public_key_str
from warden_guard import proof, state
from warden_guard.proof import ProtectionProofApp, protection_proof
from warden_guard.state import increment_scan_count

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_reference_verifier():  # noqa: ANN202
    spec_path = REPO_ROOT / "spec" / "verify_apa.py"
    spec = importlib.util.spec_from_file_location("verify_apa", spec_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_apa = _load_reference_verifier()


def test_heartbeat_shape() -> None:
    for _ in range(3):
        increment_scan_count()
    doc = protection_proof("api.example.com")
    assert doc["spec_version"] == "apa/0.1"
    assert doc["protector"] == "warden"
    assert doc["endpoint_host"] == "api.example.com"
    assert str(doc["pub"]).startswith("ed25519:")
    assert str(doc["sig"]).startswith("sig:")
    assert doc["window_s"] == 86400
    assert doc["window_start"] == doc["ts"] - 86400
    assert doc["scans_served"] == 3
    assert len(verify_apa.b64u_decode(str(doc["nonce"]))) >= 16  # >=128-bit nonce
    assert isinstance(doc["ts"], int)


def test_heartbeat_reports_the_signed_rolling_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 2_000_000_000
    clock = iter((now - 86_401, now - 60))
    monkeypatch.setattr(state.time, "time", lambda: next(clock))
    increment_scan_count()
    increment_scan_count()
    monkeypatch.setattr(proof.time, "time", lambda: now)

    doc = protection_proof("api.example.com")

    assert doc["window_start"] == now - 86_400
    assert doc["scans_served"] == 1


def test_legacy_heartbeat_signs_an_unavailable_counter_instead_of_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 2_000_000_000
    state.state_path().parent.mkdir(parents=True, exist_ok=True)
    state.state_path().write_text(
        json.dumps({"scans_served": 91_000, "updated_at": now - 60}),
        encoding="utf-8",
    )
    monkeypatch.setattr(proof.time, "time", lambda: now)

    doc = protection_proof("api.example.com")

    assert doc["scans_served"] is None
    validate_protection_proof(doc, expected_host="api.example.com", now=now)
    assert (
        verify_apa._validate_proof(
            doc,
            expected_host="api.example.com",
            expected_pub=str(doc["pub"]),
            now=now,
        )
        is None
    )


def test_heartbeat_rejects_a_nonstandard_attestation_window() -> None:
    with pytest.raises(ValueError, match="86400"):
        protection_proof("api.example.com", window_s=3600)


def test_heartbeat_verifies_with_reference_verifier() -> None:
    doc = protection_proof("api.example.com")
    validate_protection_proof(doc, expected_host="api.example.com", now=int(doc["ts"]))
    # spec/verify_apa.py's exact signature check (used by its _reprobe): must not raise
    verify_apa._verify_sig(doc, "sig", str(doc["pub"]))
    scans = verify_apa._validate_proof(
        doc,
        expected_host="api.example.com",
        expected_pub=str(doc["pub"]),
        now=int(doc["ts"]),
    )
    assert scans == 0


def test_reference_verifier_rejects_future_and_nonconforming_proofs() -> None:
    doc = protection_proof("api.example.com")
    future = dict(doc)
    future["ts"] = int(doc["ts"]) + verify_apa.TTL_SECONDS + 1
    future["window_start"] = int(future["ts"]) - 86400
    future = proof.sign_document(future, proof.load_or_create_key(), sig_field="sig")
    with pytest.raises(ValueError, match="outside TTL"):
        verify_apa._validate_proof(
            future,
            expected_host="api.example.com",
            expected_pub=str(future["pub"]),
            now=int(doc["ts"]),
        )

    malformed = dict(doc)
    malformed.pop("window_start")
    malformed = proof.sign_document(malformed, proof.load_or_create_key(), sig_field="sig")
    with pytest.raises(ValueError, match="window_start"):
        verify_apa._validate_proof(
            malformed,
            expected_host="api.example.com",
            expected_pub=str(malformed["pub"]),
            now=int(doc["ts"]),
        )

    missing_count = dict(doc)
    missing_count.pop("scans_served")
    missing_count = proof.sign_document(missing_count, proof.load_or_create_key(), sig_field="sig")
    with pytest.raises(ValueError, match="scans_served is required"):
        validate_protection_proof(
            missing_count,
            expected_host="api.example.com",
            now=int(doc["ts"]),
        )
    with pytest.raises(ValueError, match="scans_served is required"):
        verify_apa._validate_proof(
            missing_count,
            expected_host="api.example.com",
            expected_pub=str(missing_count["pub"]),
            now=int(doc["ts"]),
        )


def test_forged_scan_count_fails_reference_verifier() -> None:
    doc = protection_proof("api.example.com")
    forged = dict(doc)
    forged["scans_served"] = 999_999
    with pytest.raises(InvalidSignature):
        verify_apa._verify_sig(forged, "sig", str(forged["pub"]))


def test_canonicalization_matches_reference() -> None:
    from warden_guard.apa import canonical

    sample = {"b": 1, "a": {"z": "ü", "y": [1, 2]}, "sig": "x"}
    assert canonical(sample) == verify_apa.canonical(sample)


def test_key_persists_across_loads() -> None:
    first = public_key_str(load_or_create_key())
    second = public_key_str(load_or_create_key())
    assert first == second
    assert key_path().exists()


async def test_asgi_app_serves_signed_heartbeat() -> None:
    app = ProtectionProofApp("api.example.com")
    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app({"type": "http", "method": "GET", "path": "/"}, receive, send)
    start = messages[0]
    assert start["status"] == 200
    assert (b"cache-control", b"no-store") in start["headers"]
    doc = json.loads(messages[1]["body"])
    verify_apa._verify_sig(doc, "sig", doc["pub"])


async def test_asgi_app_rejects_post() -> None:
    app = ProtectionProofApp("api.example.com")
    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app({"type": "http", "method": "POST", "path": "/"}, receive, send)
    assert messages[0]["status"] == 405
