"""Objective gate: the SDK heartbeat MUST verify with spec/verify_apa.py's crypto."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from warden_guard.keys import key_path, load_or_create_key, public_key_str
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
    assert doc["scans_served"] == 3
    assert len(verify_apa.b64u_decode(str(doc["nonce"]))) >= 16  # >=128-bit nonce
    assert isinstance(doc["ts"], int)


def test_heartbeat_verifies_with_reference_verifier() -> None:
    doc = protection_proof("api.example.com")
    # spec/verify_apa.py's exact signature check (used by its _reprobe): must not raise
    verify_apa._verify_sig(doc, "sig", str(doc["pub"]))


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
