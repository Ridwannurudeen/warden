"""Middleware short-circuit, @guard decorator, and the verify/keygen CLI."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden_guard import ScanResult, WardenBlocked, WardenClient, WardenGuard, guard
from warden_guard.apa import b64u_encode, sign_document
from warden_guard.cli import main as cli_main


class StubClient(WardenClient):
    """WardenClient whose scan() returns a fixed verdict (no network)."""

    def __init__(self, verdict: str, sanitized: str = "") -> None:
        super().__init__()
        self._result = ScanResult(
            verdict=verdict,
            risk_level="HIGH" if verdict != "ALLOW" else "NONE",
            threat_classes=["PROMPT_INJECTION"] if verdict != "ALLOW" else [],
            sanitized_payload=sanitized,
            raw={"verdict": verdict},
        )

    def scan(self, payload: str, **kwargs: object) -> ScanResult:  # type: ignore[override]
        return self._result


async def _echo_app(scope: dict, receive, send) -> None:  # noqa: ANN001
    body = bytearray()
    more = True
    while more:
        message = await receive()
        body.extend(message.get("body", b""))
        more = message.get("more_body", False)
    payload = bytes(body)
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", str(len(payload)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _run(app, method: str, body: bytes) -> tuple[int, bytes]:  # noqa: ANN001
    messages: list[dict] = []
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app({"type": "http", "method": method, "path": "/"}, receive, send)
    payload = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return messages[0]["status"], payload


async def test_middleware_short_circuits_block_with_400() -> None:
    app = WardenGuard(_echo_app, client=StubClient("BLOCK"))
    status, body = await _run(app, "POST", b"poisoned payload")
    assert status == 400
    detail = json.loads(body)
    assert detail["error"] == "payload blocked by Warden"
    assert detail["verdict"]["verdict"] == "BLOCK"


async def test_middleware_passes_allow_through_with_body_intact() -> None:
    app = WardenGuard(_echo_app, client=StubClient("ALLOW"))
    status, body = await _run(app, "POST", b"hello agent")
    assert status == 200
    assert body == b"hello agent"


async def test_middleware_skips_get_requests() -> None:
    app = WardenGuard(_echo_app, client=StubClient("BLOCK"))
    status, _ = await _run(app, "GET", b"")
    assert status == 200


def test_decorator_blocks_and_sanitizes() -> None:
    calls: list[str] = []

    @guard(StubClient("SANITIZE", sanitized="clean"), field="payload")
    def handle(payload: str) -> str:
        calls.append(payload)
        return payload

    assert handle("dirty") == "clean"
    assert calls == ["clean"]

    @guard(StubClient("BLOCK"), field="payload")
    def strict(payload: str) -> str:
        return payload

    with pytest.raises(WardenBlocked):
        strict("evil")


def test_decorator_rejects_missing_field() -> None:
    with pytest.raises(TypeError):

        @guard(StubClient("ALLOW"), field="payload")
        def no_payload(text: str) -> str:
            return text


def test_cli_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["keygen"]) == 0
    out = capsys.readouterr().out
    assert "public key: ed25519:" in out


def test_cli_verify_attestation_roundtrip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = b64u_encode(issuer.public_key().public_bytes_raw(), "ed25519")
    att = {
        "spec_version": "apa/0.1",
        "attestation_id": "test-0001",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": "api.example.com",
        "pub": "ed25519:ENDPOINTKEY",
        "tier": "guard-live",
        "status": "active",
        "scans_24h": 7,
        "verified_at": int(time.time()),
        "expires_at": int(time.time()) + 3600,
    }
    signed = sign_document(att, issuer, sig_field="issuer_sig")
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(signed), encoding="utf-8")

    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 0
    assert "VALID" in capsys.readouterr().out

    tampered = dict(signed)
    tampered["scans_24h"] = 999_999
    path.write_text(json.dumps(tampered), encoding="utf-8")
    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_cli_verify_expired_attestation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = b64u_encode(issuer.public_key().public_bytes_raw(), "ed25519")
    att = {
        "spec_version": "apa/0.1",
        "endpoint_host": "api.example.com",
        "status": "active",
        "expires_at": int(time.time()) - 10,
    }
    signed = sign_document(att, issuer, sig_field="issuer_sig")
    path = tmp_path / "expired.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 1
    assert "EXPIRED" in capsys.readouterr().out
