"""Middleware short-circuit, @guard decorator, and the verify/keygen CLI."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden_guard import (
    AsyncWardenClient,
    ScanResult,
    WardenBlocked,
    WardenClient,
    WardenGuard,
    guard,
    guard_output,
)
from warden_guard.apa import b64u_encode, sign_document
from warden_guard.cli import main as cli_main, verify_endpoint
from warden_guard.keys import load_or_create_key
from warden_guard.proof import WELL_KNOWN_PATH, protection_proof


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


class AsyncStubClient(AsyncWardenClient):
    """AsyncWardenClient whose scan() returns a fixed verdict (no network)."""

    def __init__(self, verdict: str, sanitized: str = "") -> None:
        super().__init__()
        self._result = ScanResult(
            verdict=verdict,
            risk_level="HIGH" if verdict != "ALLOW" else "NONE",
            threat_classes=["PROMPT_INJECTION"] if verdict != "ALLOW" else [],
            sanitized_payload=sanitized,
            raw={"verdict": verdict},
        )

    async def scan(self, payload: str, **kwargs: object) -> ScanResult:  # type: ignore[override]
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


def test_output_decorator_sanitizes_and_blocks() -> None:
    @guard_output(StubClient("SANITIZE", sanitized="clean output"))
    def tool(query: str) -> str:
        return "dirty output"

    assert tool("q") == "clean output"

    @guard_output(StubClient("BLOCK"))
    def risky(query: str) -> str:
        return "attacker payload"

    with pytest.raises(WardenBlocked):
        risky("q")


def test_output_decorator_allows_original() -> None:
    @guard_output(StubClient("ALLOW"))
    def tool(query: str) -> str:
        return "safe output"

    assert tool("q") == "safe output"


async def test_output_decorator_async_sanitizes() -> None:
    @guard_output(AsyncStubClient("SANITIZE", sanitized="clean"))
    async def tool(query: str) -> str:
        return "dirty"

    assert await tool("q") == "clean"


def test_cli_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["keygen"]) == 0
    out = capsys.readouterr().out
    assert "public key: ed25519:" in out


def test_cli_live_proof_renders_null_scan_count_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = load_or_create_key()
    proof = protection_proof("api.example.com", key=key)
    proof["scans_served"] = None
    proof = sign_document(proof, key, sig_field="sig")
    payload = json.dumps(proof).encode("utf-8")

    class Response:
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return payload[:limit]

        def geturl(self) -> str:
            return f"https://api.example.com{WELL_KNOWN_PATH}"

    class Opener:
        def open(self, *args: object, **kwargs: object) -> Response:
            return Response()

    monkeypatch.setattr("warden_guard.cli._PROOF_OPENER", Opener())

    ok, message = verify_endpoint("https://api.example.com")

    assert ok is True
    assert "scans_served=unavailable" in message
    assert "scans_served=None" not in message


def test_cli_live_proof_canonicalizes_explicit_default_https_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = load_or_create_key()
    payload = json.dumps(protection_proof("api.example.com", key=key)).encode("utf-8")
    requested_urls: list[str] = []

    class Response:
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return payload[:limit]

        def geturl(self) -> str:
            return requested_urls[-1]

    class Opener:
        def open(self, url: str, *, timeout: int) -> Response:
            requested_urls.append(url)
            return Response()

    monkeypatch.setattr("warden_guard.cli._PROOF_OPENER", Opener())

    ok, message = verify_endpoint("https://API.EXAMPLE.COM:443")

    assert ok is True
    assert "host=api.example.com" in message
    assert requested_urls == [f"https://api.example.com{WELL_KNOWN_PATH}"]


def test_cli_verify_attestation_roundtrip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = b64u_encode(issuer.public_key().public_bytes_raw(), "ed25519")
    endpoint_pub = b64u_encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    att = {
        "spec_version": "apa/0.1",
        "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
        "attestation_id": "00000000000000000000000000000001",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": "api.example.com",
        "pub": endpoint_pub,
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

    unavailable = dict(att)
    unavailable["scans_24h"] = None
    signed_unavailable = sign_document(unavailable, issuer, sig_field="issuer_sig")
    path.write_text(json.dumps(signed_unavailable), encoding="utf-8")
    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 0
    unavailable_output = capsys.readouterr().out
    assert "unavailable" in unavailable_output.lower()
    assert "None scans/24h" not in unavailable_output

    tampered = dict(signed)
    tampered["scans_24h"] = 999_999
    path.write_text(json.dumps(tampered), encoding="utf-8")
    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_cli_verify_expired_attestation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = b64u_encode(issuer.public_key().public_bytes_raw(), "ed25519")
    endpoint_pub = b64u_encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    now = int(time.time())
    att = {
        "spec_version": "apa/0.1",
        "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
        "attestation_id": "00000000000000000000000000000002",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": "api.example.com",
        "pub": endpoint_pub,
        "tier": "guard-live",
        "status": "active",
        "scans_24h": 7,
        "verified_at": now - 3600,
        "expires_at": now - 10,
    }
    signed = sign_document(att, issuer, sig_field="issuer_sig")
    path = tmp_path / "expired.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 1
    assert "EXPIRED" in capsys.readouterr().out


def test_cli_rejects_a_signed_malformed_attestation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = b64u_encode(issuer.public_key().public_bytes_raw(), "ed25519")
    endpoint_pub = b64u_encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    now = int(time.time())
    malformed = sign_document(
        {
            "spec_version": "apa/0.1",
            "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
            "attestation_id": "00000000000000000000000000000003",
            "issuer": "warden",
            "protector": "warden",
            "endpoint_host": "api.example.com",
            "pub": endpoint_pub,
            "tier": "guard-live",
            "status": "active",
            "scans_24h": True,
            "verified_at": now,
            "expires_at": now + 3600,
        },
        issuer,
        sig_field="issuer_sig",
    )
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")

    assert cli_main(["verify", str(path), "--issuer-pub", issuer_pub]) == 1
    assert "INVALID" in capsys.readouterr().out
