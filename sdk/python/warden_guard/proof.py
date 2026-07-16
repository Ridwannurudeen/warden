"""Protection Proof — the signed APA heartbeat served at
`GET /.well-known/agent-protection` (APA-SPEC §3).

What this proves, precisely: the host controls the guard key and signs an exact
rolling 24-hour count of payloads screened by this SDK, or signs `null` while a
legacy counter completes its warmup (`scans_served` comes from
:mod:`warden_guard.state`). It does NOT prove every request is routed through
the guard or independently audit the endpoint owner's local state.
"""

from __future__ import annotations

import json
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden_guard.apa import sign_document
from warden_guard.keys import load_or_create_key, public_key_str
from warden_guard.state import get_window_scan_count

SPEC_VERSION = "apa/0.1"
PROTECTOR = "warden"
WELL_KNOWN_PATH = "/.well-known/agent-protection"
DEFAULT_WINDOW_S = 86400


def protection_proof(
    endpoint_host: str,
    *,
    key: Ed25519PrivateKey | None = None,
    window_s: int = DEFAULT_WINDOW_S,
) -> dict[str, object]:
    """Build one signed Protection Proof document (a fresh nonce every call)."""
    if window_s != DEFAULT_WINDOW_S:
        raise ValueError("APA v0.1 protection proofs require window_s=86400")
    guard_key = key or load_or_create_key()
    now = int(time.time())
    doc: dict[str, object] = {
        "spec_version": SPEC_VERSION,
        "protector": PROTECTOR,
        "endpoint_host": endpoint_host,
        "pub": public_key_str(guard_key),
        "ts": now,
        "nonce": secrets.token_urlsafe(16),  # 128 bits
        "window_s": window_s,
        "window_start": now - window_s,
        "scans_served": get_window_scan_count(window_s=window_s, now=now),
    }
    return sign_document(doc, guard_key, sig_field="sig")


class ProtectionProofApp:
    """Pure-ASGI app serving the signed heartbeat.

    Mount it on any ASGI framework, e.g. FastAPI/Starlette:

        app.mount("/.well-known/agent-protection", ProtectionProofApp("api.example.com"))
    """

    def __init__(
        self,
        endpoint_host: str,
        *,
        key: Ed25519PrivateKey | None = None,
        window_s: int = DEFAULT_WINDOW_S,
    ) -> None:
        self.endpoint_host = endpoint_host
        self.key = key or load_or_create_key()
        self.window_s = window_s

    async def __call__(self, scope: dict, receive: object, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            raise RuntimeError("ProtectionProofApp only handles HTTP")
        if scope["method"] not in ("GET", "HEAD"):
            await _respond(send, 405, {"error": "method not allowed"})
            return
        doc = protection_proof(self.endpoint_host, key=self.key, window_s=self.window_s)
        await _respond(send, 200, doc)


async def _respond(send, status: int, body: dict) -> None:  # noqa: ANN001
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})
