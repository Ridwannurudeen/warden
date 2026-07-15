"""APA v0.1 crypto primitives — canonicalization + Ed25519 sign/verify.

These MUST stay byte-identical to `spec/verify_apa.py` (the reference verifier):
canonical JSON is sorted keys, compact separators, `ensure_ascii=False`, UTF-8;
signatures are computed over the canonical bytes of the object WITHOUT its sig
field; keys/signatures are unpadded base64url prefixed `ed25519:` / `sig:`.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TTL_SECONDS = 3600  # APA §3 default heartbeat freshness window


def canonical(obj: dict) -> bytes:
    """RFC-8785-aligned canonical JSON (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def b64u_decode(value: str) -> bytes:
    """Decode `alg:base64url` (unpadded) → bytes. Tolerates a missing prefix."""
    raw = value.split(":", 1)[1] if ":" in value else value
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def b64u_encode(raw: bytes, prefix: str) -> str:
    return f"{prefix}:{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}"


def sign_document(doc: dict, private_key: Ed25519PrivateKey, sig_field: str = "sig") -> dict:
    """Return a copy of `doc` with `sig_field` = Ed25519 sig over canonical(doc)."""
    core = {k: v for k, v in doc.items() if k != sig_field}
    signed = dict(core)
    signed[sig_field] = b64u_encode(private_key.sign(canonical(core)), "sig")
    return signed


def verify_document(doc: dict, pub: str, sig_field: str = "sig") -> None:
    """Verify Ed25519 `sig_field` over canonical(doc without sig_field). Raises on failure."""
    signature = doc.get(sig_field)
    if not isinstance(signature, str):
        raise ValueError(f"missing {sig_field}")
    core = {k: v for k, v in doc.items() if k != sig_field}
    Ed25519PublicKey.from_public_bytes(b64u_decode(pub)).verify(
        b64u_decode(signature), canonical(core)
    )
