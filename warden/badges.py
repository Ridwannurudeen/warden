"""Badge issuance and verification helpers for Warden audits."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _badge_secret(secret: str | None = None) -> str:
    configured = secret if secret is not None else os.getenv("WARDEN_BADGE_SECRET")
    if configured is None or not configured.strip():
        raise RuntimeError("WARDEN_BADGE_SECRET is required for badge integrity")
    return configured


def _canonical_json(record: dict[str, object]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def b64u_encode(raw: bytes, prefix: str) -> str:
    """Encode bytes as APA `prefix:base64url` (unpadded)."""
    return f"{prefix}:{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}"


def b64u_decode(value: str) -> bytes:
    """Decode APA `alg:base64url` (unpadded) to bytes. Tolerates a missing prefix."""
    raw = value.split(":", 1)[1] if ":" in value else value
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def ed25519_sign_record(
    record: dict[str, object], private_key: Ed25519PrivateKey, sig_field: str
) -> dict[str, object]:
    """Return a copy of record with `sig_field` = Ed25519 sig over canonical(record - sig_field)."""
    core = {key: value for key, value in record.items() if key != sig_field}
    signature = private_key.sign(_canonical_json(core).encode("utf-8"))
    signed = dict(core)
    signed[sig_field] = b64u_encode(signature, "sig")
    return signed


def ed25519_verify_record(record: dict[str, object], pub: str, sig_field: str) -> bool:
    """Verify an Ed25519 `sig_field` over canonical(record - sig_field) against `pub`."""
    signature = record.get(sig_field)
    if not isinstance(signature, str):
        return False
    core = {key: value for key, value in record.items() if key != sig_field}
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(pub)).verify(
            b64u_decode(signature), _canonical_json(core).encode("utf-8")
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def issue_badge(
    target_host: str,
    score: float,
    grade: str,
    blocked: int,
    total: int,
    issued_at: str,
    consent_verified: bool = True,
    *,
    secret: str | None = None,
) -> dict[str, object]:
    """
    Issue a signed badge record for a completed audit.

    The audit id is stable for the same target host, score, and issued date.
    `consent_verified` is part of the signed payload so an unconsented audit
    can never be re-labeled as consented after issuance.
    """
    short_hash_input = f"{target_host}|{issued_at}|{score}"
    audit_id = hashlib.sha256(short_hash_input.encode("utf-8")).hexdigest()[:16]

    payload = {
        "audit_id": audit_id,
        "target_host": target_host,
        "grade": grade,
        "score": score,
        "blocked": blocked,
        "total": total,
        "issued_at": issued_at,
        "consent_verified": consent_verified,
    }
    canonical_payload = dict(payload)
    canonical_json = _canonical_json(canonical_payload)
    payload["signature"] = hmac.new(
        _badge_secret(secret).encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return payload


def verify_badge(badge: dict[str, object], *, secret: str | None = None) -> bool:
    """
    Verify a badge record's integrity.
    """
    signature = badge.get("signature")
    if not isinstance(signature, str):
        return False

    expected = dict(badge)
    expected.pop("signature", None)
    canonical_json = _canonical_json(expected)
    expected_signature = hmac.new(
        _badge_secret(secret).encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
