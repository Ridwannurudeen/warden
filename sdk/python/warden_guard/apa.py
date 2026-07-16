"""APA v0.1 crypto primitives — canonicalization + Ed25519 sign/verify.

These MUST stay byte-identical to `spec/verify_apa.py` (the reference verifier):
canonical JSON is sorted keys, compact separators, `ensure_ascii=False`, UTF-8;
signatures are computed over the canonical bytes of the object WITHOUT its sig
field; keys/signatures are unpadded base64url prefixed `ed25519:` / `sig:`.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TTL_SECONDS = 3600  # APA §3 default heartbeat freshness window
WINDOW_SECONDS = 86_400
SPEC_VERSION = "apa/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/protection/v1"
_ATTESTATION_ID = re.compile(r"^[0-9a-f]{32}$")
_TIERS = {"guard-live", "audited"}
_STATUSES = {"active", "stale", "key-changed", "revoked", "invalid"}


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


def _validate_canonical_public_key(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key")
    try:
        decoded = b64u_decode(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key") from exc
    if len(decoded) != 32 or b64u_encode(decoded, "ed25519") != value:
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key")
    return value


def sign_revocation(
    attestation_id: str,
    private_key: Ed25519PrivateKey,
    *,
    replacement_pub: str | None = None,
    ts: int | None = None,
    nonce: str | None = None,
) -> dict:
    """Sign a plain APA revocation or authorize one exact endpoint-key replacement."""
    if not _ATTESTATION_ID.fullmatch(attestation_id):
        raise ValueError("attestation_id must be 32 lowercase hexadecimal characters")
    timestamp = int(time.time()) if ts is None else ts
    if type(timestamp) is not int:
        raise ValueError("revocation ts must be an integer")
    request_nonce = b64u_encode(secrets.token_bytes(16), "nonce") if nonce is None else nonce
    try:
        nonce_bytes = b64u_decode(request_nonce)
    except ValueError as exc:
        raise ValueError("revocation nonce must contain at least 128 bits") from exc
    if len(nonce_bytes) < 16:
        raise ValueError("revocation nonce must contain at least 128 bits")

    core = {
        "attestation_id": attestation_id,
        "ts": timestamp,
        "nonce": request_nonce,
    }
    if replacement_pub is not None:
        canonical_replacement = _validate_canonical_public_key(
            replacement_pub,
            "replacement_pub",
        )
        current_pub = b64u_encode(private_key.public_key().public_bytes_raw(), "ed25519")
        if canonical_replacement == current_pub:
            raise ValueError("replacement_pub must differ from the currently bound key")
        core["replacement_pub"] = canonical_replacement
    return sign_document(core, private_key)


def verify_document(doc: dict, pub: str, sig_field: str = "sig") -> None:
    """Verify Ed25519 `sig_field` over canonical(doc without sig_field). Raises on failure."""
    signature = doc.get(sig_field)
    if not isinstance(signature, str) or not signature.startswith("sig:"):
        raise ValueError(f"missing {sig_field}")
    if not pub.startswith("ed25519:") or len(b64u_decode(pub)) != 32:
        raise ValueError("public key must be an ed25519: 32-byte key")
    if len(b64u_decode(signature)) != 64:
        raise ValueError(f"{sig_field} must be a sig: 64-byte signature")
    core = {k: v for k, v in doc.items() if k != sig_field}
    Ed25519PublicKey.from_public_bytes(b64u_decode(pub)).verify(
        b64u_decode(signature), canonical(core)
    )


def validate_protection_proof(
    proof: dict,
    *,
    expected_host: str | None = None,
    expected_pub: str | None = None,
    expected_protector: str | None = None,
    now: int | None = None,
) -> None:
    """Validate the complete signed APA v0.1 Protection Proof shape."""
    if not isinstance(proof, dict):
        raise ValueError("proof must be a JSON object")
    pub = proof.get("pub")
    if not isinstance(pub, str):
        raise ValueError("proof missing pub")
    if expected_pub is not None and pub != expected_pub:
        raise ValueError("endpoint key changed")
    verify_document(proof, pub, sig_field="sig")
    if proof.get("spec_version") != SPEC_VERSION:
        raise ValueError("proof spec_version must be apa/0.1")
    protector = proof.get("protector")
    if not isinstance(protector, str) or not protector:
        raise ValueError("proof protector must be a non-empty string")
    if expected_protector is not None and protector != expected_protector:
        raise ValueError("proof protector changed")
    endpoint_host = proof.get("endpoint_host")
    if not isinstance(endpoint_host, str) or not endpoint_host:
        raise ValueError("proof endpoint_host must be a non-empty string")
    if expected_host is not None and endpoint_host != expected_host:
        raise ValueError("proof endpoint_host does not match the requested host")
    timestamp = proof.get("ts")
    if type(timestamp) is not int:
        raise ValueError("proof ts must be an integer")
    current = int(time.time()) if now is None else now
    if type(current) is not int or abs(current - timestamp) > TTL_SECONDS:
        raise ValueError("proof timestamp is outside TTL")
    window_s = proof.get("window_s")
    if type(window_s) is not int or window_s != WINDOW_SECONDS:
        raise ValueError("proof window_s must be 86400")
    window_start = proof.get("window_start")
    if type(window_start) is not int or window_start != timestamp - window_s:
        raise ValueError("proof window_start must equal ts - window_s")
    if "scans_served" not in proof:
        raise ValueError("proof scans_served is required")
    scans = proof["scans_served"]
    if scans is not None and (type(scans) is not int or scans < 0):
        raise ValueError("proof scans_served must be null or a non-negative integer")
    nonce = proof.get("nonce")
    if not isinstance(nonce, str) or len(b64u_decode(nonce)) < 16:
        raise ValueError("proof nonce must contain at least 128 bits")


def validate_attestation(attestation: dict, issuer_pub: str) -> None:
    """Validate an issuer signature and the complete APA v0.1 record shape."""
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be a JSON object")
    verify_document(attestation, issuer_pub, sig_field="issuer_sig")
    if attestation.get("spec_version") != SPEC_VERSION:
        raise ValueError("attestation spec_version must be apa/0.1")
    if attestation.get("predicate_type") != PREDICATE_TYPE:
        raise ValueError("attestation predicate_type is unsupported")
    attestation_id = attestation.get("attestation_id")
    if not isinstance(attestation_id, str) or not _ATTESTATION_ID.fullmatch(attestation_id):
        raise ValueError("attestation_id must be 32 lowercase hexadecimal characters")
    for field in ("issuer", "protector", "endpoint_host"):
        if not isinstance(attestation.get(field), str) or not attestation[field]:
            raise ValueError(f"attestation {field} must be a non-empty string")
    pub = attestation.get("pub")
    if not isinstance(pub, str) or not pub.startswith("ed25519:") or len(b64u_decode(pub)) != 32:
        raise ValueError("attestation pub must be an ed25519: 32-byte key")
    if attestation.get("tier") not in _TIERS:
        raise ValueError("attestation tier is unsupported")
    if attestation.get("status") not in _STATUSES:
        raise ValueError("attestation status is unsupported")
    if "scans_24h" not in attestation:
        raise ValueError("attestation scans_24h is required")
    scans = attestation["scans_24h"]
    if scans is not None and (type(scans) is not int or scans < 0):
        raise ValueError("attestation scans_24h must be null or a non-negative integer")
    verified_at = attestation.get("verified_at")
    expires_at = attestation.get("expires_at")
    if type(verified_at) is not int or verified_at < 0:
        raise ValueError("attestation verified_at must be a non-negative integer")
    if type(expires_at) is not int or expires_at < verified_at:
        raise ValueError("attestation expires_at must be at or after verified_at")
