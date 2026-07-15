"""APA issuer core: heartbeat probing, attestation issuance, offline verification.

Implements the issuer side of spec/APA-SPEC.md v0.1. Two Ed25519 layers, never
conflated: the endpoint signs its Protection Proof with its own keypair (`pub`),
the issuer signs the Attestation record with the issuer key.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from pathlib import Path

import httpx

from warden.apa_url import validate_public_http_url
from warden.badges import b64u_decode, b64u_encode, ed25519_sign_record, ed25519_verify_record
from warden import protection_store

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC_VERSION = "apa/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/protection/v1"
ISSUER_NAME = "warden"
PROOF_PATH = "/.well-known/agent-protection"
PROOF_TTL_SECONDS = 3600
ATTESTATION_TTL_SECONDS = 3600
PROBE_TIMEOUT_SECONDS = 3.0
MAX_PROOF_RESPONSE_BYTES = 64_000
MIN_NONCE_BITS = 128

# Global cap on concurrent outbound probes, independent of per-IP rate limits
# (APA-SPEC §10 SSRF/DoS). Single-worker deployment, so a process-wide
# semaphore is the whole story.
_PROBE_SEMAPHORE = asyncio.Semaphore(4)


def _issuer_key_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "apa_issuer.key"


def issuer_private_key() -> Ed25519PrivateKey:
    """Load the issuer Ed25519 key from WARDEN_ISSUER_KEY (base64url 32-byte seed).

    Dev fallback: generate once and persist next to the other local data files
    so attestations stay verifiable across restarts.
    """
    seed_value = os.getenv("WARDEN_ISSUER_KEY", "").strip()
    if seed_value:
        return Ed25519PrivateKey.from_private_bytes(b64u_decode(seed_value))

    key_path = _issuer_key_path()
    if key_path.exists():
        stored = key_path.read_text(encoding="utf-8").strip()
        return Ed25519PrivateKey.from_private_bytes(b64u_decode(stored))

    key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    seed = b64u_encode(private_key.private_bytes_raw(), "ed25519-seed")
    key_path.write_text(seed + "\n", encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # best effort on non-POSIX filesystems
    return private_key


def issuer_public_key() -> str:
    return b64u_encode(issuer_private_key().public_key().public_bytes_raw(), "ed25519")


def issuer_document() -> dict[str, object]:
    """The /.well-known/apa-issuer.json body (APA-SPEC §7.1)."""
    return {
        "issuer": ISSUER_NAME,
        "keys": [{"kid": "warden-issuer-1", "pub": issuer_public_key(), "not_after": None}],
    }


async def _fetch_proof(endpoint: str) -> tuple[str, dict[str, object]]:
    """SSRF-safe fetch of the endpoint's Protection Proof.

    Returns (endpoint_host, proof). DNS is pinned by validate_public_http_url;
    redirects are not followed; the response is size-capped.
    """
    connect_url, host_header, parsed = await validate_public_http_url(endpoint)
    origin_parts = httpx.URL(connect_url)
    proof_url = str(origin_parts.copy_with(path=PROOF_PATH, query=None))
    host_with_port = host_header
    if parsed.port and f":{parsed.port}" not in host_with_port:
        host_with_port = f"{host_with_port}:{parsed.port}"

    async with _PROBE_SEMAPHORE:
        async with httpx.AsyncClient(
            timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            async with client.stream(
                "GET",
                proof_url,
                headers={"Host": host_with_port},
                extensions={"sni_hostname": host_header},
            ) as response:
                if response.status_code != 200:
                    raise ValueError(
                        f"endpoint returned HTTP {response.status_code} for {PROOF_PATH}"
                    )
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_PROOF_RESPONSE_BYTES:
                        raise ValueError("protection proof exceeds response size cap")
                    chunks.append(chunk)

    try:
        proof = json.loads(b"".join(chunks))
    except json.JSONDecodeError as exc:
        raise ValueError("protection proof is not valid JSON") from exc
    if not isinstance(proof, dict):
        raise ValueError("protection proof must be a JSON object")

    endpoint_host = host_header if not parsed.port else f"{host_header}:{parsed.port}"
    return endpoint_host, proof


async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
    """Fetch + verify an endpoint's Protection Proof (APA-SPEC §3/§4).

    Verifies the Ed25519 self-signature, freshness (TTL 3600s), nonce size and
    non-replay, and the host binding inside the signed document. Returns
    (endpoint_host, pub, scans_served). Raises ValueError with the reason.
    """
    endpoint_host, proof = await _fetch_proof(endpoint)

    pub = proof.get("pub")
    if not isinstance(pub, str) or not pub:
        raise ValueError("protection proof is missing 'pub'")
    if not ed25519_verify_record(proof, pub, "sig"):
        raise ValueError("protection proof signature is invalid")

    ts = proof.get("ts")
    if not isinstance(ts, int):
        raise ValueError("protection proof is missing integer 'ts'")
    if int(time.time()) - ts > PROOF_TTL_SECONDS:
        raise ValueError("protection proof is stale (ts outside TTL)")

    proof_host = proof.get("endpoint_host")
    if proof_host != endpoint_host:
        raise ValueError("protection proof endpoint_host does not match the probed host")

    nonce = proof.get("nonce")
    if not isinstance(nonce, str) or len(b64u_decode(nonce)) * 8 < MIN_NONCE_BITS:
        raise ValueError("protection proof nonce must be at least 128 bits")
    if not protection_store.record_nonce(endpoint_host, nonce):
        raise ValueError("protection proof nonce was replayed")

    scans_served = proof.get("scans_served")
    if not isinstance(scans_served, int) or scans_served < 0:
        scans_served = None
    return endpoint_host, pub, scans_served


def issue_attestation(
    endpoint_host: str,
    pub: str,
    scans: int | None,
    tier: str = "guard-live",
    status: str = "active",
) -> dict[str, object]:
    """Build and issuer-sign an APA §5 attestation record (endpoint-host keyed only)."""
    now = int(time.time())
    record = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "attestation_id": secrets.token_hex(16),
        "issuer": ISSUER_NAME,
        "protector": ISSUER_NAME,
        "endpoint_host": endpoint_host,
        "pub": pub,
        "tier": tier,
        "status": status,
        "scans_24h": scans,
        "verified_at": now,
        "expires_at": now + ATTESTATION_TTL_SECONDS,
    }
    return ed25519_sign_record(record, issuer_private_key(), "issuer_sig")


def verify_attestation_record(record: dict[str, object]) -> bool:
    """Verify the issuer signature over canonical(record without issuer_sig)."""
    return ed25519_verify_record(record, issuer_public_key(), "issuer_sig")


def effective_status(record: dict[str, object], now: int | None = None) -> str:
    """True current status: revoked/key-changed persist; expired active reads stale."""
    status = str(record.get("status", "invalid"))
    if status != "active":
        return status
    current = now if now is not None else int(time.time())
    expires_at = record.get("expires_at")
    if isinstance(expires_at, int) and current > expires_at:
        return "stale"
    return "active"


_BADGE_COLORS = {
    "active": "#0ea371",
    "stale": "#b45309",
    "key-changed": "#be123c",
    "revoked": "#be123c",
    "invalid": "#be123c",
}


def render_badge_svg(status: str, scans_24h: int | None) -> str:
    """Embeddable SVG for an attestation. Always renders the true status.

    Honest label per APA-SPEC §5: "Warden Guard Live · N/24h" — never a bare
    "Protected". Non-active statuses render their own label and color.
    """
    if status == "active":
        right = f"{scans_24h}/24h" if isinstance(scans_24h, int) else "live"
    else:
        right = status
    color = _BADGE_COLORS.get(status, _BADGE_COLORS["invalid"])
    label = "Warden Guard Live"
    left_width = 118
    right_width = 12 + 7 * len(right)
    total = left_width + right_width
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {right}">'
        f'<rect width="{left_width}" height="20" fill="#1f2937"/>'
        f'<rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>'
        f'<g fill="#ffffff" font-family="Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="8" y="14">{label}</text>'
        f'<text x="{left_width + 6}" y="14">{right}</text>'
        f"</g></svg>"
    )


def verify_revocation(body: dict[str, object], bound_pub: str, endpoint_host: str) -> None:
    """Validate a POST /apa/revoke request signed by the endpoint key.

    Body core: {attestation_id, ts, nonce}, `sig` by the endpoint private key.
    Raises ValueError with the reason on any failure.
    """
    if not ed25519_verify_record(body, bound_pub, "sig"):
        raise ValueError("revocation signature is invalid")
    ts = body.get("ts")
    if not isinstance(ts, int) or abs(int(time.time()) - ts) > PROOF_TTL_SECONDS:
        raise ValueError("revocation timestamp is missing or outside TTL")
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or len(b64u_decode(nonce)) * 8 < MIN_NONCE_BITS:
        raise ValueError("revocation nonce must be at least 128 bits")
    if not protection_store.record_nonce(endpoint_host, nonce):
        raise ValueError("revocation nonce was replayed")
