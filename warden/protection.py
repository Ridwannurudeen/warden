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
from urllib.parse import urlsplit

import httpx

from warden.apa_url import PublicUrlUnavailable, validate_public_http_url
from warden.badges import b64u_decode, b64u_encode, ed25519_sign_record, ed25519_verify_record
from warden import protection_store

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC_VERSION = "apa/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/protection/v1"
ISSUER_NAME = "warden"
PROOF_PATH = "/.well-known/agent-protection"
PROOF_TTL_SECONDS = 3600
PROOF_WINDOW_SECONDS = 86_400
ATTESTATION_TTL_SECONDS = 3600
PROBE_TIMEOUT_SECONDS = 3.0
MAX_PROOF_RESPONSE_BYTES = 64_000
MIN_NONCE_BITS = 128
ATTESTATION_SCOPE = "Endpoint-signed count; local counter state is not independently audited."
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991
DEFAULT_ISSUER_KID = "warden-issuer-1"

# Global cap on concurrent outbound probes, independent of per-IP rate limits
# (APA-SPEC §10 SSRF/DoS). Single-worker deployment, so a process-wide
# semaphore is the whole story.
_PROBE_SEMAPHORE = asyncio.Semaphore(4)


class ProtectionProbeUnavailable(ValueError):
    """No fresh proof can currently be obtained from the registered endpoint."""


class ProtectionProofInvalid(ValueError):
    """The endpoint returned a proof that fails APA validation."""


def _canonical_endpoint_host(host: str, *, scheme: str, port: int | None) -> str:
    host_identity = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme.lower() == "https" else 80
    return host_identity if port in (None, default_port) else f"{host_identity}:{port}"


def validate_endpoint_public_key(value: object, field_name: str) -> str:
    """Return a canonical APA Ed25519 public key or raise a field-specific error."""
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key")
    try:
        decoded = b64u_decode(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key") from exc
    if len(decoded) != 32 or b64u_encode(decoded, "ed25519") != value:
        raise ValueError(f"{field_name} must be a canonical ed25519: 32-byte key")
    return value


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


def _validate_issuer_key(key: object) -> dict[str, object]:
    if not isinstance(key, dict) or set(key) != {"kid", "pub", "not_after"}:
        raise ValueError("issuer history contains a malformed key")
    kid = key.get("kid")
    pub = key.get("pub")
    not_after = key.get("not_after")
    if not isinstance(kid, str) or not kid or kid.strip() != kid:
        raise ValueError("issuer key kid must be a non-empty trimmed string")
    if not isinstance(pub, str) or not pub.startswith("ed25519:"):
        raise ValueError("issuer key pub must be an ed25519: 32-byte key")
    try:
        decoded = b64u_decode(pub)
    except ValueError as exc:
        raise ValueError("issuer key pub must be an ed25519: 32-byte key") from exc
    if len(decoded) != 32 or b64u_encode(decoded, "ed25519") != pub:
        raise ValueError("issuer key pub must be canonical unpadded base64url")
    if type(not_after) is not int or not 0 <= not_after <= MAX_SAFE_UNIX_SECONDS:
        raise ValueError("issuer key not_after must be non-negative safe Unix seconds")
    return {"kid": kid, "pub": pub, "not_after": not_after}


def _issuer_history_keys() -> list[dict[str, object]]:
    history_value = os.getenv("WARDEN_ISSUER_HISTORY", "").strip()
    if not history_value:
        return []
    try:
        history = json.loads(Path(history_value).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("issuer history must be readable valid JSON") from exc
    if not isinstance(history, dict) or set(history) != {"keys"}:
        raise ValueError("issuer history must be an object containing only keys")
    keys = history.get("keys")
    if not isinstance(keys, list):
        raise ValueError("issuer history keys must be an array")
    validated = [_validate_issuer_key(key) for key in keys]
    if any(int(key["not_after"]) == MAX_SAFE_UNIX_SECONDS for key in validated):
        raise ValueError("retired issuer key not_after must be finite")
    return sorted(
        validated,
        key=lambda key: (-int(key["not_after"]), str(key["kid"])),
    )


def issuer_keys() -> list[dict[str, object]]:
    current = _validate_issuer_key(
        {
            "kid": os.getenv("WARDEN_ISSUER_KID", "").strip() or DEFAULT_ISSUER_KID,
            "pub": issuer_public_key(),
            "not_after": MAX_SAFE_UNIX_SECONDS,
        }
    )
    keys = [current, *_issuer_history_keys()]
    kids = [str(key["kid"]) for key in keys]
    pubs = [str(key["pub"]) for key in keys]
    if len(kids) != len(set(kids)):
        raise ValueError("issuer history contains a duplicate kid")
    if len(pubs) != len(set(pubs)):
        raise ValueError("issuer history contains a duplicate pub")
    return keys


def issuer_document() -> dict[str, object]:
    """The /.well-known/apa-issuer.json body (APA-SPEC §7.1)."""
    return {
        "issuer": ISSUER_NAME,
        "keys": issuer_keys(),
    }


async def _fetch_proof(endpoint: str) -> tuple[str, dict[str, object]]:
    """SSRF-safe fetch of the endpoint's Protection Proof.

    Returns (endpoint_host, proof). DNS is pinned by validate_public_http_url;
    redirects are not followed; the response is size-capped.
    """
    try:
        connect_url, host_header, parsed = await validate_public_http_url(endpoint)
    except PublicUrlUnavailable as exc:
        raise ProtectionProbeUnavailable(str(exc)) from exc
    except ValueError as exc:
        raise ProtectionProofInvalid(str(exc)) from exc
    origin_parts = httpx.URL(connect_url)
    proof_url = str(origin_parts.copy_with(path=PROOF_PATH, query=None))
    endpoint_host = _canonical_endpoint_host(
        host_header,
        scheme=parsed.scheme,
        port=parsed.port,
    )

    try:
        async with _PROBE_SEMAPHORE:
            async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
                async with httpx.AsyncClient(
                    timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=False
                ) as client:
                    async with client.stream(
                        "GET",
                        proof_url,
                        headers={"Host": endpoint_host},
                        extensions={"sni_hostname": host_header},
                    ) as response:
                        if response.status_code != 200:
                            raise ProtectionProbeUnavailable(
                                f"endpoint returned HTTP {response.status_code} for {PROOF_PATH}"
                            )
                        chunks: list[bytes] = []
                        total = 0
                        async for chunk in response.aiter_bytes():
                            total += len(chunk)
                            if total > MAX_PROOF_RESPONSE_BYTES:
                                raise ProtectionProofInvalid(
                                    "protection proof exceeds response size cap"
                                )
                            chunks.append(chunk)
    except TimeoutError as exc:
        raise ProtectionProbeUnavailable("protection proof request timed out") from exc
    except httpx.HTTPError as exc:
        raise ProtectionProbeUnavailable("protection proof request failed") from exc

    try:
        proof = json.loads(b"".join(chunks))
    except json.JSONDecodeError as exc:
        raise ProtectionProofInvalid("protection proof is not valid JSON") from exc
    if not isinstance(proof, dict):
        raise ProtectionProofInvalid("protection proof must be a JSON object")

    return endpoint_host, proof


async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
    """Fetch + verify an endpoint's Protection Proof (APA-SPEC §3/§4).

    Verifies the Ed25519 self-signature, freshness (TTL 3600s), nonce size and
    non-replay, and the host binding inside the signed document. Returns
    (endpoint_host, pub, scans_served), where scans_served may be None during
    an explicit migration warmup. Raises ValueError with the reason.
    """
    if urlsplit(endpoint).scheme.lower() != "https":
        raise ProtectionProofInvalid("APA protection endpoints must use HTTPS")
    endpoint_host, proof = await _fetch_proof(endpoint)

    raw_pub = proof.get("pub")
    if not isinstance(raw_pub, str) or not raw_pub:
        raise ProtectionProofInvalid("protection proof is missing 'pub'")
    try:
        pub = validate_endpoint_public_key(raw_pub, "protection proof pub")
    except ValueError as exc:
        raise ProtectionProofInvalid(str(exc)) from exc
    signature = proof.get("sig")
    try:
        if not isinstance(signature, str) or not signature.startswith("sig:"):
            raise ValueError
        if len(b64u_decode(signature)) != 64:
            raise ValueError
    except ValueError as exc:
        raise ProtectionProofInvalid(
            "protection proof sig must be a sig: 64-byte signature"
        ) from exc
    if not ed25519_verify_record(proof, pub, "sig"):
        raise ProtectionProofInvalid("protection proof signature is invalid")

    if proof.get("spec_version") != SPEC_VERSION:
        raise ProtectionProofInvalid(f"protection proof spec_version must be '{SPEC_VERSION}'")

    if proof.get("protector") != ISSUER_NAME:
        raise ProtectionProofInvalid(f"protection proof protector must be '{ISSUER_NAME}'")

    ts = proof.get("ts")
    if type(ts) is not int:
        raise ProtectionProofInvalid("protection proof is missing integer 'ts'")
    age = int(time.time()) - ts
    if age > PROOF_TTL_SECONDS:
        raise ProtectionProbeUnavailable("protection proof is stale (ts outside TTL)")
    if age < -PROOF_TTL_SECONDS:
        raise ProtectionProofInvalid("protection proof timestamp is outside TTL")

    proof_host = proof.get("endpoint_host")
    if proof_host != endpoint_host:
        raise ProtectionProofInvalid(
            "protection proof endpoint_host does not match the probed host"
        )

    window_s = proof.get("window_s")
    if type(window_s) is not int or window_s != PROOF_WINDOW_SECONDS:
        raise ProtectionProofInvalid("protection proof window_s must be 86400")
    window_start = proof.get("window_start")
    if type(window_start) is not int or window_start != ts - window_s:
        raise ProtectionProofInvalid("protection proof window_start must equal ts - window_s")

    if "scans_served" not in proof:
        raise ProtectionProofInvalid("protection proof scans_served is required")
    scans_served = proof["scans_served"]
    if scans_served is not None and (type(scans_served) is not int or scans_served < 0):
        raise ProtectionProofInvalid(
            "protection proof scans_served must be null or a non-negative integer"
        )

    nonce = proof.get("nonce")
    if not isinstance(nonce, str) or len(b64u_decode(nonce)) * 8 < MIN_NONCE_BITS:
        raise ProtectionProofInvalid("protection proof nonce must be at least 128 bits")
    if not protection_store.record_nonce(endpoint_host, nonce):
        raise ProtectionProofInvalid("protection proof nonce was replayed")
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
    return _issuer_sign_attestation(record)


def _issuer_sign_attestation(record: dict[str, object]) -> dict[str, object]:
    return ed25519_sign_record(record, issuer_private_key(), "issuer_sig")


def resign_attestation_status(record: dict[str, object], status: str) -> dict[str, object]:
    """Return an issuer-signed copy with a new explicit status."""
    updated = dict(record)
    updated["status"] = status
    return _issuer_sign_attestation(updated)


def refresh_attestation(
    record: dict[str, object],
    scans: int | None,
    *,
    verified_at: int | None = None,
) -> dict[str, object]:
    """Return an issuer-signed active copy refreshed by a valid same-key proof."""
    current = verified_at if verified_at is not None else int(time.time())
    updated = dict(record)
    updated.update(
        {
            "status": "active",
            "scans_24h": scans,
            "verified_at": current,
            "expires_at": current + ATTESTATION_TTL_SECONDS,
        }
    )
    return _issuer_sign_attestation(updated)


def verify_attestation_record(record: dict[str, object]) -> bool:
    """Verify against each issuer key valid at the record's signed verification time."""
    verified_at = record.get("verified_at")
    expires_at = record.get("expires_at")
    if (
        type(verified_at) is not int
        or verified_at < 0
        or verified_at > MAX_SAFE_UNIX_SECONDS - ATTESTATION_TTL_SECONDS
        or type(expires_at) is not int
        or expires_at != verified_at + ATTESTATION_TTL_SECONDS
    ):
        return False
    try:
        keys = issuer_keys()
    except ValueError:
        return False
    return any(
        verified_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def effective_status(record: dict[str, object], now: int | None = None) -> str:
    """True current status: invalid signatures fail before stored status or expiry."""
    if not verify_attestation_record(record):
        return "invalid"
    current = now if now is not None else int(time.time())
    expires_at = record.get("expires_at")
    if isinstance(expires_at, int) and current > expires_at:
        return "stale"
    return str(record.get("status", "invalid"))


_BADGE_COLORS = {
    "active": "#0ea371",
    "stale": "#b45309",
    "key-changed": "#be123c",
    "revoked": "#be123c",
    "invalid": "#be123c",
}


def render_badge_svg(status: str, scans_24h: int | None) -> str:
    """Embeddable SVG for an attestation. Always renders the true status.

    Honest label per APA-SPEC §5: "Warden Guard Live · N/24h" or an explicit
    unavailable count — never a bare "Protected". Non-active statuses render
    their own label and color.
    """
    if status == "active":
        right = f"{scans_24h}/24h" if isinstance(scans_24h, int) else "count unavailable"
    else:
        right = status
    color = _BADGE_COLORS.get(status, _BADGE_COLORS["invalid"])
    label = "Warden Guard Live" if status == "active" else "Warden APA"
    left_width = 118
    right_width = 12 + 7 * len(right)
    total = left_width + right_width
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {right}">'
        f"<desc>{ATTESTATION_SCOPE}</desc>"
        f'<rect width="{left_width}" height="20" fill="#1f2937"/>'
        f'<rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>'
        f'<g fill="#ffffff" font-family="Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="8" y="14">{label}</text>'
        f'<text x="{left_width + 6}" y="14">{right}</text>'
        f"</g></svg>"
    )


def verify_revocation(
    body: dict[str, object],
    bound_pub: str,
    endpoint_host: str,
    *,
    consume_nonce: bool = True,
) -> str | None:
    """Validate a POST /apa/revoke request signed by the endpoint key.

    Body core: {attestation_id, ts, nonce, replacement_pub?}, `sig` by the
    currently bound endpoint private key. Returns the canonical replacement
    key when present. API callers defer nonce consumption to their SQLite
    transaction; direct callers retain the original consume-on-verify behavior.
    """
    if not ed25519_verify_record(body, bound_pub, "sig"):
        raise ValueError("revocation signature is invalid")
    ts = body.get("ts")
    if type(ts) is not int or abs(int(time.time()) - ts) > PROOF_TTL_SECONDS:
        raise ValueError("revocation timestamp is missing or outside TTL")
    nonce = body.get("nonce")
    try:
        nonce_bytes = b64u_decode(nonce) if isinstance(nonce, str) else b""
    except ValueError as exc:
        raise ValueError("revocation nonce must be at least 128 bits") from exc
    if len(nonce_bytes) * 8 < MIN_NONCE_BITS:
        raise ValueError("revocation nonce must be at least 128 bits")
    replacement = body.get("replacement_pub")
    if replacement is not None:
        replacement = validate_endpoint_public_key(replacement, "replacement_pub")
        if replacement == bound_pub:
            raise ValueError("replacement_pub must differ from the currently bound key")
    if consume_nonce and not protection_store.record_nonce(endpoint_host, nonce):
        raise ValueError("revocation nonce was replayed")
    return replacement
