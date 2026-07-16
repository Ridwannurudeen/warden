#!/usr/bin/env python3
"""Portable Agent Protection Attestation (APA v0.1) verifier — reference impl.

Paste this into ANY marketplace or router agent. It verifies an APA attestation
**offline** against an issuer's published Ed25519 public key — no Warden account,
no callback to the issuer required.

Only dependency: `cryptography` (Ed25519). Everything else is stdlib.

Usage:
    # offline verify (issuer pubkey provided or fetched from issuer discovery URL)
    python verify_apa.py attestation.json --issuer-pub ed25519:PB1n...
    python verify_apa.py attestation.json --issuer-url https://warden.gudman.xyz

    # also re-probe the endpoint's live heartbeat (stronger: confirms guard still up)
    python verify_apa.py attestation.json --issuer-pub ed25519:... --live

    # prove the verifier + spec crypto are correct (generates a keypair, round-trips)
    python verify_apa.py --selftest

Spec: spec/APA-SPEC.md
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TTL_SECONDS = 3600  # §3 default heartbeat freshness window
ATTESTATION_TTL_SECONDS = 3600
WINDOW_SECONDS = 86_400
SPEC_VERSION = "apa/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/protection/v1"
ATTESTATION_ID = re.compile(r"^[0-9a-f]{32}$")
TIERS = {"guard-live", "audited"}
STATUSES = {"active", "stale", "key-changed", "revoked", "invalid"}
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991


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


def _validate_b64u(value: object, prefix: str, length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        raise ValueError(label)
    try:
        decoded = b64u_decode(value)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(label) from exc
    if len(decoded) != length or b64u_encode(decoded, prefix) != value:
        raise ValueError(label)
    return decoded


def _verify_sig(obj: dict, sig_field: str, pub_b64: str) -> None:
    """Verify Ed25519 `sig_field` over canonical(obj without sig_field). Raises on failure."""
    signature = _validate_b64u(obj.get(sig_field), "sig", 64, sig_field)
    public_key = _validate_b64u(pub_b64, "ed25519", 32, "public key")
    core = {k: v for k, v in obj.items() if k != sig_field}
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical(core))


def _validate_proof(
    proof: dict,
    *,
    expected_host: str,
    expected_pub: str,
    expected_protector: str = "warden",
    now: int | None = None,
) -> int | None:
    """Validate the signed heartbeat and return its rolling count, or None if unavailable."""
    if not isinstance(proof, dict):
        raise ValueError("endpoint heartbeat must be a JSON object")
    if proof.get("pub") != expected_pub:
        raise ValueError("endpoint key changed")
    _verify_sig(proof, "sig", expected_pub)
    if proof.get("spec_version") != SPEC_VERSION:
        raise ValueError("endpoint heartbeat spec_version must be apa/0.1")
    if proof.get("protector") != expected_protector:
        raise ValueError("endpoint heartbeat protector does not match the attestation")
    if proof.get("endpoint_host") != expected_host:
        raise ValueError("endpoint heartbeat host does not match the attestation")
    timestamp = proof.get("ts")
    if type(timestamp) is not int:
        raise ValueError("endpoint heartbeat ts must be an integer")
    current = int(time.time()) if now is None else now
    if type(current) is not int or abs(current - timestamp) > TTL_SECONDS:
        raise ValueError("endpoint heartbeat timestamp is outside TTL")
    window_s = proof.get("window_s")
    if type(window_s) is not int or window_s != WINDOW_SECONDS:
        raise ValueError("endpoint heartbeat window_s must be 86400")
    window_start = proof.get("window_start")
    if type(window_start) is not int or window_start != timestamp - window_s:
        raise ValueError("endpoint heartbeat window_start must equal ts - window_s")
    if "scans_served" not in proof:
        raise ValueError("endpoint heartbeat scans_served is required")
    scans = proof["scans_served"]
    if scans is not None and (type(scans) is not int or scans < 0):
        raise ValueError("endpoint heartbeat scans_served must be null or a non-negative integer")
    nonce = proof.get("nonce")
    if not isinstance(nonce, str) or len(b64u_decode(nonce)) < 16:
        raise ValueError("endpoint heartbeat nonce must contain at least 128 bits")
    return scans


def _validate_attestation(att: dict) -> None:
    """Validate the signed APA v0.1 record shape before interpreting its claims."""
    if not isinstance(att, dict):
        raise ValueError("expected a JSON object")
    if att.get("spec_version") != SPEC_VERSION:
        raise ValueError("spec_version")
    if att.get("predicate_type") != PREDICATE_TYPE:
        raise ValueError("predicate_type")
    attestation_id = att.get("attestation_id")
    if not isinstance(attestation_id, str) or not ATTESTATION_ID.fullmatch(attestation_id):
        raise ValueError("attestation_id")
    for field in ("issuer", "protector", "endpoint_host"):
        if not isinstance(att.get(field), str) or not att[field]:
            raise ValueError(field)
    _validate_b64u(att.get("pub"), "ed25519", 32, "pub")
    _validate_b64u(att.get("issuer_sig"), "sig", 64, "issuer_sig")
    if att.get("tier") not in TIERS:
        raise ValueError("tier")
    if att.get("status") not in STATUSES:
        raise ValueError("status")
    if "scans_24h" not in att:
        raise ValueError("scans_24h")
    scans = att["scans_24h"]
    if scans is not None and (type(scans) is not int or scans < 0):
        raise ValueError("scans_24h")
    verified_at = att.get("verified_at")
    expires_at = att.get("expires_at")
    if (
        type(verified_at) is not int
        or verified_at < 0
        or verified_at > MAX_SAFE_UNIX_SECONDS - ATTESTATION_TTL_SECONDS
    ):
        raise ValueError("verified_at")
    if type(expires_at) is not int or expires_at != verified_at + ATTESTATION_TTL_SECONDS:
        raise ValueError("expires_at")


def _validate_issuer_pub(pub: object) -> str:
    _validate_b64u(pub, "ed25519", 32, "issuer key pub")
    assert isinstance(pub, str)
    return pub


def _issuer_pubs_for(att: dict, issuer_material: str | dict) -> list[str]:
    if isinstance(issuer_material, str):
        return [_validate_issuer_pub(issuer_material)]
    if not isinstance(issuer_material, dict) or set(issuer_material) != {"issuer", "keys"}:
        raise ValueError("issuer document shape")
    if issuer_material.get("issuer") != att.get("issuer"):
        raise ValueError("issuer identity")
    keys = issuer_material.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("issuer keys")
    kids: set[str] = set()
    pubs: set[bytes] = set()
    applicable: list[str] = []
    previous_not_after = MAX_SAFE_UNIX_SECONDS
    for index, key in enumerate(keys):
        if not isinstance(key, dict) or set(key) != {"kid", "pub", "not_after"}:
            raise ValueError("issuer key shape")
        kid = key.get("kid")
        if not isinstance(kid, str) or not kid or kid.strip() != kid:
            raise ValueError("issuer key kid")
        pub = _validate_issuer_pub(key.get("pub"))
        not_after = key.get("not_after")
        if type(not_after) is not int or not_after < 0 or not_after > MAX_SAFE_UNIX_SECONDS:
            raise ValueError("issuer key not_after")
        if index == 0 and not_after != MAX_SAFE_UNIX_SECONDS:
            raise ValueError("current issuer key must publish the safe-integer sentinel")
        if index > 0 and not_after == MAX_SAFE_UNIX_SECONDS:
            raise ValueError("retired issuer key not_after must be finite")
        if not_after > previous_not_after:
            raise ValueError("issuer keys are not newest-first")
        previous_not_after = not_after
        if kid in kids:
            raise ValueError("duplicate issuer kid")
        decoded_pub = b64u_decode(pub)
        if decoded_pub in pubs:
            raise ValueError("duplicate issuer pub")
        kids.add(kid)
        pubs.add(decoded_pub)
        if att["verified_at"] <= not_after:
            applicable.append(pub)
    return applicable


def verify_attestation(
    att: dict, issuer_material: str | dict, *, live: bool = False
) -> tuple[bool, str]:
    """Offline verify per §6. Returns (ok, human message)."""
    try:
        _validate_attestation(att)
    except (ValueError, KeyError) as exc:
        return False, f"signed attestation INVALID ({exc})"

    try:
        issuer_pubs = _issuer_pubs_for(att, issuer_material)
    except (ValueError, KeyError) as exc:
        return False, f"issuer document INVALID ({exc})"

    signature_error: Exception | None = None
    for issuer_pub in issuer_pubs:
        try:
            _verify_sig(att, "issuer_sig", issuer_pub)
            break
        except (InvalidSignature, ValueError, KeyError) as exc:
            signature_error = exc
    else:
        detail = signature_error or "no key applies at verified_at"
        return False, f"issuer signature INVALID ({detail})"

    # 2. expiry
    now = int(time.time())
    expires = att.get("expires_at")
    if isinstance(expires, int) and now > expires:
        return False, "signature valid but EXPIRED → status: stale"

    status = att.get("status")
    if status and status != "active":
        return False, f"signature valid but status is '{status}'"

    scans = att.get("scans_24h")
    scans_label = "count unavailable" if scans is None else f"{scans} scans/24h"

    # 3. optional live re-probe of the endpoint heartbeat
    if live:
        ok, msg = _reprobe(att)
        if not ok:
            return False, f"issuer sig valid, but live re-probe failed: {msg}"
        return True, f"VALID + live guard confirmed ({scans_label})"

    return (
        True,
        f"VALID (endpoint={att.get('endpoint_host')}, {scans_label}, tier={att.get('tier')})",
    )


def _reprobe(att: dict) -> tuple[bool, str]:
    host = att.get("endpoint_host")
    pub = att.get("pub")
    if not host or not pub:
        return False, "attestation missing endpoint_host/pub"
    url = f"https://{host}/.well-known/agent-protection"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310 (https only)
            proof = json.loads(resp.read(64_000))
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot fetch proof: {exc}"
    try:
        _validate_proof(
            proof,
            expected_host=host,
            expected_pub=pub,
            expected_protector=str(att.get("protector")),
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        return False, str(exc) or "endpoint heartbeat invalid"
    return True, "ok"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "issuer discovery redirects are not allowed",
            headers,
            fp,
        )


def _load_issuer_document_from_url(base_url: str, *, opener=None) -> dict:
    if not isinstance(base_url, str) or base_url != base_url.strip():
        raise ValueError("issuer URL must be a clean HTTPS origin")
    try:
        parsed = urllib.parse.urlsplit(base_url)
        parsed.port
    except ValueError as exc:
        raise ValueError("issuer URL must be a clean HTTPS origin") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("issuer URL must be a clean HTTPS origin")
    url = f"https://{parsed.netloc}/.well-known/apa-issuer.json"
    source = opener or urllib.request.build_opener(_NoRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    with source.open(request, timeout=5) as resp:  # noqa: S310
        if resp.geturl() != url:
            raise ValueError("issuer discovery redirects are not allowed")
        data = json.loads(resp.read(64_000))
    if not isinstance(data, dict):
        raise SystemExit(f"malformed issuer document at {url}")
    return data


def _selftest() -> int:
    """Generate a keypair, sign a spec-shaped attestation, verify it, then tamper."""
    priv = Ed25519PrivateKey.generate()
    pub = b64u_encode(priv.public_key().public_bytes_raw(), "ed25519")
    endpoint_pub = b64u_encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    now = int(time.time())
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
        "scans_24h": 41207,
        "verified_at": now,
        "expires_at": now + ATTESTATION_TTL_SECONDS,
    }
    sig = priv.sign(canonical(att))
    att["issuer_sig"] = b64u_encode(sig, "sig")

    ok, msg = verify_attestation(att, pub)
    print(f"[1] genuine attestation -> ok={ok}: {msg}")
    assert ok, "genuine attestation must verify"

    tampered = dict(att)
    tampered["scans_24h"] = 999999  # forge the usage number
    ok2, msg2 = verify_attestation(tampered, pub)
    print(f"[2] tampered scans_24h  -> ok={ok2}: {msg2}")
    assert not ok2, "tampered attestation must fail"

    wrong = b64u_encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519")
    ok3, msg3 = verify_attestation(att, wrong)
    print(f"[3] wrong issuer key    -> ok={ok3}: {msg3}")
    assert not ok3, "wrong issuer key must fail"

    print("\nSELFTEST PASSED — APA v0.1 crypto is implementable and this verifier is correct.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify an APA v0.1 attestation")
    parser.add_argument("attestation", nargs="?")
    issuer = parser.add_mutually_exclusive_group()
    issuer.add_argument("--issuer-pub")
    issuer.add_argument("--issuer-url")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return _selftest()
    if not args.attestation:
        parser.print_help()
        return 2
    att = json.load(open(args.attestation, encoding="utf-8"))
    if args.issuer_pub:
        issuer_material = args.issuer_pub
    elif args.issuer_url:
        issuer_material = _load_issuer_document_from_url(args.issuer_url)
    else:
        parser.error("provide --issuer-pub <ed25519:...> or --issuer-url <base>")
    ok, msg = verify_attestation(att, issuer_material, live=args.live)
    print(("✓ " if ok else "✗ ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
