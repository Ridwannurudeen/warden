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

import base64
import json
import sys
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TTL_SECONDS = 3600  # §3 default heartbeat freshness window


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


def _verify_sig(obj: dict, sig_field: str, pub_b64: str) -> None:
    """Verify Ed25519 `sig_field` over canonical(obj without sig_field). Raises on failure."""
    signature = obj.get(sig_field)
    if not isinstance(signature, str):
        raise InvalidSignature(f"missing {sig_field}")
    core = {k: v for k, v in obj.items() if k != sig_field}
    Ed25519PublicKey.from_public_bytes(b64u_decode(pub_b64)).verify(
        b64u_decode(signature), canonical(core)
    )


def verify_attestation(att: dict, issuer_pub: str, *, live: bool = False) -> tuple[bool, str]:
    """Offline verify per §6. Returns (ok, human message)."""
    # 1. issuer signature
    try:
        _verify_sig(att, "issuer_sig", issuer_pub)
    except (InvalidSignature, ValueError, KeyError) as exc:
        return False, f"issuer signature INVALID ({exc})"

    # 2. expiry
    now = int(time.time())
    expires = att.get("expires_at")
    if isinstance(expires, int) and now > expires:
        return False, "signature valid but EXPIRED → status: stale"

    status = att.get("status")
    if status and status != "active":
        return False, f"signature valid but status is '{status}'"

    # 3. optional live re-probe of the endpoint heartbeat
    if live:
        ok, msg = _reprobe(att)
        if not ok:
            return False, f"issuer sig valid, but live re-probe failed: {msg}"
        return True, f"VALID + live guard confirmed ({att.get('scans_24h')} scans/24h)"

    scans = att.get("scans_24h")
    return (
        True,
        f"VALID (endpoint={att.get('endpoint_host')}, {scans} scans/24h, tier={att.get('tier')})",
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
    if proof.get("pub") != pub:
        return False, "endpoint key changed"
    try:
        _verify_sig(proof, "sig", pub)
    except (InvalidSignature, ValueError, KeyError):
        return False, "endpoint heartbeat signature invalid"
    if int(time.time()) - int(proof.get("ts", 0)) > TTL_SECONDS:
        return False, "endpoint heartbeat stale"
    return True, "ok"


def _load_issuer_pub_from_url(base_url: str) -> str:
    url = base_url.rstrip("/") + "/.well-known/apa-issuer.json"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
        data = json.loads(resp.read(64_000))
    keys = data.get("keys") or []
    if not keys:
        raise SystemExit(f"no issuer keys at {url}")
    return keys[0]["pub"]  # newest-first by convention


def _selftest() -> int:
    """Generate a keypair, sign a spec-shaped attestation, verify it, then tamper."""
    priv = Ed25519PrivateKey.generate()
    pub = b64u_encode(priv.public_key().public_bytes_raw(), "ed25519")
    att = {
        "spec_version": "apa/0.1",
        "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
        "attestation_id": "selftest-0001",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": "api.example.com",
        "pub": "ed25519:ENDPOINTKEY",
        "tier": "guard-live",
        "status": "active",
        "scans_24h": 41207,
        "verified_at": int(time.time()),
        "expires_at": int(time.time()) + 3600,
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
    if "--selftest" in argv:
        return _selftest()
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    att = json.load(open(args[0], encoding="utf-8"))
    live = "--live" in argv
    if "--issuer-pub" in argv:
        issuer_pub = argv[argv.index("--issuer-pub") + 1]
    elif "--issuer-url" in argv:
        issuer_pub = _load_issuer_pub_from_url(argv[argv.index("--issuer-url") + 1])
    else:
        raise SystemExit("provide --issuer-pub <ed25519:...> or --issuer-url <base>")
    ok, msg = verify_attestation(att, issuer_pub, live=live)
    print(("✓ " if ok else "✗ ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
