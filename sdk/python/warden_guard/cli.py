"""`warden-guard` CLI — verify APA proofs/attestations, manage the guard key.

warden-guard verify https://api.example.com
warden-guard verify attestation.json --issuer-pub ed25519:...
warden-guard keygen
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

from warden_guard.apa import TTL_SECONDS, verify_document
from warden_guard.keys import key_path, load_or_create_key, public_key_str
from warden_guard.proof import WELL_KNOWN_PATH


def verify_endpoint(url: str) -> tuple[bool, str]:
    """Fetch a live Protection Proof and verify its self-signature + freshness."""
    base = url if "://" in url else "https://" + url
    proof_url = base.rstrip("/") + WELL_KNOWN_PATH
    try:
        with urllib.request.urlopen(proof_url, timeout=5) as resp:  # noqa: S310
            proof = json.loads(resp.read(64_000))
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot fetch proof at {proof_url}: {exc}"
    pub = proof.get("pub")
    if not isinstance(pub, str):
        return False, "proof missing pub"
    try:
        verify_document(proof, pub, sig_field="sig")
    except Exception:  # noqa: BLE001
        return False, "heartbeat signature INVALID"
    if int(time.time()) - int(proof.get("ts", 0)) > TTL_SECONDS:
        return False, "heartbeat signature valid but STALE"
    return True, (
        f"VALID live proof — host={proof.get('endpoint_host')}, "
        f"protector={proof.get('protector')}, scans_served={proof.get('scans_served')}"
    )


def verify_attestation_file(path: str, issuer_pub: str) -> tuple[bool, str]:
    """Offline-verify an APA attestation record per APA-SPEC §6 (steps 1-2)."""
    with open(path, encoding="utf-8") as handle:
        att = json.load(handle)
    try:
        verify_document(att, issuer_pub, sig_field="issuer_sig")
    except Exception as exc:  # noqa: BLE001
        return False, f"issuer signature INVALID ({exc})"
    expires = att.get("expires_at")
    if isinstance(expires, int) and int(time.time()) > expires:
        return False, "signature valid but EXPIRED -> status: stale"
    status = att.get("status")
    if status and status != "active":
        return False, f"signature valid but status is '{status}'"
    return True, (
        f"VALID (endpoint={att.get('endpoint_host')}, "
        f"{att.get('scans_24h')} scans/24h, tier={att.get('tier')})"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden-guard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a live endpoint proof or attestation file")
    verify.add_argument("target", help="endpoint URL or path to an attestation JSON file")
    verify.add_argument("--issuer-pub", help="issuer public key (ed25519:...) for attestations")

    sub.add_parser("keygen", help="generate (or show) the local guard keypair")

    args = parser.parse_args(argv)

    if args.command == "keygen":
        existed = key_path().exists()
        key = load_or_create_key()
        action = "existing" if existed else "generated"
        print(f"{action} guard key at {key_path()}")
        print(f"public key: {public_key_str(key)}")
        return 0

    if "://" in args.target or not args.target.endswith(".json"):
        ok, msg = verify_endpoint(args.target)
    else:
        if not args.issuer_pub:
            parser.error("attestation verify requires --issuer-pub ed25519:...")
        ok, msg = verify_attestation_file(args.target, args.issuer_pub)
    print(("OK  " if ok else "FAIL ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
