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
from urllib.parse import urlsplit

from warden_guard.aio import AsyncWardenClient
from warden_guard.apa import validate_attestation, validate_protection_proof
from warden_guard.keys import key_path, load_or_create_key, public_key_str
from warden_guard.proof import WELL_KNOWN_PATH
from warden_guard.proxy import WardenReverseProxy


def verify_endpoint(url: str) -> tuple[bool, str]:
    """Fetch a live Protection Proof and verify its self-signature + freshness."""
    base = url if "://" in url else "https://" + url
    parsed = urlsplit(base)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False, "APA endpoints must use a valid HTTPS origin"
    try:
        port = parsed.port
    except ValueError:
        return False, "APA endpoints must use a valid HTTPS origin"
    host = parsed.hostname.lower()
    host_identity = f"[{host}]" if ":" in host else host
    endpoint_host = host_identity if port in (None, 443) else f"{host_identity}:{port}"
    proof_url = f"https://{endpoint_host}{WELL_KNOWN_PATH}"
    try:
        with urllib.request.urlopen(proof_url, timeout=5) as resp:  # noqa: S310
            proof = json.loads(resp.read(64_000))
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot fetch proof at {proof_url}: {exc}"
    try:
        validate_protection_proof(proof, expected_host=endpoint_host)
    except Exception as exc:  # noqa: BLE001
        return False, f"heartbeat INVALID ({exc})"
    scans = proof.get("scans_served")
    scans_label = "unavailable" if scans is None else str(scans)
    return True, (
        f"VALID live proof — host={proof.get('endpoint_host')}, "
        f"protector={proof.get('protector')}, scans_served={scans_label}"
    )


def verify_attestation_file(path: str, issuer_pub: str) -> tuple[bool, str]:
    """Offline-verify an APA attestation record per APA-SPEC §6 (steps 1-2)."""
    with open(path, encoding="utf-8") as handle:
        att = json.load(handle)
    try:
        validate_attestation(att, issuer_pub)
    except Exception as exc:  # noqa: BLE001
        return False, f"attestation INVALID ({exc})"
    expires = att.get("expires_at")
    if isinstance(expires, int) and int(time.time()) > expires:
        return False, "signature valid but EXPIRED -> status: stale"
    status = att.get("status")
    if status and status != "active":
        return False, f"signature valid but status is '{status}'"
    scans = att.get("scans_24h")
    scans_label = "count unavailable" if scans is None else f"{scans} scans/24h"
    return True, (
        f"VALID (endpoint={att.get('endpoint_host')}, {scans_label}, tier={att.get('tier')})"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden-guard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a live endpoint proof or attestation file")
    verify.add_argument("target", help="endpoint URL or path to an attestation JSON file")
    verify.add_argument("--issuer-pub", help="issuer public key (ed25519:...) for attestations")

    sub.add_parser("keygen", help="generate (or show) the local guard keypair")

    proxy = sub.add_parser("proxy", help="run a fail-closed guarded reverse proxy")
    proxy.add_argument("--upstream", required=True, help="HTTP(S) origin to protect")
    proxy.add_argument(
        "--warden-url",
        help="explicit hosted scanner origin; omit for enforcement-grade local scanning",
    )
    proxy.add_argument("--listen", default="127.0.0.1", help="listen address")
    proxy.add_argument("--port", type=int, default=8787, help="listen port")
    proxy.add_argument("--max-body-bytes", type=int, default=1_000_000)

    args = parser.parse_args(argv)

    if args.command == "proxy":
        if not 1 <= args.port <= 65_535:
            parser.error("proxy port must be between 1 and 65535")
        try:
            import uvicorn
        except ImportError:
            parser.error("proxy command requires the 'proxy' package extra")
        client = AsyncWardenClient(
            base_url=args.warden_url or "https://warden.gudman.xyz",
            local=args.warden_url is None,
            fail_open=False,
        )
        proxy_app = WardenReverseProxy(
            args.upstream,
            client=client,
            max_body_bytes=args.max_body_bytes,
        )
        uvicorn.run(proxy_app, host=args.listen, port=args.port)
        return 0

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
