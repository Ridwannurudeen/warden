"""Append a checkpointed revocation for one endpoint-audit attestation."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden import audit_attestations, protection_store  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-id", required=True)
    parser.add_argument("--revoked-at", type=int)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{16}", args.audit_id):
        parser.error("--audit-id must contain 16 lowercase hexadecimal characters")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    revoked_at = int(time.time()) if args.revoked_at is None else args.revoked_at
    try:
        recorded_at = protection_store.revoke_audit_attestation(
            args.audit_id,
            revoked_at=revoked_at,
            record_validator=audit_attestations.verify_audit_attestation,
        )
    except (
        protection_store.ProtectionStateConflict,
        ValueError,
    ) as exc:
        raise SystemExit(f"audit attestation revocation refused: {exc}") from exc
    print(
        json.dumps(
            {
                "audit_id": args.audit_id,
                "status": "revoked",
                "revoked_at": recorded_at,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
