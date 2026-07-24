"""Append a checkpointed revocation for one signed Hardening Pack."""

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

from warden import hardening, protection_store  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-id", required=True)
    parser.add_argument("--revoked-at", type=int)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{64}", args.pack_id):
        parser.error("--pack-id must contain 64 lowercase hexadecimal characters")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    revoked_at = int(time.time()) if args.revoked_at is None else args.revoked_at
    try:
        recorded_at = protection_store.revoke_hardening_pack(
            args.pack_id,
            revoked_at=revoked_at,
            record_validator=hardening.verify_pack,
        )
    except (
        protection_store.ProtectionStateConflict,
        ValueError,
    ) as exc:
        raise SystemExit(f"hardening pack revocation refused: {exc}") from exc
    print(
        json.dumps(
            {
                "pack_id": args.pack_id,
                "status": "revoked",
                "revoked_at": recorded_at,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
