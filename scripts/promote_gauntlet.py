"""Second human review of a confirmed Gauntlet bypass for training use."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.gauntlet_store import promote_confirmed_bypass_to_training  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Promote a distinct, consented reproducer from a confirmed WARDEN BREAKER "
            "into first-party training attacks."
        )
    )
    parser.add_argument("claim_id")
    parser.add_argument("certificate_id")
    parser.add_argument(
        "--training-payload-file",
        type=Path,
        required=True,
        help="UTF-8 file containing the separately reviewed training reproducer.",
    )
    parser.add_argument(
        "--confirm-human-training-review",
        action="store_true",
        help="Confirm the second human review, rights evidence, provenance, and category.",
    )
    return parser.parse_args(argv)


def _read_training_payload(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise SystemExit("training payload file must be a regular non-symlink file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit("training payload file could not be read") from exc
    if len(raw) > 16_000:
        raise SystemExit("training payload file is too large")
    try:
        payload = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("training payload file must be valid UTF-8") from exc
    if not payload.strip():
        raise SystemExit("training payload file must not be blank")
    if len(payload) > 4_000:
        raise SystemExit("training payload must not exceed 4000 characters")
    return payload


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.confirm_human_training_review:
        raise SystemExit("refusing promotion without --confirm-human-training-review")
    if not os.getenv("WARDEN_ISSUER_KEY", "").strip():
        raise SystemExit("WARDEN_ISSUER_KEY is required for training promotion")
    if not os.getenv("WARDEN_PROTECTION_DB", "").strip():
        raise SystemExit("WARDEN_PROTECTION_DB is required for training promotion")
    result = promote_confirmed_bypass_to_training(
        args.claim_id,
        certificate_id=args.certificate_id,
        training_payload=_read_training_payload(args.training_payload_file),
        reviewer_approved=True,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
