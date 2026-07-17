"""Human-only Gauntlet bypass promotion into the held-out benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.core.verdict import ReasonCode  # noqa: E402
from warden.gauntlet_store import confirm_bypass  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Promote one human-reviewed pending Gauntlet claim to held-out evaluation."
    )
    parser.add_argument("claim_id")
    parser.add_argument("category", choices=[reason.value for reason in ReasonCode])
    parser.add_argument(
        "--confirm-human-review",
        action="store_true",
        help="Confirm that a human reviewed the payload and assigned the category.",
    )
    parser.add_argument(
        "--redacted-payload-file",
        type=Path,
        required=True,
        help="UTF-8 file containing the exact publishable reproducer to rescan.",
    )
    credit = parser.add_mutually_exclusive_group(required=True)
    credit.add_argument(
        "--credit-handle",
        help="Reviewer-approved public finder handle to sign into the certificate.",
    )
    credit.add_argument(
        "--anonymous",
        action="store_true",
        help="Issue the certificate without public finder credit.",
    )
    return parser.parse_args(argv)


def _read_reviewed_payload(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise SystemExit("redacted payload file must be a regular non-symlink file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit("redacted payload file could not be read") from exc
    if len(raw) > 16_000:
        raise SystemExit("redacted payload file is too large")
    try:
        payload = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("redacted payload file must be valid UTF-8") from exc
    if not payload.strip():
        raise SystemExit("redacted payload file must not be blank")
    if len(payload) > 4_000:
        raise SystemExit("redacted payload must not exceed 4000 characters")
    return payload


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.confirm_human_review:
        raise SystemExit("refusing promotion without --confirm-human-review")
    if not os.getenv("WARDEN_ISSUER_KEY", "").strip():
        raise SystemExit("WARDEN_ISSUER_KEY is required for human confirmation")
    if not os.getenv("WARDEN_PROTECTION_DB", "").strip():
        raise SystemExit("WARDEN_PROTECTION_DB is required for human confirmation")
    result = confirm_bypass(
        args.claim_id,
        ReasonCode(args.category),
        reviewed_payload=_read_reviewed_payload(args.redacted_payload_file),
        finder=None if args.anonymous else args.credit_handle,
        reviewer_approved=True,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
