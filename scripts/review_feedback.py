"""Human-only promotion of consented redacted feedback."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden import feedback_store  # noqa: E402
from warden.core.verdict import ReasonCode  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Promote one explicitly consented, human-reviewed redacted reproducer "
            "to exactly one training or held-out dataset."
        )
    )
    parser.add_argument("feedback_id")
    parser.add_argument("destination", choices=("training", "held-out"))
    parser.add_argument("category", choices=[reason.value for reason in ReasonCode])
    parser.add_argument(
        "--expected-verdict",
        choices=("SANITIZE", "BLOCK"),
        help="Required only when promoting attack feedback into training.",
    )
    parser.add_argument(
        "--confirm-human-review",
        action="store_true",
        help="Confirm the stored reproducer is redacted, authorized, and correctly categorized.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.confirm_human_review:
        raise SystemExit("refusing promotion without --confirm-human-review")
    result = feedback_store.promote_feedback(
        args.feedback_id,
        destination=args.destination,
        category=ReasonCode(args.category),
        expected_verdict=args.expected_verdict,
        reviewer_approved=True,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
