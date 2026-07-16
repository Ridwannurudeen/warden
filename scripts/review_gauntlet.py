"""Human-only Gauntlet bypass promotion into the held-out benchmark."""

from __future__ import annotations

import argparse
import json
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.confirm_human_review:
        raise SystemExit("refusing promotion without --confirm-human-review")
    case = confirm_bypass(args.claim_id, ReasonCode(args.category))
    print(json.dumps(case, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
