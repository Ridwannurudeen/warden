"""Promote a human-reviewed mapping from a pinned local dataset checkout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.corpus_ingestion import (  # noqa: E402
    DEFAULT_ALLOWLIST_PATH,
    ingest_reviewed_corpus,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Promote reviewed rows from an exact allowlisted path in a pinned local Git checkout. "
            "This command never downloads source data."
        )
    )
    parser.add_argument("source_id")
    parser.add_argument("checkout", type=Path)
    parser.add_argument("review_mapping", type=Path)
    parser.add_argument("dataset", choices=("attacks", "benign"))
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST_PATH)
    parser.add_argument(
        "--confirm-human-review",
        action="store_true",
        help="Confirm every mapped payload, category, verdict, and redistribution right was reviewed.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not args.confirm_human_review:
        raise SystemExit("refusing corpus ingestion without --confirm-human-review")
    result = ingest_reviewed_corpus(
        source_id=args.source_id,
        checkout=args.checkout,
        review_path=args.review_mapping,
        dataset=args.dataset,
        reviewer_approved=True,
        allowlist_path=args.allowlist,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
