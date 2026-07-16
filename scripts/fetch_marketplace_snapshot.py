"""Fetch one public marketplace snapshot without loading Warden secrets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.marketplace.fetch import MarketplaceSnapshot, fetch_snapshot  # noqa: E402

DEFAULT_SNAPSHOT = Path("/opt/warden-snapshot/agents-v1.jsonl")


def format_summary_log(snapshot: MarketplaceSnapshot) -> str:
    metadata = snapshot.metadata
    return (
        f"capturedAt={metadata.captured_at} "
        f"query={metadata.query!r} "
        f"sampled={metadata.sampled} "
        f"expected={metadata.expected} "
        f"dropped={metadata.dropped}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch a public OKX.AI marketplace snapshot.")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--query", default="a")
    parser.add_argument("--page-size", type=int, default=100)
    args = parser.parse_args(argv)
    if not args.query or args.query != args.query.strip():
        parser.error("--query must be a non-empty trimmed string")
    if not 1 <= args.page_size <= 100:
        parser.error("--page-size must be between 1 and 100")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    snapshot = fetch_snapshot(
        args.snapshot,
        query=args.query,
        page_size=args.page_size,
    )
    print(format_summary_log(snapshot))


if __name__ == "__main__":
    main()
