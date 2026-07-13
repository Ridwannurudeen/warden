"""Build the static Warden marketplace security index."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.engine import WardenEngine  # noqa: E402
from warden.marketplace.catalog import build_hire_catalog  # noqa: E402
from warden.marketplace.fetch import fetch_snapshot, load_snapshot  # noqa: E402
from warden.marketplace.index import index_agents  # noqa: E402
from warden.marketplace.render import render_marketplace  # noqa: E402

DEFAULT_SNAPSHOT = ROOT / "data" / "marketplace" / "agents-v1.jsonl"
DEFAULT_OUTPUT = ROOT / "site" / "agents"
DEFAULT_HIRE_CATALOG = ROOT / "site" / "data" / "warden-services.json"


async def build(args: argparse.Namespace) -> None:
    if args.refresh:
        fetch_snapshot(
            args.snapshot,
            query=args.query,
            page_size=args.page_size,
        )
    snapshot = load_snapshot(args.snapshot)
    args.hire_catalog.parent.mkdir(parents=True, exist_ok=True)
    args.hire_catalog.write_text(
        json.dumps(build_hire_catalog(snapshot), indent=2) + "\n",
        encoding="utf-8",
    )
    indexed = await index_agents(snapshot.agents, WardenEngine())
    summary = render_marketplace(
        indexed,
        args.output,
        fetched_at=snapshot.metadata.fetched_at,
    )
    print(
        f"Indexed {summary.agent_count} agents; "
        f"{summary.matched_count} public-text matches; "
        f"{summary.audited_count} independently audited."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Warden's marketplace security index.")
    parser.add_argument("--refresh", action="store_true", help="Refresh the public CLI snapshot.")
    parser.add_argument("--query", default="a")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--hire-catalog", type=Path, default=DEFAULT_HIRE_CATALOG)
    return parser.parse_args()


def main() -> None:
    asyncio.run(build(parse_args()))


if __name__ == "__main__":
    main()
