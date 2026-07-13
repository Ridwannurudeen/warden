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
from warden.badge_store import list_badges  # noqa: E402
from warden.marketplace.catalog import build_hire_catalog  # noqa: E402
from warden.marketplace.fetch import fetch_snapshot, load_snapshot  # noqa: E402
from warden.marketplace.index import index_agents  # noqa: E402
from warden.marketplace.render import associate_badges, render_marketplace  # noqa: E402

DEFAULT_SNAPSHOT = ROOT / "data" / "marketplace" / "agents-v1.jsonl"
DEFAULT_OUTPUT = ROOT / "site" / "agents"
DEFAULT_HIRE_CATALOG = ROOT / "site" / "data" / "warden-services.json"
DEFAULT_MARKETPLACE_SUMMARY = ROOT / "site" / "data" / "marketplace-summary.json"
DEFAULT_BADGE_STORE = ROOT / "badges" / "issued.jsonl"
DEFAULT_BADGE_LINKS = ROOT / "data" / "marketplace" / "badge-links-v1.json"


def load_badge_links(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("badge link manifest is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("schemaVersion") != 1:
        raise RuntimeError("badge link manifest schemaVersion must be 1")
    links = document.get("links")
    if not isinstance(links, list):
        raise RuntimeError("badge link manifest links must be a list")

    mapped: dict[str, str] = {}
    for link in links:
        if not isinstance(link, dict):
            raise RuntimeError("badge link entries must be objects")
        audit_id = link.get("auditId")
        agent_id = link.get("agentId")
        if (
            not isinstance(audit_id, str)
            or len(audit_id) != 16
            or any(character not in "0123456789abcdef" for character in audit_id)
            or not isinstance(agent_id, str)
            or not agent_id.isdecimal()
        ):
            raise RuntimeError("badge links require a lowercase 16-hex auditId and decimal agentId")
        existing = mapped.get(audit_id)
        if existing is not None and existing != agent_id:
            raise RuntimeError(f"badge {audit_id} is linked to multiple agents")
        mapped[audit_id] = agent_id
    return mapped


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
    badges_by_agent = associate_badges(
        indexed,
        list_badges(args.badge_store),
        load_badge_links(args.badge_links),
    )
    summary = render_marketplace(
        indexed,
        args.output,
        fetched_at=snapshot.metadata.fetched_at,
        badge_records=badges_by_agent,
    )
    args.marketplace_summary.parent.mkdir(parents=True, exist_ok=True)
    args.marketplace_summary.write_text(
        json.dumps(
            {
                "agentCount": summary.agent_count,
                "auditedCount": summary.audited_count,
                "fetchedAt": snapshot.metadata.fetched_at,
                "matchedCount": summary.matched_count,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
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
    parser.add_argument("--badge-store", type=Path, default=DEFAULT_BADGE_STORE)
    parser.add_argument("--badge-links", type=Path, default=DEFAULT_BADGE_LINKS)
    parser.add_argument(
        "--marketplace-summary",
        type=Path,
        default=DEFAULT_MARKETPLACE_SUMMARY,
    )
    return parser.parse_args()


def main() -> None:
    asyncio.run(build(parse_args()))


if __name__ == "__main__":
    main()
