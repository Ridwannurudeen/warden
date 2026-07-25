"""Build the static Warden marketplace security index."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.engine import WardenEngine  # noqa: E402
from warden.badge_store import list_badges  # noqa: E402
from warden.badges import b64u_decode, b64u_encode  # noqa: E402
from warden.marketplace.catalog import (  # noqa: E402
    build_hire_catalog,
    build_hire_catalog_from_agent,
)
from warden.marketplace.fetch import (  # noqa: E402
    MarketplaceAgent,
    fetch_provider_agent,
    load_snapshot,
)
from warden.marketplace.index import index_agent, index_agents  # noqa: E402
from warden.marketplace.render import (  # noqa: E402
    ApaIssuerKey,
    associate_attestations,
    associate_badges,
    render_marketplace,
    render_provider_page,
)
from warden.sitemap import write_crawler_files  # noqa: E402

DEFAULT_SNAPSHOT = ROOT / "data" / "marketplace" / "agents-v1.jsonl"
DEFAULT_OUTPUT = ROOT / "site" / "agents"
DEFAULT_HIRE_CATALOG = ROOT / "site" / "data" / "warden-services.json"
DEFAULT_MARKETPLACE_SUMMARY = ROOT / "site" / "data" / "marketplace-summary.json"
DEFAULT_BADGE_STORE = ROOT / "badges" / "issued.jsonl"
DEFAULT_BADGE_LINKS = ROOT / "data" / "marketplace" / "badge-links-v1.json"
DEFAULT_APA_DB = Path(os.getenv("WARDEN_PROTECTION_DB", ROOT / "data" / "protection.db"))
_issuer_history_value = os.getenv("WARDEN_ISSUER_HISTORY", "").strip()
DEFAULT_APA_ISSUER_HISTORY = Path(_issuer_history_value) if _issuer_history_value else None
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991


@dataclass(frozen=True)
class EvidenceLinks:
    audit_by_id: dict[str, str]
    attestation_by_id: dict[str, str]


def _crawler_site_root(args: argparse.Namespace) -> Path | None:
    configured = getattr(args, "site_root", None)
    if configured is not None:
        expected_output = (configured / "agents").resolve()
        if args.output.resolve() != expected_output:
            raise RuntimeError("--site-root must own the marketplace output directory")
        return configured
    if args.output == DEFAULT_OUTPUT:
        return ROOT / "site"
    return None


def _write_json_atomic(path: Path, document: dict[str, object]) -> None:
    serialized = json.dumps(document, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(serialized)
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def load_evidence_links(path: Path) -> EvidenceLinks:
    if not path.exists():
        return EvidenceLinks(audit_by_id={}, attestation_by_id={})
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("badge link manifest is not valid JSON") from exc
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        raise RuntimeError("evidence link manifest schemaVersion must be 2")
    links = document.get("links")
    if not isinstance(links, list):
        raise RuntimeError("evidence link manifest links must be a list")

    audits: dict[str, str] = {}
    attestations: dict[str, str] = {}
    for link in links:
        if not isinstance(link, dict):
            raise RuntimeError("evidence link entries must be objects")
        agent_id = link.get("agentId")
        if not isinstance(agent_id, str) or not agent_id.isdecimal():
            raise RuntimeError("evidence links require a decimal agentId")

        keys = set(link)
        if keys == {"auditId", "agentId"}:
            evidence_id = link["auditId"]
            expected_length = 16
            mapped = audits
            label = "auditId"
        elif keys == {"attestationId", "agentId"}:
            evidence_id = link["attestationId"]
            expected_length = 32
            mapped = attestations
            label = "attestationId"
        else:
            raise RuntimeError(
                "evidence links require exactly one of auditId or attestationId with agentId"
            )
        if (
            not isinstance(evidence_id, str)
            or len(evidence_id) != expected_length
            or any(character not in "0123456789abcdef" for character in evidence_id)
        ):
            raise RuntimeError(f"evidence link {label} must be lowercase {expected_length}-hex")
        existing = mapped.get(evidence_id)
        if existing is not None and existing != agent_id:
            raise RuntimeError(f"evidence {evidence_id} is linked to multiple agents")
        mapped[evidence_id] = agent_id
    return EvidenceLinks(audit_by_id=audits, attestation_by_id=attestations)


def load_apa_attestations(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise RuntimeError(f"APA attestation database is missing: {path}")
    try:
        with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
            rows = connection.execute(
                "SELECT record_json FROM attestations ORDER BY created_at, attestation_id"
            ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError("APA attestation database could not be read") from exc

    records: list[dict[str, object]] = []
    for (record_json,) in rows:
        try:
            record = json.loads(record_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("APA attestation database contains invalid record JSON") from exc
        if not isinstance(record, dict):
            raise RuntimeError("APA attestation database records must be JSON objects")
        records.append(record)
    return records


def load_apa_issuer_history(
    path: Path | None,
    current_pub: str,
) -> tuple[ApaIssuerKey, ...]:
    if path is None:
        return ()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("APA issuer history must be readable valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {"keys"}:
        raise RuntimeError("APA issuer history must contain only a keys array")
    keys = document.get("keys")
    if not isinstance(keys, list):
        raise RuntimeError("APA issuer history keys must be an array")

    history: list[ApaIssuerKey] = []
    kids: set[str] = set()
    pubs = {current_pub}
    for value in keys:
        if not isinstance(value, dict) or set(value) != {"kid", "pub", "not_after"}:
            raise RuntimeError("APA issuer history contains a malformed key")
        kid = value["kid"]
        pub = value["pub"]
        not_after = value["not_after"]
        if not isinstance(kid, str) or not kid or kid.strip() != kid:
            raise RuntimeError("APA issuer history kid must be a non-empty trimmed string")
        try:
            decoded = b64u_decode(pub) if isinstance(pub, str) else b""
        except ValueError as exc:
            raise RuntimeError("APA issuer history pub must be an ed25519: 32-byte key") from exc
        if (
            not isinstance(pub, str)
            or not pub.startswith("ed25519:")
            or len(decoded) != 32
            or b64u_encode(decoded, "ed25519") != pub
        ):
            raise RuntimeError("APA issuer history pub must be an ed25519: 32-byte key")
        if type(not_after) is not int or not 0 <= not_after <= MAX_SAFE_UNIX_SECONDS:
            raise RuntimeError("APA issuer history not_after must be safe Unix seconds")
        if not_after == MAX_SAFE_UNIX_SECONDS:
            raise RuntimeError("APA issuer history keys require a finite retirement cutoff")
        if kid in kids:
            raise RuntimeError("APA issuer history contains a duplicate kid")
        if pub in pubs:
            raise RuntimeError("APA issuer history contains a duplicate pub")
        kids.add(kid)
        pubs.add(pub)
        history.append(ApaIssuerKey(kid=kid, pub=pub, not_after=not_after))
    return tuple(sorted(history, key=lambda key: (-key.not_after, key.kid)))


def _fetch_provider(args: argparse.Namespace) -> tuple[MarketplaceAgent | None, str]:
    """Read our own listing, which both the catalogue and our own page are built from.

    The census is a record of the *public* marketplace, so it drops us entirely while
    the listing is under review, and it lags the listing the rest of the time. The
    provider fetch answers in both states. It needs the CLI, so it is optional and the
    census remains the fallback for offline and CI builds.
    """
    fetched_at = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    if args.no_provider_fetch:
        return None, fetched_at
    try:
        return fetch_provider_agent(args.provider_agent_id), fetched_at
    except RuntimeError as exc:
        print(f"provider fetch failed, falling back to the snapshot: {exc}", file=sys.stderr)
        return None, fetched_at


def _hire_catalog(
    snapshot,
    args: argparse.Namespace,
    provider: MarketplaceAgent | None,
    fetched_at: str,
) -> dict[str, object]:
    if provider is None:
        return build_hire_catalog(snapshot)
    return build_hire_catalog_from_agent(
        provider,
        fetched_at,
        provider_agent_id=args.provider_agent_id,
    )


async def _render_own_page(
    args: argparse.Namespace,
    provider: MarketplaceAgent,
    fetched_at: str,
    snapshot,
    evidence_links: EvidenceLinks,
    issuer_history: tuple[ApaIssuerKey, ...],
) -> None:
    """Render our own page from our own listing, after the census sweep has run.

    The census deletes any page it does not contain, so while the listing is under review
    ours would otherwise 404 even though the deploy gate requires it.
    """
    indexed = await index_agent(provider, WardenEngine())
    badges = associate_badges(
        [indexed],
        list_badges(args.badge_store),
        evidence_links.audit_by_id,
    ).get(provider.agent_id, [])
    attestations: list[dict[str, object]] = []
    if evidence_links.attestation_by_id:
        attestations = associate_attestations(
            [indexed],
            load_apa_attestations(args.apa_db),
            evidence_links.attestation_by_id,
            args.apa_issuer_pub,
            issuer_history,
        ).get(provider.agent_id, [])
    render_provider_page(
        indexed,
        args.output,
        fetched_at=fetched_at,
        in_census=any(agent.agent_id == provider.agent_id for agent in snapshot.agents),
        badge_records=badges,
        attestation_records=attestations,
        apa_issuer_pub=args.apa_issuer_pub,
        apa_issuer_history=issuer_history,
    )


async def build(args: argparse.Namespace) -> None:
    snapshot = load_snapshot(args.snapshot)
    provider, provider_fetched_at = _fetch_provider(args)
    _write_json_atomic(
        args.hire_catalog,
        _hire_catalog(snapshot, args, provider, provider_fetched_at),
    )
    indexed = await index_agents(snapshot.agents, WardenEngine())
    evidence_links = load_evidence_links(args.badge_links)
    badges_by_agent = associate_badges(
        indexed,
        list_badges(args.badge_store),
        evidence_links.audit_by_id,
    )
    attestations_by_agent: dict[str, list[dict[str, object]]] = {}
    issuer_history: tuple[ApaIssuerKey, ...] = ()
    if evidence_links.attestation_by_id:
        if not args.apa_issuer_pub:
            raise RuntimeError(
                "WARDEN_ISSUER_PUBLIC_KEY is required when APA evidence links are configured"
            )
        issuer_history = load_apa_issuer_history(
            args.apa_issuer_history,
            args.apa_issuer_pub,
        )
        attestations_by_agent = associate_attestations(
            indexed,
            load_apa_attestations(args.apa_db),
            evidence_links.attestation_by_id,
            args.apa_issuer_pub,
            issuer_history,
        )
    summary = render_marketplace(
        indexed,
        args.output,
        coverage=snapshot.metadata,
        badge_records=badges_by_agent,
        attestation_records=attestations_by_agent,
        apa_issuer_pub=args.apa_issuer_pub,
        apa_issuer_history=issuer_history,
    )
    _write_json_atomic(
        args.marketplace_summary,
        {
            "schemaVersion": 2,
            "capturedAt": snapshot.metadata.captured_at,
            "query": snapshot.metadata.query,
            "sampled": summary.sampled,
            "expected": summary.expected,
            "dropped": summary.dropped,
            "matchedCount": summary.matched_count,
            "auditedCount": summary.audited_count,
        },
    )
    if provider is not None:
        await _render_own_page(
            args,
            provider,
            provider_fetched_at,
            snapshot,
            evidence_links,
            issuer_history,
        )
    site_root = _crawler_site_root(args)
    if site_root is not None:
        write_crawler_files(site_root)
    print(
        f"Indexed {summary.sampled} agents; "
        f"{summary.matched_count} public-text matches; "
        f"{summary.audited_count} independently audited."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Warden's marketplace security index.")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--hire-catalog", type=Path, default=DEFAULT_HIRE_CATALOG)
    parser.add_argument("--provider-agent-id", default="3808")
    parser.add_argument(
        "--no-provider-fetch",
        action="store_true",
        help="build the hire catalog from the snapshot only, without calling the CLI",
    )
    parser.add_argument("--badge-store", type=Path, default=DEFAULT_BADGE_STORE)
    parser.add_argument("--badge-links", type=Path, default=DEFAULT_BADGE_LINKS)
    parser.add_argument("--apa-db", type=Path, default=DEFAULT_APA_DB)
    parser.add_argument("--apa-issuer-pub", default=os.getenv("WARDEN_ISSUER_PUBLIC_KEY"))
    parser.add_argument(
        "--apa-issuer-history",
        type=Path,
        default=DEFAULT_APA_ISSUER_HISTORY,
    )
    parser.add_argument(
        "--marketplace-summary",
        type=Path,
        default=DEFAULT_MARKETPLACE_SUMMARY,
    )
    parser.add_argument(
        "--site-root",
        type=Path,
        help="Complete public site root whose crawler files should be regenerated.",
    )
    return parser.parse_args()


def main() -> None:
    asyncio.run(build(parse_args()))


if __name__ == "__main__":
    main()
