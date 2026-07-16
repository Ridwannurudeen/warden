"""Render static marketplace security index pages."""

from __future__ import annotations

import html
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from warden.badges import b64u_decode, b64u_encode, ed25519_verify_record, verify_badge
from warden.marketplace.fetch import SnapshotMetadata
from warden.marketplace.index import IndexedAgent
from warden.site_render import page_shell

APA_ISSUER = "warden"
APA_PROTECTOR = "warden"
APA_ATTESTATION_TTL_SECONDS = 3_600
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991


@dataclass(frozen=True)
class RenderSummary:
    sampled: int
    expected: int
    dropped: int
    matched_count: int
    audited_count: int


@dataclass(frozen=True)
class ApaIssuerKey:
    kid: str
    pub: str
    not_after: int


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _safe_external_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return value


def _initials(name: str) -> str:
    words = name.split()
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return f"{words[0][0]}{words[1][0]}".upper()


def _number(value: int | None) -> str:
    return "Not reported" if value is None else f"{value:,}"


def _raw_stat(value: float | None) -> str:
    if value is None:
        return "Not reported"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _buyer_review(value: float | None) -> str:
    if value is None:
        return "No buyer reviews"
    formatted = f"{value:.2f}".rstrip("0").rstrip(".")
    return f"{formatted} / 5"


def _coverage_text(coverage: SnapshotMetadata) -> str:
    agent_label = "agent" if coverage.sampled == 1 else "agents"
    if coverage.sampled == coverage.expected and coverage.dropped == 0:
        return (
            f'Complete discovery response for marketplace query "{coverage.query}". '
            f"{coverage.sampled} unique {agent_label} sampled; "
            f"the highest reported result total for that query was {coverage.expected}. "
            f"Captured {coverage.captured_at}."
        )
    if coverage.sampled > coverage.expected:
        return (
            f'Partial/degraded discovery response for marketplace query "{coverage.query}". '
            f"{coverage.sampled} unique {agent_label} sampled; the sample exceeded the highest "
            f"reported result total of {coverage.expected}, so upstream counts disagree. "
            f"Captured {coverage.captured_at}."
        )
    missing_label = "agent was" if coverage.dropped == 1 else "agents were"
    return (
        f'Partial/degraded discovery response for marketplace query "{coverage.query}". '
        f"{coverage.sampled} unique {agent_label} sampled; "
        f"the highest reported result total for that query was {coverage.expected}; "
        f"{coverage.dropped} expected {missing_label} not present in this response. "
        f"Captured {coverage.captured_at}."
    )


def _public_text_status(indexed: IndexedAgent) -> tuple[str, str]:
    if indexed.fields_scanned == 0 or indexed.verdict is None:
        return "unscanned", "Not scanned — no public text"
    if indexed.threat_classes:
        return "signal", "Public-text pattern match"
    return "none", "No public-text pattern match"


def _verified_badge(records: list[dict[str, object]]) -> dict[str, object] | None:
    valid = [record for record in records if verify_badge(record)]
    if not valid:
        return None
    return max(valid, key=lambda record: str(record.get("issued_at", "")))


def _listed_service_hosts(
    indexed_agents: list[IndexedAgent], *, include_non_default_port: bool
) -> dict[str, set[str]]:
    service_hosts_by_agent: dict[str, set[str]] = {}
    for indexed in indexed_agents:
        for service in indexed.agent.services:
            endpoint = urlparse(service.endpoint)
            if (
                endpoint.scheme not in {"http", "https"}
                or not endpoint.hostname
                or endpoint.username
                or endpoint.password
            ):
                continue
            try:
                port = endpoint.port
            except ValueError:
                continue
            host = endpoint.hostname.rstrip(".").casefold()
            default_port = 443 if endpoint.scheme == "https" else 80
            if include_non_default_port and port not in (None, default_port):
                host = f"{host}:{port}"
            service_hosts_by_agent.setdefault(indexed.agent.agent_id, set()).add(host)
    return service_hosts_by_agent


def _normalize_apa_endpoint_host(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character.isspace() or character in "/?#@" for character in value)
    ):
        return None
    parsed = urlparse(f"//{value}")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        port = parsed.port
    except ValueError:
        return value.casefold()
    host = parsed.hostname.rstrip(".").casefold()
    return host if port is None else f"{host}:{port}"


def _require_apa_issuer_pub(issuer_pub: str) -> None:
    try:
        decoded = b64u_decode(issuer_pub)
        valid = (
            issuer_pub.startswith("ed25519:")
            and len(decoded) == 32
            and b64u_encode(decoded, "ed25519") == issuer_pub
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("APA issuer public key must be a canonical ed25519: 32-byte key")


def _valid_apa_attestation(
    record: dict[str, object],
    issuer_pub: str,
    issuer_history: Sequence[ApaIssuerKey] = (),
) -> bool:
    attestation_id = record.get("attestation_id")
    if (
        record.get("spec_version") != "apa/0.1"
        or record.get("predicate_type") != "https://warden.gudman.xyz/spec/protection/v1"
        or record.get("issuer") != APA_ISSUER
        or record.get("protector") != APA_PROTECTOR
        or not isinstance(attestation_id, str)
        or len(attestation_id) != 32
        or any(character not in "0123456789abcdef" for character in attestation_id)
        or record.get("tier") != "guard-live"
        or record.get("status") not in {"active", "stale", "key-changed", "revoked", "invalid"}
    ):
        return False
    if not isinstance(record.get("endpoint_host"), str) or not record["endpoint_host"]:
        return False
    endpoint_pub = record.get("pub")
    try:
        if (
            not isinstance(endpoint_pub, str)
            or not endpoint_pub.startswith("ed25519:")
            or len(b64u_decode(endpoint_pub)) != 32
        ):
            return False
    except (TypeError, ValueError):
        return False
    issuer_sig = record.get("issuer_sig")
    try:
        if (
            not isinstance(issuer_sig, str)
            or not issuer_sig.startswith("sig:")
            or len(b64u_decode(issuer_sig)) != 64
        ):
            return False
    except (TypeError, ValueError):
        return False
    if "scans_24h" not in record:
        return False
    scans = record["scans_24h"]
    if scans is not None and (type(scans) is not int or scans < 0):
        return False
    verified_at = record.get("verified_at")
    expires_at = record.get("expires_at")
    if (
        type(verified_at) is not int
        or verified_at < 0
        or verified_at > MAX_SAFE_UNIX_SECONDS - APA_ATTESTATION_TTL_SECONDS
        or type(expires_at) is not int
        or expires_at != verified_at + APA_ATTESTATION_TTL_SECONDS
    ):
        return False
    if ed25519_verify_record(record, issuer_pub, "issuer_sig"):
        return True
    return any(
        verified_at <= key.not_after and ed25519_verify_record(record, key.pub, "issuer_sig")
        for key in issuer_history
    )


def _verified_attestation(
    records: list[dict[str, object]],
    issuer_pub: str,
    issuer_history: Sequence[ApaIssuerKey] = (),
) -> dict[str, object] | None:
    valid = [
        record for record in records if _valid_apa_attestation(record, issuer_pub, issuer_history)
    ]
    if not valid:
        return None
    return max(
        valid,
        key=lambda record: (int(record["verified_at"]), str(record["attestation_id"])),
    )


def associate_badges(
    indexed_agents: list[IndexedAgent],
    badge_records: list[dict[str, object]],
    badge_links: dict[str, str],
) -> dict[str, list[dict[str, object]]]:
    service_hosts_by_agent = _listed_service_hosts(indexed_agents, include_non_default_port=False)

    associated: dict[str, list[dict[str, object]]] = {}
    for badge in badge_records:
        if not verify_badge(badge):
            continue
        audit_id = str(badge.get("audit_id", ""))
        agent_id = badge_links.get(audit_id)
        if agent_id not in service_hosts_by_agent:
            continue
        target_host = str(badge.get("target_host", "")).rstrip(".").casefold()
        if target_host not in service_hosts_by_agent[agent_id]:
            continue
        associated.setdefault(agent_id, []).append(badge)
    return associated


def associate_attestations(
    indexed_agents: list[IndexedAgent],
    attestation_records: list[dict[str, object]],
    attestation_links: dict[str, str],
    issuer_pub: str,
    issuer_history: Sequence[ApaIssuerKey] = (),
) -> dict[str, list[dict[str, object]]]:
    _require_apa_issuer_pub(issuer_pub)
    service_hosts_by_agent = _listed_service_hosts(indexed_agents, include_non_default_port=True)
    associated: dict[str, list[dict[str, object]]] = {}
    for record in attestation_records:
        if not _valid_apa_attestation(record, issuer_pub, issuer_history):
            continue
        attestation_id = str(record["attestation_id"])
        agent_id = attestation_links.get(attestation_id)
        if agent_id not in service_hosts_by_agent:
            continue
        endpoint_host = _normalize_apa_endpoint_host(record["endpoint_host"])
        if endpoint_host not in service_hosts_by_agent[agent_id]:
            continue
        associated.setdefault(agent_id, []).append(record)
    return associated


def _render_services(indexed: IndexedAgent) -> str:
    if not indexed.agent.services:
        return '<p class="empty-state">No services listed in this marketplace snapshot.</p>'
    rows = []
    for service in indexed.agent.services:
        endpoint = _escape(service.endpoint or "Not reported")
        fee = _escape(service.fee_amount if service.fee_amount is not None else "Not reported")
        rows.append(
            f"""<article class="service-card">
  <p class="eyebrow">Service #{_escape(service.service_id)}</p>
  <h3>{_escape(service.service_name or "Unnamed service")}</h3>
  <dl class="data-list">
    <div><dt>Type</dt><dd>{_escape(service.service_type or "Not reported")}</dd></div>
    <div><dt>Fee amount</dt><dd class="num">{fee}</dd></div>
    <div><dt>Endpoint</dt><dd><code>{endpoint}</code></dd></div>
  </dl>
  <p>{_escape(service.service_description or "No public service description.")}</p>
</article>"""
        )
    return "".join(rows)


def _render_agent_page(
    indexed: IndexedAgent,
    coverage: SnapshotMetadata,
    badge_records: list[dict[str, object]],
    attestation_records: list[dict[str, object]],
    apa_issuer_pub: str,
    apa_issuer_history: Sequence[ApaIssuerKey],
) -> str:
    agent = indexed.agent
    badge = _verified_badge(badge_records)
    if badge is None:
        audit_status = (
            '<p class="status-label status-label--pending">No linked Warden audit</p>'
            '<a class="button secondary" href="/hire">Request an authorized endpoint audit</a>'
        )
    else:
        audit_id = _escape(badge.get("audit_id", ""))
        audit_status = (
            '<p class="status-label status-label--allow">Verified audit badge</p>'
            f'<a class="button secondary" href="/badges/{audit_id}">Open badge {audit_id}</a>'
            '<p class="caveat">The badge signature verifies record integrity. Its agent association comes from a reviewed build manifest and a matching listed-service host.</p>'
        )

    attestation = _verified_attestation(
        attestation_records,
        apa_issuer_pub,
        apa_issuer_history,
    )
    if attestation is None:
        apa_status = '<p class="status-label status-label--pending">No linked APA guard proof</p>'
    else:
        attestation_id = _escape(attestation["attestation_id"])
        scans = attestation["scans_24h"]
        scans_label = "exact count unavailable" if scans is None else f"{int(scans):,} / 24h"
        apa_status = (
            '<p class="status-label status-label--pending">Linked signed APA guard proof; open record for current status</p>'
            f'<a class="button secondary" href="/apa/attestation/{attestation_id}">Open attestation {attestation_id}</a>'
            f'<p class="caveat">Signed usage claim at verification time: {_escape(scans_label)}. This static page does not claim the record is currently active. This is not an endpoint audit or security certification. The issuer signature authenticates the record; its agent association comes from a reviewed manifest plus a matching listed-service endpoint host. Guard-live does not prove every request traversed the guard.</p>'
        )

    avatar_url = _safe_external_url(agent.profile_picture)
    avatar_link = (
        f'<a href="{_escape(avatar_url)}" rel="noreferrer">View marketplace avatar</a>'
        if avatar_url
        else "Marketplace avatar unavailable"
    )
    categories = ", ".join(agent.category_codes) or "Uncategorized"
    threats = ", ".join(indexed.threat_classes) or "No public-text signals"
    verdict = indexed.verdict or "NOT_SCANNED"
    _, public_text_label = _public_text_status(indexed)
    body = f"""
<section class="agent-hero">
  <div class="agent-avatar" aria-hidden="true">{_escape(_initials(agent.name))}</div>
  <div>
    <p class="eyebrow">Marketplace agent #{_escape(agent.agent_id)}</p>
    <h1>{_escape(agent.name or "Unnamed agent")}</h1>
    <p class="hero-text">{_escape(agent.profile_description or "No public profile description.")}</p>
    <p class="source-link">{avatar_link} | <a href="https://www.okx.ai/" rel="noreferrer">Open OKX.AI and search Agent #{_escape(agent.agent_id)}</a></p>
  </div>
</section>
<section class="data-grid" aria-label="Marketplace statistics">
  <div><span>Category</span><strong>{_escape(categories)}</strong></div>
  <div><span>Sold count</span><strong class="num">{_number(agent.sold_count)}</strong></div>
  <div><span>Feedback rate</span><strong class="num">{_raw_stat(agent.feedback_rate)}</strong></div>
  <div><span>Buyer review average</span><strong class="num">{_buyer_review(agent.security_rate)}</strong></div>
</section>
<section class="feature-panel">
  <p class="eyebrow">Public listing text only</p>
  <h2>{_escape(public_text_label)}</h2>
  <p>{_escape(indexed.rationale)}</p>
  <dl class="data-list">
    <div><dt>Warden decision</dt><dd>{_escape(verdict)}</dd></div>
    <div><dt>Threat classes</dt><dd>{_escape(threats)}</dd></div>
    <div><dt>Fields scanned</dt><dd class="num">{indexed.fields_scanned}</dd></div>
  </dl>
  <p class="caveat"><strong>Scope:</strong> This scans only the public profile and service descriptions captured in the dated marketplace snapshot. It does not call the endpoint, establish malicious intent, or certify security.</p>
</section>
<section>
  <p class="eyebrow">Independent audit</p>
  <h2>Audit status</h2>
  {audit_status}
</section>
<section>
  <p class="eyebrow">Agent Protection Attestation</p>
  <h2>Guard-proof status</h2>
  {apa_status}
</section>
<section>
  <p class="eyebrow">Public services</p>
  <h2>{len(agent.services)} listed service{"s" if len(agent.services) != 1 else ""}</h2>
  <div class="service-grid">{_render_services(indexed)}</div>
</section>
<p class="snapshot-note">{_escape(_coverage_text(coverage))}</p>
"""
    return page_shell(
        f"{agent.name or 'Unnamed agent'} | Warden Security Index",
        f"Public listing-text scan for OKX.AI Agent #{agent.agent_id}.",
        body,
        active="agents",
        canonical_path=f"/agents/{agent.agent_id}",
    )


def _render_index_page(
    indexed_agents: list[IndexedAgent],
    coverage: SnapshotMetadata,
    summary: RenderSummary,
    audited_agent_ids: set[str],
    attested_agent_ids: set[str],
) -> str:
    categories = sorted(
        {category for indexed in indexed_agents for category in indexed.agent.category_codes}
    )
    options = "".join(
        f'<option value="{_escape(category)}">{_escape(category)}</option>'
        for category in categories
    )
    sorted_agents = sorted(
        indexed_agents,
        key=lambda indexed: (
            -(indexed.agent.sold_count if indexed.agent.sold_count is not None else -1),
            indexed.agent.name.casefold(),
        ),
    )
    rows = []
    for indexed in sorted_agents:
        agent = indexed.agent
        match_state, public_text_label = _public_text_status(indexed)
        audit_state = "audited" if agent.agent_id in audited_agent_ids else "not-audited"
        audit_label = "Linked signed audit" if audit_state == "audited" else "No linked audit"
        apa_label = (
            "Linked signed APA guard proof; open record for current status"
            if agent.agent_id in attested_agent_ids
            else "No linked APA guard proof"
        )
        categories_text = ", ".join(agent.category_codes) or "Uncategorized"
        category_data = "|".join(agent.category_codes)
        search_text = " ".join(
            (
                agent.agent_id,
                agent.name,
                categories_text,
                public_text_label,
                " ".join(indexed.threat_classes),
                audit_label,
                apa_label,
            )
        )
        sold_sort = "" if agent.sold_count is None else str(agent.sold_count)
        review_sort = "" if agent.security_rate is None else str(agent.security_rate)
        row_label = (
            f"Agent: {agent.name or 'Unnamed agent'}; Agent ID: {agent.agent_id}; "
            f"Category: {categories_text}; Sold: {_number(agent.sold_count)}; "
            f"Public listing text: {public_text_label}; "
            f"Verdict: {indexed.verdict or 'NOT_SCANNED'}; "
            f"Endpoint audit: {audit_label}; "
            f"APA attestation: {apa_label}; "
            f"Buyer review average: {_buyer_review(agent.security_rate)}"
        )
        rows.append(
            f"""<a class="agent-row" href="/agents/{_escape(agent.agent_id)}" aria-label="{_escape(row_label)}" data-agent-row data-search="{_escape(search_text)}" data-category="{_escape(category_data)}" data-match="{match_state}" data-audit="{audit_state}" data-name="{_escape(agent.name.casefold())}" data-agent-id="{_escape(agent.agent_id)}" data-sold="{sold_sort}" data-review="{review_sort}">
  <span><strong>{_escape(agent.name or "Unnamed agent")}</strong><small>Agent #{_escape(agent.agent_id)}</small></span>
  <span data-label="Category">{_escape(categories_text)}</span>
  <span class="num" data-label="Sold">{_number(agent.sold_count)}</span>
  <span data-label="Public text"><strong>{_escape(public_text_label)}</strong><small>{_escape(indexed.verdict or "NOT_SCANNED")}</small></span>
  <span data-label="Endpoint evidence"><strong>{audit_label}</strong><small>{apa_label}</small></span>
  <span class="num" data-label="Buyer reviews">{_buyer_review(agent.security_rate)}</span>
</a>"""
        )

    agent_label = "agent" if summary.sampled == 1 else "agents"
    body = f"""
<section class="index-hero">
  <p class="eyebrow">OKX.AI marketplace security index</p>
  <h1><span class="num">{summary.sampled}</span> {agent_label} indexed</h1>
  <p class="hero-text">{summary.matched_count} with deterministic pattern matches in public listing text | {summary.audited_count} with linked signed endpoint-audit records.</p>
  <p class="caveat"><strong>Public listing text only.</strong> {_escape(_coverage_text(coverage))} A text signal is not a finding that an agent is malicious, compromised, or unsafe.</p>
</section>
<details class="methodology-drawer" id="methodology">
  <summary>Methodology and evidence boundary</summary>
  <div class="feature-panel">
    <h2>What the index checks</h2>
    <p>Warden runs its deterministic fast path over each captured public profile description and public service description. The dated snapshot supplies names, categories, listing statistics, and service metadata.</p>
    <h3>What this does not mean</h3>
    <p>The index does not call agent endpoints, inspect private prompts, prove ownership, establish intent, or provide continuous monitoring. “No public-text pattern match” means only that no implemented fast detector fired on the captured listing fields.</p>
    <h3>Independent endpoint audits</h3>
    <p>Audit status is separate. “Linked signed audit” requires a valid Warden badge plus a reviewed audit-to-agent link and matching listed-service host. A badge is point-in-time evidence, not certification.</p>
    <p><a class="button secondary" href="/hire">Configure an authorized endpoint audit</a></p>
    <p class="caveat">Audit only a public endpoint you own or are authorized to test. A returned result is not independent proof of target-owner permission.</p>
    <h3>APA guard proofs</h3>
    <p>“Linked signed APA guard proof” requires a valid Warden issuer signature, an explicit reviewed attestation-to-agent link, and the attested endpoint host in that agent's listed services. It records live-guard evidence at verification time; open the attestation for current status. It is not an endpoint audit or security certification, and it does not prove every request traversed the guard.</p>
  </div>
</details>
<section class="filter-bar marketplace-filter-bar" data-agent-controls hidden aria-label="Search, filter, and sort agents">
  <label>Search listings<input type="search" data-agent-search autocomplete="off" placeholder="Name, agent ID, category, or signal"></label>
  <label>Category<select data-agent-category><option value="">All categories</option>{options}</select></label>
  <label>Public-text signal<select data-agent-match><option value="">All public-text results</option><option value="signal">Pattern match</option><option value="none">No pattern match</option><option value="unscanned">No public text to scan</option></select></label>
  <label>Endpoint audit<select data-agent-audit><option value="">All audit states</option><option value="audited">Linked signed audit</option><option value="not-audited">No linked audit</option></select></label>
  <label>Sort<select data-agent-sort><option value="sold-desc">Sold count, high to low</option><option value="name-asc">Name, A to Z</option><option value="review-desc">Buyer review, high to low</option><option value="signal-first">Public-text signals first</option><option value="audit-first">Linked audits first</option></select></label>
  <button class="button secondary" type="button" data-agent-reset>Clear filters</button>
</section>
<section>
  <p class="snapshot-note" aria-live="polite" aria-atomic="true">Showing <span class="num" data-agent-rendered>{summary.sampled}</span> of <span class="num" data-agent-visible>{summary.sampled}</span> matching agents.</p>
  <noscript><p class="snapshot-note">Search and filter controls require JavaScript. All agents in this dated snapshot are listed below.</p></noscript>
  <div class="agent-row agent-row--header" aria-hidden="true"><span>Agent</span><span>Category</span><span>Sold</span><span>Public listing text</span><span>Endpoint evidence</span><span>Buyer review average</span></div>
  <div data-agent-results>{"".join(rows)}</div>
  <button class="button secondary" type="button" data-agent-more hidden>Show more agents</button>
  <p class="empty-state" data-agent-empty hidden>No marketplace listings match these filters. Clear a filter to restore the full dated snapshot.</p>
</section>
"""
    return page_shell(
        "Marketplace Security Index | Warden",
        "Public listing-text scans for agents returned by the OKX.AI marketplace sweep.",
        body,
        active="agents",
        scripts=("agents.js",),
        canonical_path="/agents",
    )


def render_marketplace(
    indexed_agents: list[IndexedAgent],
    output_dir: Path,
    *,
    coverage: SnapshotMetadata,
    badge_records: dict[str, list[dict[str, object]]] | None = None,
    attestation_records: dict[str, list[dict[str, object]]] | None = None,
    apa_issuer_pub: str | None = None,
    apa_issuer_history: Sequence[ApaIssuerKey] = (),
) -> RenderSummary:
    if len(indexed_agents) != coverage.sampled:
        raise RuntimeError("indexed agent count does not match snapshot sampled coverage")
    output_dir.mkdir(parents=True, exist_ok=True)
    badges = badge_records or {}
    attestations = attestation_records or {}
    if attestations and not apa_issuer_pub:
        raise ValueError("APA issuer public key is required to render attestation evidence")
    issuer_pub = apa_issuer_pub or ""
    expected_files = {f"{indexed.agent.agent_id}.html" for indexed in indexed_agents}
    for existing in output_dir.glob("*.html"):
        if existing.stem.isdecimal() and existing.name not in expected_files:
            existing.unlink()

    audited_count = 0
    audited_agent_ids: set[str] = set()
    attested_agent_ids: set[str] = set()
    for indexed in indexed_agents:
        records = badges.get(indexed.agent.agent_id, [])
        if _verified_badge(records) is not None:
            audited_count += 1
            audited_agent_ids.add(indexed.agent.agent_id)
        agent_attestations = attestations.get(indexed.agent.agent_id, [])
        attestation = _verified_attestation(
            agent_attestations,
            issuer_pub,
            apa_issuer_history,
        )
        if attestation is not None:
            attested_agent_ids.add(indexed.agent.agent_id)
        page = _render_agent_page(
            indexed,
            coverage,
            records,
            agent_attestations,
            issuer_pub,
            apa_issuer_history,
        )
        (output_dir / f"{indexed.agent.agent_id}.html").write_text(page, encoding="utf-8")

    summary = RenderSummary(
        sampled=coverage.sampled,
        expected=coverage.expected,
        dropped=coverage.dropped,
        matched_count=sum(bool(indexed.threat_classes) for indexed in indexed_agents),
        audited_count=audited_count,
    )
    index_page = _render_index_page(
        indexed_agents,
        coverage,
        summary,
        audited_agent_ids,
        attested_agent_ids,
    )
    (output_dir / "index.html").write_text(index_page, encoding="utf-8")
    return summary
