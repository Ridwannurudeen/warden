"""Render static marketplace security index pages."""

from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from warden.badges import verify_badge
from warden.marketplace.index import IndexedAgent
from warden.site_render import page_shell


@dataclass(frozen=True)
class RenderSummary:
    agent_count: int
    matched_count: int
    audited_count: int


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


def associate_badges(
    indexed_agents: list[IndexedAgent],
    badge_records: list[dict[str, object]],
    badge_links: dict[str, str],
) -> dict[str, list[dict[str, object]]]:
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
            host = endpoint.hostname.rstrip(".").casefold()
            service_hosts_by_agent.setdefault(indexed.agent.agent_id, set()).add(host)

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
    fetched_at: str,
    badge_records: list[dict[str, object]],
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
  <p class="eyebrow">Public services</p>
  <h2>{len(agent.services)} listed service{"s" if len(agent.services) != 1 else ""}</h2>
  <div class="service-grid">{_render_services(indexed)}</div>
</section>
<p class="snapshot-note">Marketplace snapshot fetched {_escape(fetched_at)}.</p>
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
    fetched_at: str,
    summary: RenderSummary,
    audited_agent_ids: set[str],
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
            f"Buyer review average: {_buyer_review(agent.security_rate)}"
        )
        rows.append(
            f"""<a class="agent-row" href="/agents/{_escape(agent.agent_id)}" aria-label="{_escape(row_label)}" data-agent-row data-search="{_escape(search_text)}" data-category="{_escape(category_data)}" data-match="{match_state}" data-audit="{audit_state}" data-name="{_escape(agent.name.casefold())}" data-agent-id="{_escape(agent.agent_id)}" data-sold="{sold_sort}" data-review="{review_sort}">
  <span><strong>{_escape(agent.name or "Unnamed agent")}</strong><small>Agent #{_escape(agent.agent_id)}</small></span>
  <span data-label="Category">{_escape(categories_text)}</span>
  <span class="num" data-label="Sold">{_number(agent.sold_count)}</span>
  <span data-label="Public text"><strong>{_escape(public_text_label)}</strong><small>{_escape(indexed.verdict or "NOT_SCANNED")}</small></span>
  <span data-label="Endpoint audit"><strong>{audit_label}</strong></span>
  <span class="num" data-label="Buyer reviews">{_buyer_review(agent.security_rate)}</span>
</a>"""
        )

    agent_label = "agent" if summary.agent_count == 1 else "agents"
    body = f"""
<section class="index-hero">
  <p class="eyebrow">OKX.AI marketplace security index</p>
  <h1><span class="num">{summary.agent_count}</span> {agent_label} indexed</h1>
  <p class="hero-text">{summary.matched_count} with deterministic pattern matches in public listing text | {summary.audited_count} with linked signed endpoint-audit records.</p>
  <p class="caveat"><strong>Public listing text only.</strong> All agents returned by the marketplace sweep at {_escape(fetched_at)}. A text signal is not a finding that an agent is malicious, compromised, or unsafe.</p>
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
  <p class="snapshot-note" aria-live="polite" aria-atomic="true">Showing <span class="num" data-agent-rendered>{summary.agent_count}</span> of <span class="num" data-agent-visible>{summary.agent_count}</span> matching agents.</p>
  <noscript><p class="snapshot-note">Search and filter controls require JavaScript. All agents in this dated snapshot are listed below.</p></noscript>
  <div class="agent-row agent-row--header" aria-hidden="true"><span>Agent</span><span>Category</span><span>Sold</span><span>Public listing text</span><span>Endpoint audit</span><span>Buyer review average</span></div>
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
    fetched_at: str,
    badge_records: dict[str, list[dict[str, object]]] | None = None,
) -> RenderSummary:
    output_dir.mkdir(parents=True, exist_ok=True)
    badges = badge_records or {}
    expected_files = {f"{indexed.agent.agent_id}.html" for indexed in indexed_agents}
    for existing in output_dir.glob("*.html"):
        if existing.stem.isdecimal() and existing.name not in expected_files:
            existing.unlink()

    audited_count = 0
    audited_agent_ids: set[str] = set()
    for indexed in indexed_agents:
        records = badges.get(indexed.agent.agent_id, [])
        if _verified_badge(records) is not None:
            audited_count += 1
            audited_agent_ids.add(indexed.agent.agent_id)
        page = _render_agent_page(indexed, fetched_at, records)
        (output_dir / f"{indexed.agent.agent_id}.html").write_text(page, encoding="utf-8")

    summary = RenderSummary(
        agent_count=len(indexed_agents),
        matched_count=sum(bool(indexed.threat_classes) for indexed in indexed_agents),
        audited_count=audited_count,
    )
    index_page = _render_index_page(indexed_agents, fetched_at, summary, audited_agent_ids)
    (output_dir / "index.html").write_text(index_page, encoding="utf-8")
    return summary
