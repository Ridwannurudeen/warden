"""Render static marketplace security index pages."""

from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from warden.badges import verify_badge
from warden.marketplace.index import IndexedAgent


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


def _verified_badge(records: list[dict[str, object]]) -> dict[str, object] | None:
    valid = [record for record in records if verify_badge(record)]
    if not valid:
        return None
    return max(valid, key=lambda record: str(record.get("issued_at", "")))


def _page_shell(title: str, description: str, body: str, active: str = "agents") -> str:
    nav = []
    for href, label, key in (
        ("/", "Home", "home"),
        ("/playground", "Playground", "playground"),
        ("/agents", "Agents", "agents"),
        ("/gauntlet", "Gauntlet", "gauntlet"),
        ("/hire", "Hire", "hire"),
        ("/docs", "Docs", "docs"),
    ):
        current = ' aria-current="page"' if key == active else ""
        nav.append(f'<a href="{href}"{current}>{label}</a>')
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="{_escape(description)}">
    <title>{_escape(title)}</title>
    <link rel="icon" href="/assets/warden-avatar.png">
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header class="site-header page-shell">
      <a class="brand" href="/"><img src="/assets/warden-avatar.png" alt="" width="36" height="36"><span>Warden</span></a>
      <nav class="site-nav" aria-label="Primary">{" ".join(nav)}</nav>
    </header>
    <main id="main" class="page-shell">{body}</main>
    <script src="/app.js" defer></script>
  </body>
</html>
"""


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
            '<p class="status-label status-label--pending">Not yet audited</p>'
            '<a class="button secondary" href="/hire">Get a Warden audit</a>'
        )
    else:
        audit_id = _escape(badge.get("audit_id", ""))
        audit_status = (
            '<p class="status-label status-label--allow">Verified audit badge</p>'
            f'<a class="button secondary" href="/badges/{audit_id}">Open badge {audit_id}</a>'
        )

    avatar_url = _safe_external_url(agent.profile_picture)
    avatar_link = (
        f'<a href="{_escape(avatar_url)}" rel="noreferrer">View marketplace avatar</a>'
        if avatar_url
        else "Marketplace avatar unavailable"
    )
    categories = ", ".join(agent.category_codes) or "Uncategorized"
    threats = ", ".join(indexed.threat_classes) or "None detected"
    verdict = indexed.verdict or "NOT_SCANNED"
    body = f"""
<section class="agent-hero">
  <div class="agent-avatar" aria-hidden="true">{_escape(_initials(agent.name))}</div>
  <div>
    <p class="eyebrow">Marketplace agent #{_escape(agent.agent_id)}</p>
    <h1>{_escape(agent.name or "Unnamed agent")}</h1>
    <p class="hero-text">{_escape(agent.profile_description or "No public profile description.")}</p>
    <p class="source-link">{avatar_link} · <a href="https://www.okx.ai/" rel="noreferrer">Open OKX.AI and search Agent #{_escape(agent.agent_id)}</a></p>
  </div>
</section>
<section class="data-grid" aria-label="Marketplace statistics">
  <div><span>Category</span><strong>{_escape(categories)}</strong></div>
  <div><span>Sold count</span><strong class="num">{_number(agent.sold_count)}</strong></div>
  <div><span>Feedback rate</span><strong class="num">{_raw_stat(agent.feedback_rate)}</strong></div>
  <div><span>Buyer review average</span><strong class="num">{_buyer_review(agent.security_rate)}</strong></div>
</section>
<section class="feature-panel">
  <p class="eyebrow">Warden public-text scan</p>
  <h2>{_escape(verdict)}</h2>
  <p>{_escape(indexed.rationale)}</p>
  <dl class="data-list">
    <div><dt>Threat classes</dt><dd>{_escape(threats)}</dd></div>
    <div><dt>Fields scanned</dt><dd class="num">{indexed.fields_scanned}</dd></div>
  </dl>
  <p class="caveat"><strong>Scope:</strong> This scans public listing descriptions only. It does not test endpoint behavior and does not certify that an agent is secure.</p>
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
    return _page_shell(
        f"{agent.name or 'Unnamed agent'} | Warden Security Index",
        f"Public listing-text scan for OKX.AI Agent #{agent.agent_id}.",
        body,
    )


def _render_index_page(
    indexed_agents: list[IndexedAgent],
    fetched_at: str,
    summary: RenderSummary,
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
        has_match = bool(indexed.threat_classes)
        rows.append(
            f"""<a class="agent-row" href="/agents/{_escape(agent.agent_id)}" data-category="{_escape(" ".join(agent.category_codes))}" data-match="{"yes" if has_match else "no"}">
  <span><strong>{_escape(agent.name or "Unnamed agent")}</strong><small>Agent #{_escape(agent.agent_id)}</small></span>
  <span>{_escape(", ".join(agent.category_codes) or "Uncategorized")}</span>
  <span class="num">{_number(agent.sold_count)}</span>
  <span>{_escape(indexed.verdict or "NOT_SCANNED")}</span>
  <span class="num">{_buyer_review(agent.security_rate)}</span>
</a>"""
        )

    agent_label = "agent" if summary.agent_count == 1 else "agents"
    body = f"""
<section class="index-hero">
  <p class="eyebrow">OKX.AI marketplace security index</p>
  <h1><span class="num">{summary.agent_count}</span> {agent_label} indexed</h1>
  <p class="hero-text">{summary.matched_count} with injection-pattern matches in public text · {summary.audited_count} independently audited.</p>
  <p class="caveat">All agents returned by the marketplace sweep at {_escape(fetched_at)}. Results cover public listing text only, not endpoint behavior.</p>
</section>
<section class="filter-bar" aria-label="Agent filters">
  <label>Category<select data-agent-category><option value="">All categories</option>{options}</select></label>
  <label>Public-text match<select data-agent-match><option value="">All results</option><option value="yes">Pattern match</option><option value="no">No match</option></select></label>
</section>
<section>
  <div class="agent-row agent-row--header" aria-hidden="true"><span>Agent</span><span>Category</span><span>Sold</span><span>Text scan</span><span>Buyer review average</span></div>
  <div data-agent-results>{"".join(rows)}</div>
</section>
"""
    return _page_shell(
        "Marketplace Security Index | Warden",
        "Public listing-text scans for agents returned by the OKX.AI marketplace sweep.",
        body,
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
    for indexed in indexed_agents:
        records = badges.get(indexed.agent.agent_id, [])
        if _verified_badge(records) is not None:
            audited_count += 1
        page = _render_agent_page(indexed, fetched_at, records)
        (output_dir / f"{indexed.agent.agent_id}.html").write_text(page, encoding="utf-8")

    summary = RenderSummary(
        agent_count=len(indexed_agents),
        matched_count=sum(bool(indexed.threat_classes) for indexed in indexed_agents),
        audited_count=audited_count,
    )
    index_page = _render_index_page(indexed_agents, fetched_at, summary)
    (output_dir / "index.html").write_text(index_page, encoding="utf-8")
    return summary
