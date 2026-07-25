"""Render static marketplace security index pages."""

from __future__ import annotations

import html
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from warden.badges import (
    b64u_decode,
    b64u_encode,
    canonical_target,
    ed25519_verify_record,
    verify_badge,
)
from warden.marketplace.fetch import SnapshotMetadata
from warden.marketplace.index import IndexedAgent
from warden.site_render import page_shell

APA_ISSUER = "warden"
APA_PROTECTOR = "warden"
APA_ATTESTATION_TTL_SECONDS = 3_600
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991
WARDEN_MARKETPLACE_AGENT_ID = "3808"
MARKETPLACE_INDEX_ROW_LIMIT = 50


@dataclass(frozen=True)
class RenderSummary:
    sampled: int
    expected: int
    dropped: int
    matched_count: int
    audited_count: int


@dataclass(frozen=True)
class PageProvenance:
    """Where one agent page's facts came from.

    Census pages describe a dated crawl of the public marketplace. Our own page cannot,
    because `agent search` omits a listing under review, so it states our own listing as
    its source instead. The page must never present one as the other.
    """

    note: str
    scope_source: str
    stat_suffix: str


@dataclass(frozen=True)
class ApaIssuerKey:
    kid: str
    pub: str
    not_after: int


# A marketplace crawl routinely misses a small fraction of the reported total because OKX
# pagination is not fully stable across pages. A snapshot that captured at least this ratio
# of the reported total is treated as a complete dated capture (stamp DATED); below it, or
# when counts disagree (sampled > expected), the capture is flagged DEGRADED. The coverage
# note always states the exact sampled/expected/dropped figures regardless of the stamp.
MARKETPLACE_COMPLETE_RATIO = 0.99


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _safe_external_url(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not hostname
        or username
        or password
        or (port is not None and not 1 <= port <= 65_535)
    ):
        return None
    return value


def _initials(name: str) -> str:
    words = name.split()
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return f"{words[0][0]}{words[1][0]}".upper()


def _language_attribute(value: object) -> str:
    text = str(value)
    if any("\u3040" <= character <= "\u30ff" for character in text):
        return ' lang="ja"'
    if any("\uac00" <= character <= "\ud7af" for character in text):
        return ' lang="ko"'
    if any(
        "\u3400" <= character <= "\u4dbf" or "\u4e00" <= character <= "\u9fff" for character in text
    ):
        return ' lang="zh"'
    return ""


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
    captured_ratio = coverage.sampled / coverage.expected if coverage.expected else 0.0
    if captured_ratio >= MARKETPLACE_COMPLETE_RATIO:
        return (
            f'Dated discovery snapshot for marketplace query "{coverage.query}". '
            f"{coverage.sampled} of {coverage.expected} listed {agent_label} captured; "
            f"{coverage.dropped} {missing_label} not present in this crawl "
            f"(OKX marketplace pagination is not fully stable across pages, so a few "
            f"listings can shift between pages during discovery). "
            f"Captured {coverage.captured_at}."
        )
    return (
        f'Partial/degraded discovery response for marketplace query "{coverage.query}". '
        f"{coverage.sampled} of {coverage.expected} listed {agent_label} captured; "
        f"{coverage.dropped} {missing_label} not present in this response. "
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
            try:
                endpoint = urlparse(service.endpoint)
                hostname = endpoint.hostname
                username = endpoint.username
                password = endpoint.password
                port = endpoint.port
            except ValueError:
                continue
            if endpoint.scheme not in {"http", "https"} or not hostname or username or password:
                continue
            host = hostname.rstrip(".").casefold()
            default_port = 443 if endpoint.scheme == "https" else 80
            if include_non_default_port and port not in (None, default_port):
                host = f"{host}:{port}"
            service_hosts_by_agent.setdefault(indexed.agent.agent_id, set()).add(host)
    return service_hosts_by_agent


def _listed_service_targets(indexed_agents: list[IndexedAgent]) -> dict[str, set[str]]:
    """Per-agent set of exact canonical service endpoints (scheme/host/port/path)."""
    targets_by_agent: dict[str, set[str]] = {}
    for indexed in indexed_agents:
        for service in indexed.agent.services:
            try:
                endpoint = urlparse(service.endpoint)
                hostname = endpoint.hostname
                username = endpoint.username
                password = endpoint.password
                port = endpoint.port
            except ValueError:
                continue
            if endpoint.scheme not in {"http", "https"} or not hostname or username or password:
                continue
            canonical = canonical_target(
                endpoint.scheme, hostname, port, endpoint.path, endpoint.query
            )
            targets_by_agent.setdefault(indexed.agent.agent_id, set()).add(canonical)
    return targets_by_agent


def _badge_canonical_target(badge: dict[str, object]) -> str | None:
    """Return the exact canonical endpoint a v2 badge is bound to, else None (v1)."""
    target = badge.get("target")
    if not isinstance(target, dict):
        return None
    scheme = target.get("scheme")
    host = target.get("host")
    if not isinstance(scheme, str) or not isinstance(host, str) or not host:
        return None
    port = target.get("port")
    if port is not None and not isinstance(port, int):
        return None
    path = target.get("path")
    query = target.get("query")
    return canonical_target(
        scheme,
        host,
        port,
        path if isinstance(path, str) else "/",
        query if isinstance(query, str) else "",
    )


def _normalize_apa_endpoint_host(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character.isspace() or character in "/?#@" for character in value)
    ):
        return None
    try:
        parsed = urlparse(f"//{value}")
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        return None
    if (
        not hostname
        or username
        or password
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = hostname.rstrip(".").casefold()
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
    service_targets_by_agent = _listed_service_targets(indexed_agents)

    associated: dict[str, list[dict[str, object]]] = {}
    for badge in badge_records:
        if not verify_badge(badge):
            continue
        audit_id = str(badge.get("audit_id", ""))
        agent_id = badge_links.get(audit_id)
        if agent_id is None:
            continue
        badge_target = _badge_canonical_target(badge)
        if badge_target is not None:
            # v2 records bind the exact audited endpoint; association requires an
            # exact scheme/host/port/path match to one of the agent's services.
            if badge_target not in service_targets_by_agent.get(agent_id, set()):
                continue
        else:
            # Legacy v1 records carry only a host; they remain host-scoped receipts.
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
    open_attribute = " open" if len(indexed.agent.services) == 1 else ""
    for service in indexed.agent.services:
        endpoint = _escape(service.endpoint or "Not reported")
        fee = _escape(service.fee_amount if service.fee_amount is not None else "Not reported")
        rows.append(
            f"""<details class="marketplace-service"{open_attribute}>
  <summary><span class="marketplace-service__summary">
    <span class="marketplace-service__identity"><span class="service-id">Service #{_escape(service.service_id)}</span><strong{_language_attribute(service.service_name)}>{_escape(service.service_name or "Unnamed service")}</strong></span>
    <span class="marketplace-service__meta"><span><span class="sr-only">Type: </span>{_escape(service.service_type or "Not reported")}</span><span class="num"><span class="sr-only">Fee amount: </span>{fee}</span></span>
  </span></summary>
  <div class="marketplace-service__body">
    <dl class="data-list">
    <div><dt>Endpoint</dt><dd><code>{endpoint}</code></dd></div>
    </dl>
    <p class="marketplace-service__description"{_language_attribute(service.service_description)}>{_escape(service.service_description or "No public service description.")}</p>
  </div>
</details>"""
        )
    return "".join(rows)


def _census_provenance(coverage: SnapshotMetadata) -> PageProvenance:
    return PageProvenance(
        note=_coverage_text(coverage),
        scope_source="the dated marketplace snapshot",
        stat_suffix="at snapshot",
    )


def _provider_provenance(fetched_at: str, *, in_census: bool) -> PageProvenance:
    census_state = (
        "It is also present in the dated discovery crawl."
        if in_census
        else "The discovery crawl omits it, because OKX excludes a listing under review "
        "from agent search, so this page is not a census record."
    )
    return PageProvenance(
        note=(
            "Sourced from Warden's own OKX.AI listing via agent service-list, fetched "
            f"{fetched_at}. {census_state}"
        ),
        scope_source="our own OKX.AI listing",
        stat_suffix="at listing fetch",
    )


def _render_agent_page(
    indexed: IndexedAgent,
    provenance: PageProvenance,
    badge_records: list[dict[str, object]],
    attestation_records: list[dict[str, object]],
    apa_issuer_pub: str,
    apa_issuer_history: Sequence[ApaIssuerKey],
) -> str:
    agent = indexed.agent
    badge = _verified_badge(badge_records)
    if badge is None:
        audit_status = (
            "<span>No linked endpoint audit record in this dated build.</span>"
            '<a class="text-link" href="/hire">Request an authorized endpoint audit</a>'
        )
    else:
        audit_id = _escape(badge.get("audit_id", ""))
        audit_status = (
            "<strong>Linked signed endpoint audit record</strong>"
            f'<a class="text-link" href="/badges/{audit_id}">'
            f"Open endpoint audit record {audit_id}</a>"
            "<small>The signature verifies record integrity. The agent link comes from a "
            "reviewed build manifest and a matching listed-service host.</small>"
        )

    attestation = _verified_attestation(
        attestation_records,
        apa_issuer_pub,
        apa_issuer_history,
    )
    if attestation is None:
        apa_status = "<span>No linked APA guard proof in this dated build.</span>"
    else:
        attestation_id = _escape(attestation["attestation_id"])
        scans = attestation["scans_24h"]
        scans_label = "exact count unavailable" if scans is None else f"{int(scans):,} / 24h"
        apa_status = (
            "<strong>Linked signed APA guard proof</strong>"
            f'<a class="text-link" href="/apa/attestation/{attestation_id}">'
            f"Open attestation {attestation_id}</a>"
            f"<small>Signed usage claim at verification time: {_escape(scans_label)}. "
            "This static page does not claim the record is currently active. The issuer "
            "signature authenticates the record; the agent link comes from a reviewed "
            "manifest and a matching listed-service endpoint host.</small>"
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
    sold_label = (
        f"Sold {provenance.stat_suffix}"
        if agent.agent_id == WARDEN_MARKETPLACE_AGENT_ID
        else "Sold count"
    )
    buyer_review_label = (
        f"Buyer review {provenance.stat_suffix}"
        if agent.agent_id == WARDEN_MARKETPLACE_AGENT_ID
        else "Buyer review average"
    )
    verdict_chip_class = {
        "ALLOW": "status-label status-label--allow",
        "SANITIZE": "status-label status-label--sanitize",
        "BLOCK": "status-label",
    }.get(verdict, "status-label status-label--unscanned")
    audit_evidence_state = "none" if badge is None else "linked"
    apa_evidence_state = "none" if attestation is None else "linked"
    body = f"""
<section class="agent-hero">
  <div class="agent-avatar" aria-hidden="true">{_escape(_initials(agent.name))}</div>
  <div>
    <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Home</a><span aria-hidden="true">/</span><a href="/agents">Marketplace Evidence Index</a><span aria-hidden="true">/</span><span>Agent #{_escape(agent.agent_id)}</span></nav>
    <p class="eyebrow">Marketplace agent #{_escape(agent.agent_id)}</p>
    <h1{_language_attribute(agent.name)}>{_escape(agent.name or "Unnamed agent")}</h1>
    <p class="hero-text"{_language_attribute(agent.profile_description)}>{_escape(agent.profile_description or "No public profile description.")}</p>
    <span class="source-stamp" data-source-stamp="DATED"><span data-source-stamp-label>DATED</span></span>
    <p class="source-link">{avatar_link} | <a href="https://www.okx.ai/" rel="noreferrer">Open OKX.AI and search Agent #{_escape(agent.agent_id)}</a></p>
  </div>
</section>
<section class="data-grid" aria-label="Marketplace statistics">
  <div><span>Category</span><strong>{_escape(categories)}</strong></div>
  <div><span>{sold_label}</span><strong class="num">{_number(agent.sold_count)}</strong></div>
  <div><span>Feedback rate</span><strong class="num">{_raw_stat(agent.feedback_rate)}</strong></div>
  <div><span>{buyer_review_label}</span><strong class="num">{_buyer_review(agent.security_rate)}</strong></div>
</section>
<section class="feature-panel scan-verdict" data-verdict="{_escape(verdict)}">
  <div class="scan-verdict__head">
    <div>
      <p class="eyebrow">Public listing text only</p>
      <h2>{_escape(public_text_label)}</h2>
    </div>
    <span class="{verdict_chip_class}">{_escape(verdict)}</span>
  </div>
  <div class="scan-verdict__body">
  <p>{_escape(indexed.rationale)}</p>
  <dl class="data-list">
    <div><dt>Warden decision</dt><dd>{_escape(verdict)}</dd></div>
    <div><dt>Threat classes</dt><dd>{_escape(threats)}</dd></div>
    <div><dt>Fields scanned</dt><dd class="num">{indexed.fields_scanned}</dd></div>
  </dl>
  <p class="caveat"><strong>Scope:</strong> This scans only the public profile and service descriptions captured in {_escape(provenance.scope_source)}. It does not call the endpoint, establish malicious intent, or certify security.</p>
  </div>
</section>
<section>
  <p class="eyebrow">Linked evidence</p>
  <h2>Endpoint and guard records</h2>
  <dl class="data-list linked-evidence-ledger">
    <div data-evidence="{audit_evidence_state}"><dt>Endpoint audit record</dt><dd>{audit_status}</dd></div>
    <div data-evidence="{apa_evidence_state}"><dt>APA guard proof</dt><dd>{apa_status}</dd></div>
  </dl>
  <p class="caveat">No linked record is not evidence of safety or risk. An endpoint audit record is point-in-time evidence, not certification. A guard proof is not an endpoint audit or security certification and does not prove every request traversed the guard.</p>
</section>
<section>
  <p class="eyebrow">Public services</p>
  <h2>{len(agent.services)} listed service{"s" if len(agent.services) != 1 else ""}</h2>
  <div class="marketplace-service-list">{_render_services(indexed)}</div>
</section>
<p class="snapshot-note">{_escape(provenance.note)}</p>
"""
    return page_shell(
        f"{agent.name or 'Unnamed agent'} · Agent #{agent.agent_id} | Warden Marketplace Evidence Index",
        f"Public listing-text scan for OKX.AI Agent #{agent.agent_id}.",
        body,
        active="agents",
        body_class="page-archetype--marketplace",
        canonical_path=f"/agents/{agent.agent_id}",
    )


def _sorted_indexed_agents(indexed_agents: list[IndexedAgent]) -> list[IndexedAgent]:
    return sorted(
        indexed_agents,
        key=lambda indexed: (
            -(indexed.agent.sold_count if indexed.agent.sold_count is not None else -1),
            indexed.agent.name.casefold(),
        ),
    )


def _marketplace_index_data(
    indexed_agents: list[IndexedAgent],
    coverage: SnapshotMetadata,
    audited_agent_ids: set[str],
    attested_agent_ids: set[str],
) -> dict[str, object]:
    records = []
    for indexed in _sorted_indexed_agents(indexed_agents):
        agent = indexed.agent
        match_state, public_text_label = _public_text_status(indexed)
        records.append(
            {
                "agentId": agent.agent_id,
                "name": agent.name,
                "categories": list(agent.category_codes),
                "sold": agent.sold_count,
                "review": agent.security_rate,
                "match": match_state,
                "publicTextLabel": public_text_label,
                "verdict": indexed.verdict,
                "threatClasses": list(indexed.threat_classes),
                "audit": ("audited" if agent.agent_id in audited_agent_ids else "not-audited"),
                "apa": ("attested" if agent.agent_id in attested_agent_ids else "not-attested"),
            }
        )
    return {
        "schemaVersion": 1,
        "capturedAt": coverage.captured_at,
        "sampled": coverage.sampled,
        "hasAudits": bool(audited_agent_ids),
        "hasAttestations": bool(attested_agent_ids),
        "records": records,
    }


def _render_index_page(
    indexed_agents: list[IndexedAgent],
    coverage: SnapshotMetadata,
    summary: RenderSummary,
    audited_agent_ids: set[str],
    attested_agent_ids: set[str],
) -> str:
    snapshot_date = coverage.captured_at[:10]
    sorted_agents = _sorted_indexed_agents(indexed_agents)
    listed_agents = sorted_agents[:MARKETPLACE_INDEX_ROW_LIMIT]
    categories = sorted(
        {category for indexed in sorted_agents for category in indexed.agent.category_codes}
    )
    options = "".join(
        f'<option value="{_escape(category)}">{_escape(category)}</option>'
        for category in categories
    )
    has_audits = bool(audited_agent_ids)
    has_attestations = bool(attested_agent_ids)
    has_endpoint_evidence = has_audits or has_attestations
    rows = []
    for indexed in listed_agents:
        agent = indexed.agent
        match_state, public_text_label = _public_text_status(indexed)
        audit_state = "audited" if agent.agent_id in audited_agent_ids else "not-audited"
        audit_label = (
            "Linked signed endpoint audit record"
            if audit_state == "audited"
            else "No linked endpoint audit record"
        )
        apa_label = (
            "Linked signed APA guard proof"
            if agent.agent_id in attested_agent_ids
            else "No linked APA guard proof"
        )
        apa_state = "attested" if agent.agent_id in attested_agent_ids else "not-attested"
        categories_text = ", ".join(agent.category_codes) or "Uncategorized"
        category_data = "|".join(agent.category_codes)
        search_parts = [
            agent.agent_id,
            agent.name,
            categories_text,
            public_text_label,
            " ".join(indexed.threat_classes),
        ]
        if has_audits:
            search_parts.append(audit_label)
        if has_attestations:
            search_parts.append(apa_label)
        search_text = " ".join(search_parts)
        sold_sort = "" if agent.sold_count is None else str(agent.sold_count)
        review_sort = "" if agent.security_rate is None else str(agent.security_rate)
        sold_label = (
            f"Sold at {snapshot_date} snapshot"
            if agent.agent_id == WARDEN_MARKETPLACE_AGENT_ID
            else "Sold"
        )
        buyer_review_label = (
            f"Buyer review at {snapshot_date} snapshot"
            if agent.agent_id == WARDEN_MARKETPLACE_AGENT_ID
            else "Buyer review average"
        )
        buyer_review_data_label = (
            buyer_review_label if agent.agent_id == WARDEN_MARKETPLACE_AGENT_ID else "Buyer reviews"
        )
        row_label_parts = [
            f"Agent: {agent.name or 'Unnamed agent'}",
            f"Agent ID: {agent.agent_id}",
            f"Category: {categories_text}",
            f"{sold_label}: {_number(agent.sold_count)}",
            f"Public listing text: {public_text_label}",
        ]
        if has_audits:
            row_label_parts.append(f"Endpoint audit record: {audit_label}")
        if has_attestations:
            row_label_parts.append(f"APA attestation: {apa_label}")
        row_label_parts.append(f"{buyer_review_label}: {_buyer_review(agent.security_rate)}")
        row_label = "; ".join(row_label_parts)
        if has_audits and has_attestations:
            endpoint_evidence = (
                f'<span data-label="Endpoint evidence"><strong>{audit_label}</strong>'
                f"<small>{apa_label}</small></span>"
            )
        elif has_audits:
            endpoint_evidence = (
                f'<span data-label="Endpoint evidence"><strong>{audit_label}</strong></span>'
            )
        elif has_attestations:
            endpoint_evidence = (
                f'<span data-label="Endpoint evidence"><strong>{apa_label}</strong></span>'
            )
        else:
            endpoint_evidence = ""
        row_class = "agent-row" if has_endpoint_evidence else "agent-row agent-row--no-evidence"
        rows.append(
            f"""<a class="{row_class}" href="/agents/{_escape(agent.agent_id)}" aria-label="{_escape(row_label)}" data-agent-row data-search="{_escape(search_text)}" data-category="{_escape(category_data)}" data-match="{match_state}" data-audit="{audit_state}" data-apa="{apa_state}" data-name="{_escape(agent.name.casefold())}" data-agent-id="{_escape(agent.agent_id)}" data-sold="{sold_sort}" data-review="{review_sort}">
  <span><strong{_language_attribute(agent.name)}>{_escape(agent.name or "Unnamed agent")}</strong><small>Agent #{_escape(agent.agent_id)}</small></span>
  <span data-label="Category">{_escape(categories_text)}</span>
  <span class="num" data-label="{_escape(sold_label)}">{_number(agent.sold_count)}</span>
  <span data-label="Public text"><strong>{_escape(public_text_label)}</strong></span>
  {endpoint_evidence}
  <span class="num" data-label="{_escape(buyer_review_data_label)}">{_buyer_review(agent.security_rate)}</span>
</a>"""
        )

    agent_label = "agent" if summary.sampled == 1 else "agents"
    loaded_count = len(listed_agents)
    # A dated snapshot is a valid point-in-time capture. OKX marketplace pagination is
    # not fully stable across pages, so a crawl routinely misses a small fraction of the
    # reported total; that is normal upstream noise, not a degraded fetch. Reserve DEGRADED
    # for a genuinely incomplete crawl (<99% captured) or disagreeing counts (sampled>expected).
    # The coverage note always states the exact sampled/expected/dropped figures either way.
    complete_response = coverage.sampled == coverage.expected and coverage.dropped == 0
    captured_ratio = coverage.sampled / coverage.expected if coverage.expected else 0.0
    source_state = (
        "DATED"
        if complete_response
        or (coverage.sampled <= coverage.expected and captured_ratio >= MARKETPLACE_COMPLETE_RATIO)
        else "DEGRADED"
    )
    audit_control = (
        "<label>Endpoint audit record<select data-agent-audit>"
        '<option value="">All record states</option>'
        '<option value="audited">Linked signed endpoint audit record</option>'
        '<option value="not-audited">No linked endpoint audit record</option></select></label>'
        if has_audits
        else '<select data-agent-audit hidden><option value=""></option></select>'
    )
    apa_control = (
        '<label>APA guard proof<select data-agent-apa><option value="">All guard-proof states</option>'
        '<option value="attested">Linked signed guard proof</option>'
        '<option value="not-attested">No linked guard proof</option></select></label>'
        if has_attestations
        else '<select data-agent-apa hidden><option value=""></option></select>'
    )
    audit_sort_option = (
        '<option value="audit-first">Linked endpoint audit records first</option>'
        if has_audits
        else ""
    )
    audit_summary = (
        f'<div><dt>Linked endpoint audit records</dt><dd class="num">'
        f"{summary.audited_count}</dd></div>"
        if has_audits
        else ""
    )
    endpoint_header = "<span>Endpoint evidence</span>" if has_endpoint_evidence else ""
    header_class = (
        "agent-row agent-row--header"
        if has_endpoint_evidence
        else "agent-row agent-row--header agent-row--no-evidence"
    )
    if loaded_count < summary.sampled:
        loaded_note = (
            f"First {loaded_count} of {summary.sampled} snapshot records are shown. "
            "Search, filters, sorting, and Show more load the complete dated index."
        )
        no_script_note = (
            f"The first {loaded_count} of {summary.sampled} snapshot records are listed below."
        )
        search_placeholder = f"Search all {summary.sampled} records"
    else:
        loaded_note = f"All {summary.sampled} snapshot records are loaded."
        no_script_note = "All records in this dated snapshot are listed below."
        search_placeholder = "Name, agent ID, category, or signal"

    body = f"""
<section class="index-hero">
  <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Home</a><span aria-hidden="true">/</span><span>Marketplace Evidence Index</span></nav>
  <h1>Marketplace Evidence Index</h1>
  <p class="hero-text"><span class="num">{summary.sampled}</span> {agent_label} in this dated discovery response. Browse what the marketplace published and what Warden found in that public text. This is not a safety ranking.</p>
  <span class="source-stamp" data-source-stamp="{source_state}"><span data-source-stamp-label>{source_state}</span></span>
  <dl class="snapshot-summary data-list" aria-label="Marketplace evidence snapshot">
    <div><dt>Captured</dt><dd><time datetime="{_escape(coverage.captured_at)}">{_escape(coverage.captured_at)}</time></dd></div>
    <div><dt>Sampled</dt><dd class="num">{summary.sampled}</dd></div>
    <div><dt>Expected discovery total</dt><dd class="num">{summary.expected}</dd></div>
    <div><dt>Missing or degraded</dt><dd class="num">{summary.dropped}</dd></div>
    <div><dt>Public-text signals</dt><dd class="num">{summary.matched_count}</dd></div>
    {audit_summary}
  </dl>
  <p class="caveat"><strong>Public listing text only.</strong> Warden did not call these agents. A pattern match is not evidence that an agent is malicious, compromised, or unsafe.</p>
  <p class="snapshot-note">{_escape(_coverage_text(coverage))}</p>
</section>
<section class="filter-bar marketplace-filter-bar" data-agent-controls hidden aria-label="Search, filter, and sort agents">
  <label>Search records<input type="search" data-agent-search autocomplete="off" placeholder="{search_placeholder}"></label>
  <label>Category<select data-agent-category><option value="">All categories</option>{options}</select></label>
  <label>Public-text result<select data-agent-match><option value="">All text results</option><option value="signal">Pattern match</option><option value="none">No pattern match</option><option value="unscanned">No public text to scan</option></select></label>
  {audit_control}
  {apa_control}
  <label>Sort<select data-agent-sort><option value="sold-desc">Sold count, high to low</option><option value="name-asc">Name, A to Z</option><option value="review-desc">Buyer review, high to low</option><option value="signal-first">Public-text signals first</option>{audit_sort_option}</select></label>
  <button class="button secondary" type="button" data-agent-reset>Clear filters</button>
</section>
<section aria-labelledby="marketplace-results-title">
  <h2 id="marketplace-results-title">Snapshot records</h2>
  <p class="snapshot-note" aria-live="polite" aria-atomic="true">Showing <span class="num" data-agent-rendered>{loaded_count}</span> of <span class="num" data-agent-visible>{loaded_count}</span> matching records. <span data-agent-scope>{_escape(loaded_note)}</span></p>
  <p class="snapshot-note" data-agent-index-state hidden aria-live="polite"></p>
  <button class="button secondary" type="button" data-agent-index-retry hidden>Retry full index</button>
  <noscript><p class="snapshot-note">Search and filter controls require JavaScript. {_escape(no_script_note)}</p></noscript>
  <div class="agent-ledger">
  <div class="{header_class}" aria-hidden="true"><span>Agent</span><span>Category</span><span>Sold at {snapshot_date} snapshot</span><span>Public listing text</span>{endpoint_header}<span>Buyer review at {snapshot_date} snapshot</span></div>
  <div data-agent-results data-agent-total="{summary.sampled}" data-agent-captured-at="{_escape(coverage.captured_at)}">{"".join(rows)}</div>
  </div>
  <button class="button secondary" type="button" data-agent-more hidden>Show more agents</button>
  <p class="empty-state" data-agent-empty hidden>No loaded records match these filters. Clear a filter to restore this page.</p>
</section>
<details class="methodology-drawer" id="methodology">
  <summary>How this index was produced</summary>
  <div class="feature-panel">
    <h2>What the index checks</h2>
    <p>Warden runs its deterministic fast path over the public profile and service descriptions captured in the dated marketplace snapshot.</p>
    <h3>What this does not mean</h3>
    <p>The index does not call agent endpoints, inspect private prompts, prove ownership, establish intent, or provide continuous monitoring. “No public-text pattern match” means only that no implemented fast detector fired on the captured listing fields.</p>
    <h3>Endpoint audit records</h3>
    <p>“Linked signed endpoint audit record” requires a valid Warden record, a reviewed audit-to-agent link, and a matching listed-service host. A record is point-in-time evidence, not certification.</p>
    <p><a class="button secondary" href="/hire">Configure an authorized endpoint audit</a></p>
    <p class="caveat">Audit only a public endpoint you own or are authorized to test. A returned result is not independent proof of target-owner permission.</p>
    <h3>APA guard proofs</h3>
    <p>“Linked signed APA guard proof” requires a valid Warden issuer signature, a reviewed attestation-to-agent link, and a matching listed-service endpoint host. It is not an endpoint audit or security certification, and it does not prove every request traversed the guard.</p>
  </div>
</details>
"""
    return page_shell(
        "Marketplace Evidence Index | Warden",
        "Public listing-text scans for agents returned by the OKX.AI marketplace sweep.",
        body,
        active="agents",
        scripts=("agents.js",),
        body_class="page-archetype--marketplace",
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
            _census_provenance(coverage),
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
    index_data = _marketplace_index_data(
        indexed_agents,
        coverage,
        audited_agent_ids,
        attested_agent_ids,
    )
    (output_dir / "index-data.json").write_text(
        json.dumps(index_data, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return summary


def render_provider_page(
    indexed: IndexedAgent,
    output_dir: Path,
    *,
    fetched_at: str,
    in_census: bool,
    badge_records: list[dict[str, object]] | None = None,
    attestation_records: list[dict[str, object]] | None = None,
    apa_issuer_pub: str | None = None,
    apa_issuer_history: Sequence[ApaIssuerKey] = (),
) -> Path:
    """Write our own agent page from our own listing rather than from the census.

    `render_marketplace` deletes any agent page the census does not contain, so this runs
    after it. It writes only the page: the index and `index-data.json` stay a record of
    the public crawl, which genuinely does not list us while the listing is under review.
    """
    records = badge_records or []
    attestations = attestation_records or []
    if attestations and not apa_issuer_pub:
        raise ValueError("APA issuer public key is required to render attestation evidence")
    page = _render_agent_page(
        indexed,
        _provider_provenance(fetched_at, in_census=in_census),
        records,
        attestations,
        apa_issuer_pub or "",
        apa_issuer_history,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{indexed.agent.agent_id}.html"
    path.write_text(page, encoding="utf-8")
    return path
