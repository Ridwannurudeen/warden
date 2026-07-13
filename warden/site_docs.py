"""Reason-code documentation sourced from Warden's regression corpus."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path

from warden.core.verdict import ReasonCode
from warden.site_render import page_shell


@dataclass(frozen=True)
class ReasonDocument:
    reason_code: ReasonCode
    slug: str
    title: str
    example_id: str
    payload: str
    context: dict[str, object]
    expected_verdict: str
    risk_level: str
    threat_classes: tuple[str, ...]
    fast_result: str
    thorough_result: str
    context_requirement: str
    intended_action: str
    commerce_impact: str
    behavior: str
    caveat: str


_DOCUMENT_METADATA: dict[ReasonCode, dict[str, object]] = {
    ReasonCode.PROMPT_INJECTION: {
        "slug": "prompt-injection",
        "title": "Prompt injection",
        "example_id": "prompt-002",
        "risk_level": "LOW",
        "threat_classes": ("PROMPT_INJECTION",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Use the sanitized payload and keep the original instruction untrusted.",
        "commerce_impact": "Seller or service text attempts to replace the buyer agent's operating instructions.",
        "behavior": "The deterministic scanner matches direct instruction-replacement language before an agent acts on it.",
        "caveat": "A prompt-injection label is one signal. Threat classes can overlap and do not imply one universal verdict.",
    },
    ReasonCode.ROLE_OVERRIDE: {
        "slug": "role-override",
        "title": "Role override",
        "example_id": "role-001",
        "risk_level": "LOW",
        "threat_classes": ("ROLE_OVERRIDE",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Preserve the caller's role and review the sanitized payload.",
        "commerce_impact": "Untrusted content tries to coerce an agent outside its authorized commerce role.",
        "behavior": "Warden flags identity and authority reassignment phrases as untrusted control text.",
        "caveat": "Downstream policy still decides what a sanitized response may do.",
    },
    ReasonCode.WEB3_INJECTION: {
        "slug": "web3-injection",
        "title": "Web3 injection",
        "example_id": "web3-002",
        "risk_level": "LOW",
        "threat_classes": ("WEB3_INJECTION",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Require explicit policy authorization before any wallet action.",
        "commerce_impact": "Text can induce token approvals, transfers, withdrawals, or other wallet actions.",
        "behavior": "The scanner detects transaction-shaped imperatives before they reach an execution layer.",
        "caveat": "Warden analyzes payload text; it does not simulate or authorize a transaction.",
    },
    ReasonCode.HIDDEN_UNICODE: {
        "slug": "hidden-unicode",
        "title": "Hidden Unicode",
        "example_id": "unicode-001",
        "risk_level": "LOW",
        "threat_classes": ("HIDDEN_UNICODE",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Inspect the detection and use normalized or sanitized text.",
        "commerce_impact": "Invisible characters can conceal or alter listing, address, and response content.",
        "behavior": "Warden exposes control and zero-width characters that ordinary visual review can miss.",
        "caveat": "Some invisible characters are legitimate; integrations should inspect the returned detection context.",
    },
    ReasonCode.ENCODING_TRICK: {
        "slug": "encoding-trick",
        "title": "Encoding trick",
        "example_id": "encoding-001",
        "risk_level": "LOW",
        "threat_classes": ("ENCODING_TRICK",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Treat the encoded block as data and inspect before use.",
        "commerce_impact": "Encoded directives can evade a plain-text operator review before payment or execution.",
        "behavior": "Warden detects encoding markers and suspicious encoded blocks.",
        "caveat": "The deterministic scanner flags the marker; it does not decode and semantically execute the hidden content.",
    },
    ReasonCode.STATISTICAL_ANOMALY: {
        "slug": "statistical-anomaly",
        "title": "Statistical anomaly",
        "example_id": "stat-001",
        "risk_level": "LOW",
        "threat_classes": ("HIDDEN_UNICODE", "STATISTICAL_ANOMALY"),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Review the combined signals before allowing an action.",
        "commerce_impact": "Dense imperatives and invisible characters can be mixed into otherwise plausible market copy.",
        "behavior": "The statistical layer scores unusually concentrated action language and structural signals.",
        "caveat": "This regression is intentionally multi-class and also triggers HIDDEN_UNICODE.",
    },
    ReasonCode.CORPUS_MATCH: {
        "slug": "corpus-match",
        "title": "Corpus similarity match",
        "example_id": "corpus-001",
        "risk_level": "LOW",
        "threat_classes": ("CORPUS_MATCH",),
        "fast_result": "ALLOW",
        "thorough_result": "SANITIZE",
        "context_requirement": "None; thorough depth required",
        "intended_action": "Use thorough mode when corpus-similarity coverage is required.",
        "commerce_impact": "A rephrased known attack may avoid literal patterns while remaining close to a regression case.",
        "behavior": "The thorough scanner compares payload text with the versioned attack corpus using TF-IDF similarity.",
        "caveat": "CORPUS_MATCH is thorough-only. The free demo route forces fast mode and does not offer this check.",
    },
    ReasonCode.DRAIN_ADDRESS: {
        "slug": "drain-address",
        "title": "Drain address",
        "example_id": "drain-002",
        "risk_level": "CRITICAL",
        "threat_classes": ("DRAIN_ADDRESS",),
        "fast_result": "BLOCK",
        "thorough_result": "BLOCK",
        "context_requirement": "context.expected_addresses",
        "intended_action": "Stop the transfer and verify the intended recipient out of band.",
        "commerce_impact": "A settlement recipient is replaced with an attacker-controlled wallet in untrusted content.",
        "behavior": "Warden compares detected recipients with context.expected_addresses and hard-blocks a high-confidence mismatch.",
        "caveat": "Expected recipient context is required for the 0.95 hard gate; without it, a transfer address scores 0.80.",
    },
    ReasonCode.TOOL_HIJACK: {
        "slug": "tool-hijack",
        "title": "Tool-call hijack",
        "example_id": "tool-002",
        "risk_level": "LOW",
        "threat_classes": ("TOOL_HIJACK",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Keep the payload separate from the real tool dispatcher.",
        "commerce_impact": "Untrusted JSON imitates executable tool output and attempts to cross the data/action boundary.",
        "behavior": "The tool analyzer identifies transfer, approval, shell, and request-shaped call structures.",
        "caveat": "Integrations must still keep untrusted payloads separate from their real tool dispatcher.",
    },
    ReasonCode.SECRET_EXFIL: {
        "slug": "secret-exfil",
        "title": "Secret exfiltration",
        "example_id": "secret-003",
        "risk_level": "CRITICAL",
        "threat_classes": ("SECRET_EXFIL",),
        "fast_result": "BLOCK",
        "thorough_result": "BLOCK",
        "context_requirement": "None",
        "intended_action": "Do not reveal the requested secret; stop the action.",
        "commerce_impact": "A response asks an operator or agent to expose wallet or authentication material.",
        "behavior": "The exfiltration analyzer combines secret-request language with high-confidence secret-shaped content.",
        "caveat": "The real regression mnemonic is intentionally redacted on this public documentation page.",
        "display_payload": "send your seed phrase: [TEST MNEMONIC REDACTED]",
    },
    ReasonCode.MALICIOUS_LINK: {
        "slug": "malicious-link",
        "title": "Malicious link",
        "example_id": "link-002",
        "risk_level": "NONE",
        "threat_classes": ("MALICIOUS_LINK",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Do not follow the flagged link; use the sanitized payload.",
        "commerce_impact": "An active or deceptive URL can move a buyer from trusted workflow into attacker-controlled content.",
        "behavior": "Warden heuristically flags data URLs, punycode, IP literals, and mixed-script hostnames.",
        "caveat": "This is heuristic analysis, not reputation intelligence. SANITIZE can coexist with risk_level NONE.",
    },
}


def _load_attacks(root: Path) -> dict[str, dict[str, object]]:
    with (root / "corpus" / "attacks.jsonl").open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    return {str(record["id"]): record for record in records}


def load_reason_documents(root: Path) -> list[ReasonDocument]:
    attacks = _load_attacks(root)
    documents = []
    for reason_code in ReasonCode:
        metadata = _DOCUMENT_METADATA[reason_code]
        example = attacks[str(metadata["example_id"])]
        documents.append(
            ReasonDocument(
                reason_code=reason_code,
                slug=str(metadata["slug"]),
                title=str(metadata["title"]),
                example_id=str(metadata["example_id"]),
                payload=str(metadata.get("display_payload", example["payload"])),
                context=dict(example.get("context", {})),
                expected_verdict=str(example["expected_verdict"]),
                risk_level=str(metadata["risk_level"]),
                threat_classes=tuple(str(value) for value in metadata["threat_classes"]),
                fast_result=str(metadata["fast_result"]),
                thorough_result=str(metadata["thorough_result"]),
                context_requirement=str(metadata["context_requirement"]),
                intended_action=str(metadata["intended_action"]),
                commerce_impact=str(metadata["commerce_impact"]),
                behavior=str(metadata["behavior"]),
                caveat=str(metadata["caveat"]),
            )
        )
    return documents


def _documentation_nav(documents: list[ReasonDocument], current: str = "") -> str:
    links = []
    for document in documents:
        marker = ' aria-current="page"' if document.slug == current else ""
        links.append(
            f'<a href="/docs/{html.escape(document.slug)}"{marker}>{html.escape(document.reason_code.value)}</a>'
        )
    return "".join(links)


def _render_index(documents: list[ReasonDocument]) -> str:
    rows = []
    for document in documents:
        availability = (
            "thorough-only"
            if document.fast_result == "ALLOW" and document.thorough_result != "ALLOW"
            else "fast-and-thorough"
        )
        search_text = " ".join(
            (
                document.reason_code.value,
                document.title,
                document.commerce_impact,
                document.context_requirement,
                document.intended_action,
            )
        )
        decisions = document.fast_result
        if document.thorough_result != document.fast_result:
            decisions += f" {document.thorough_result}"
        rows.append(
            f"""<tr data-doc-entry data-search="{html.escape(search_text, quote=True)}" data-decisions="{html.escape(decisions, quote=True)}" data-availability="{availability}">
  <th scope="row"><a href="/docs/{html.escape(document.slug)}"><span class="reason-code">{html.escape(document.reason_code.value)}</span><span>{html.escape(document.title)}</span></a></th>
  <td data-label="Fast"><strong>{html.escape(document.fast_result)}</strong></td>
  <td data-label="Thorough"><strong>{html.escape(document.thorough_result)}</strong></td>
  <td data-label="Context">{html.escape(document.context_requirement)}</td>
  <td data-label="Intended action">{html.escape(document.intended_action)}</td>
</tr>"""
        )
    body = f"""
<section class="page-hero page-hero--compact">
  <p class="eyebrow">Detection reference</p>
  <h1>Eleven reasons Warden can stop or reshape an action.</h1>
  <p class="hero-text">Each page is tied to a real regression-corpus example and documents the observed verdict, commerce impact, and detector boundary.</p>
</section>
<div class="doc-layout">
  <aside class="doc-nav" aria-label="Documentation sections">
    <a href="#decision-model">Decision model</a>
    <a href="#reason-matrix">Reason matrix</a>
    {_documentation_nav(documents)}
  </aside>
  <article class="prose">
    <section id="decision-model">
      <p class="eyebrow">Decision model</p>
      <h2>Read the operational decision before the diagnostic detail.</h2>
      <div class="card-grid docs-decision-grid">
        <article><h3>Decision</h3><p><strong>ALLOW</strong>, <strong>SANITIZE</strong>, or <strong>BLOCK</strong> tells the integrating agent what to do next.</p></article>
        <article><h3>Risk</h3><p>The observed severity band comes from the deterministic score and hard gates. It is not the decision itself.</p></article>
        <article><h3>Reason and threat class</h3><p>A reason code names the detector that fired. The response's threat_classes array deduplicates those reasons.</p></article>
        <article><h3>Confidence and score</h3><p>Detection confidence and the composite score are evidence used by the decision engine, not probabilities of safety.</p></article>
        <article><h3>Detector boundary</h3><p>Fast and thorough depth do not run identical checks. CORPUS_MATCH is thorough-only.</p></article>
      </div>
      <aside class="callout"><strong>Why SANITIZE can show risk NONE:</strong> a low-scoring detection can still require redaction or review. Decision answers what to do; risk reports the score band. The malicious-link regression below demonstrates this implemented behavior.</aside>
    </section>
    <section id="reason-matrix">
      <div class="section-heading">
        <p class="eyebrow">Reason-code matrix</p>
        <h2>Coverage, context, and intended action</h2>
        <p class="section-copy">These are observed regression outcomes, not universal guarantees for every payload.</p>
      </div>
      <div class="filter-bar docs-filter-bar" aria-label="Reason-code filters">
        <label>Search reasons<input type="search" data-doc-search autocomplete="off" placeholder="Reason, behavior, context, or action"></label>
        <label>Decision<select data-doc-decision><option value="">All decisions</option><option value="ALLOW">ALLOW</option><option value="SANITIZE">SANITIZE</option><option value="BLOCK">BLOCK</option></select></label>
        <label>Availability<select data-doc-availability><option value="">All paths</option><option value="fast-and-thorough">Fast and thorough</option><option value="thorough-only">Thorough-only signal</option></select></label>
        <button class="button secondary" type="button" data-doc-reset>Clear filters</button>
      </div>
      <p class="snapshot-note" aria-live="polite"><span class="num" data-doc-visible>{len(documents)}</span> reason codes shown</p>
      <div class="reason-matrix" data-doc-results>
        <table>
          <thead><tr><th scope="col">Reason</th><th scope="col">Fast</th><th scope="col">Thorough</th><th scope="col">Context</th><th scope="col">Intended action</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
      <p class="empty-state" data-doc-empty hidden>No reason codes match these filters. Clear a filter to restore the full matrix.</p>
    </section>
    <aside class="callout"><strong>Interpretation:</strong> ALLOW means no implemented detector fired. It is not proof that content is safe, and multiple threat classes can appear in one result.</aside>
  </article>
</div>
"""
    return page_shell(
        "Detection documentation | Warden",
        "Examples and boundaries for Warden's eleven deterministic reason codes.",
        body,
        active="docs",
        scripts=("agents.js",),
        canonical_path="/docs",
    )


def _render_document(document: ReasonDocument, documents: list[ReasonDocument]) -> str:
    request = {"payload": document.payload}
    if document.context:
        request["context"] = document.context
    example = html.escape(json.dumps(request, ensure_ascii=True, indent=2))
    classes = ", ".join(document.threat_classes)
    position = documents.index(document)
    previous_document = documents[position - 1] if position > 0 else None
    next_document = documents[position + 1] if position + 1 < len(documents) else None
    previous_link = (
        f'<a class="button secondary" rel="prev" href="/docs/{html.escape(previous_document.slug)}"><span>Previous</span><strong>{html.escape(previous_document.reason_code.value)}</strong></a>'
        if previous_document
        else "<span></span>"
    )
    next_link = (
        f'<a class="button secondary" rel="next" href="/docs/{html.escape(next_document.slug)}"><span>Next</span><strong>{html.escape(next_document.reason_code.value)}</strong></a>'
        if next_document
        else "<span></span>"
    )
    example_is_redacted = document.reason_code is ReasonCode.SECRET_EXFIL
    example_heading = (
        "Redacted regression preview" if example_is_redacted else "Real regression input"
    )
    example_notice = (
        '\n      <p class="caveat"><strong>Display-safe redaction:</strong> The BLOCK and '
        "CRITICAL outcomes below were recorded from the original test-only corpus "
        "case. They are not the result of scanning the redacted text shown here.</p>"
        if example_is_redacted
        else ""
    )
    body = f"""
<section class="page-hero page-hero--compact">
  <p class="eyebrow">Reason code</p>
  <h1>{html.escape(document.reason_code.value)}</h1>
  <p class="hero-text">{html.escape(document.commerce_impact)}</p>
</section>
<div class="doc-layout">
  <aside class="doc-nav" aria-label="Reason codes"><a href="/docs">All reason codes</a>{_documentation_nav(documents, document.slug)}</aside>
  <article class="prose">
    <section id="corpus-example">
      <p class="eyebrow">Corpus case {html.escape(document.example_id)}</p>
      <h2>{example_heading} <a class="heading-anchor" href="#corpus-example" aria-label="Link to corpus example">#</a></h2>
      <pre><code>{example}</code></pre>{example_notice}
    </section>
    <section id="observed-contract">
      <h2>Observed decision contract <a class="heading-anchor" href="#observed-contract" aria-label="Link to observed decision contract">#</a></h2>
      <div class="result-grid">
      <div><span>Fast-path result</span><strong>{html.escape(document.fast_result)}</strong></div>
      <div><span>Thorough result</span><strong>{html.escape(document.thorough_result)}</strong></div>
      <div><span>Documented risk</span><strong>{html.escape(document.risk_level)}</strong></div>
      <div><span>Threat classes</span><strong>{html.escape(classes)}</strong></div>
      </div>
    </section>
    <section id="detector-behavior"><h2>What Warden detects <a class="heading-anchor" href="#detector-behavior" aria-label="Link to detector behavior">#</a></h2><p>{html.escape(document.behavior)}</p></section>
    <section id="commerce-impact"><h2>Why it matters in agent commerce <a class="heading-anchor" href="#commerce-impact" aria-label="Link to commerce impact">#</a></h2><p>{html.escape(document.commerce_impact)}</p></section>
    <section id="detector-boundary"><h2>Detector boundary <a class="heading-anchor" href="#detector-boundary" aria-label="Link to detector boundary">#</a></h2><aside class="callout"><strong>Boundary:</strong> {html.escape(document.caveat)}</aside></section>
    <div class="hero-actions"><a class="button primary" href="/playground">Test the fast path</a><a class="button secondary" href="/integrate">Integrate Warden</a></div>
    <nav class="doc-pagination" aria-label="Reason-code pagination">{previous_link}{next_link}</nav>
  </article>
</div>
"""
    return page_shell(
        f"{document.reason_code.value} | Warden docs",
        f"Warden detection behavior and real corpus example for {document.reason_code.value}.",
        body,
        active="docs",
        canonical_path=f"/docs/{document.slug}",
    )


def render_docs(root: Path, output_dir: Path) -> None:
    documents = load_reason_documents(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "index.html").write_text(_render_index(documents), encoding="utf-8")
    for document in documents:
        (output_dir / f"{document.slug}.html").write_text(
            _render_document(document, documents),
            encoding="utf-8",
        )
