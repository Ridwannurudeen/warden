"""Reason-code documentation sourced from Warden's regression corpus."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path

from warden import __version__
from warden.core.verdict import ReasonCode
from warden.site_render import page_shell


DOCS_LAST_UPDATED = "2026-07-18"


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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
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
        "risk_level": "MEDIUM",
        "threat_classes": ("MALICIOUS_LINK",),
        "fast_result": "SANITIZE",
        "thorough_result": "SANITIZE",
        "context_requirement": "None",
        "intended_action": "Do not follow the flagged link; use the sanitized payload.",
        "commerce_impact": "An active or deceptive URL can move a buyer from trusted workflow into attacker-controlled content.",
        "behavior": "Warden heuristically flags data URLs, punycode, IP literals, and mixed-script hostnames.",
        "caveat": "This is heuristic analysis, not reputation intelligence. A detection is calibrated to at least MEDIUM even when the composite score is lower.",
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
  <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Home</a><span aria-hidden="true">/</span><span>Documentation</span></nav>
  <h1>Warden documentation</h1>
  <p class="hero-text">Integrate the guard, handle its three decisions, and look up the exact detector that produced a result.</p>
  <p class="docs-metadata"><span>Documentation version <code>{html.escape(__version__)}</code></span><span>Last updated <time datetime="{DOCS_LAST_UPDATED}">{DOCS_LAST_UPDATED}</time></span></p>
</section>
<div class="doc-layout">
  <aside class="doc-nav" aria-label="Documentation sections">
    <a href="#quickstart">Quickstart</a>
    <a href="#reason-matrix">Reason matrix</a>
    <a href="#concepts">Concepts</a>
    <a href="#decision-contract">Decision contract</a>
    <a href="#integration-patterns">Integration patterns</a>
    <a href="#evidence-apa">Evidence and APA</a>
    <a href="#transparency">Transparency</a>
    <a href="#endpoint-audit">Endpoint audit</a>
    <a href="#limits">Limits</a>
    <a href="#troubleshooting">Troubleshooting</a>
    {_documentation_nav(documents)}
  </aside>
  <article class="prose">
    <nav class="table-of-contents" aria-label="On this page">
      <strong>On this page</strong>
      <a href="#quickstart">Quickstart</a><a href="#reason-matrix">Reason matrix</a><a href="#concepts">Concepts</a><a href="#decision-contract">Decision contract</a><a href="#integration-patterns">Integration patterns</a><a href="#evidence-apa">Evidence and APA</a><a href="#transparency">Transparency</a><a href="#endpoint-audit">Endpoint audit</a><a href="#limits">Limits</a><a href="#troubleshooting">Troubleshooting</a>
    </nav>
    <section id="quickstart">
      <h2>Quickstart <a class="heading-anchor" href="#quickstart" aria-label="Link to quickstart">#</a></h2>
      <p>Install both the repository root and the reference Python client from the same source checkout. The similarly named package on PyPI is unrelated.</p>
      <pre><code>python -m pip install -e . -e sdk/python

from warden_guard import WardenClient

safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)
execute(safe)</code></pre>
      <aside class="callout"><strong>Placement:</strong> call the guard immediately before payment, tool dispatch, link navigation, secret handling, or another consequential action. The caller keeps final authority.</aside>
    </section>
    <section id="reason-matrix">
      <div class="section-heading">
        <h2>Reason-code matrix</h2>
        <p class="section-copy">Observed regression outcomes for each implemented reason code. They are not guarantees for every payload.</p>
      </div>
      <div class="filter-bar docs-filter-bar" aria-label="Filter reason codes">
        <label>Filter reason codes<input type="search" data-doc-search autocomplete="off" placeholder="Code, behavior, context, or action"></label>
        <label>Decision<select data-doc-decision><option value="">All decisions</option><option value="ALLOW">ALLOW</option><option value="SANITIZE">SANITIZE</option><option value="BLOCK">BLOCK</option></select></label>
        <label>Availability<select data-doc-availability><option value="">All paths</option><option value="fast-and-thorough">Fast and thorough</option><option value="thorough-only">Thorough-only signal</option></select></label>
        <button class="button secondary" type="button" data-doc-reset>Clear filters</button>
      </div>
      <p class="snapshot-note" aria-live="polite"><span class="num" data-doc-visible>{len(documents)}</span> reason codes shown</p>
      <div class="reason-matrix" data-doc-results>
        <table>
          <caption>Implemented reason codes and observed regression outcomes</caption>
          <thead><tr><th scope="col">Reason</th><th scope="col">Fast</th><th scope="col">Thorough</th><th scope="col">Context</th><th scope="col">Caller action</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
      <p class="empty-state" data-doc-empty hidden>No reason codes match these filters. Clear a filter to restore the full matrix.</p>
    </section>
    <section id="concepts">
      <h2>Core concepts <a class="heading-anchor" href="#concepts" aria-label="Link to concepts">#</a></h2>
      <div class="docs-reference-table"><table>
        <caption>Core concepts and their operational meaning</caption>
        <tbody>
          <tr><th scope="row">Action boundary</th><td>Warden evaluates untrusted output before the caller invokes a consequential handler.</td></tr>
          <tr><th scope="row">Decision</th><td>ALLOW continues under caller policy, SANITIZE returns transformed text, and BLOCK withholds the proposed action.</td></tr>
          <tr><th scope="row">Evidence</th><td>A qualifying decision may produce a signed APA record separate from the live response.</td></tr>
          <tr><th scope="row">Signature boundary</th><td>A valid signature proves record integrity under the applicable key. It does not prove universal safety.</td></tr>
        </tbody>
      </table></div>
    </section>
    <section id="decision-contract">
      <h2>Decision model <a class="heading-anchor" href="#decision-contract" aria-label="Link to decision contract">#</a></h2>
      <div class="docs-reference-table"><table>
        <caption>Decision response fields and caller guidance</caption>
        <thead><tr><th scope="col">Field</th><th scope="col">How to use it</th></tr></thead>
        <tbody>
          <tr><th scope="row">Decision</th><td>ALLOW, SANITIZE, or BLOCK is the operational result.</td></tr>
          <tr><th scope="row">Risk</th><td>The severity band comes from deterministic scoring and hard gates; it is not the decision.</td></tr>
          <tr><th scope="row">Reason</th><td>The machine-readable code names the detector that fired. Threat classes deduplicate related reasons.</td></tr>
          <tr><th scope="row">Confidence and score</th><td>Diagnostic evidence used by the engine, not a probability of safety.</td></tr>
          <tr><th scope="row">Depth</th><td>Fast and thorough do not run identical checks. CORPUS_MATCH is thorough-only.</td></tr>
        </tbody>
      </table></div>
      <aside class="callout"><strong>Detected threats start at risk MEDIUM:</strong> a finding that changes or withholds an action is never presented as low severity. Decision answers what to do; risk communicates the calibrated review floor.</aside>
    </section>
    <aside class="callout"><strong>Interpretation:</strong> ALLOW means no implemented detector fired. It is not proof that content is safe, and multiple threat classes can appear in one result.</aside>
    <section id="integration-patterns">
      <h2>Integration patterns <a class="heading-anchor" href="#integration-patterns" aria-label="Link to integration patterns">#</a></h2>
      <p>Python supports local in-process enforcement. The source-built TypeScript client calls the hosted endpoint and has no local scanner engine. LangChain and LlamaIndex guards ship with the Python SDK; direct HTTP, x402, OnchainOS, and MCP paths are documented on the integration route.</p>
      <p><a class="button secondary" href="/integrate">Open exact integration contracts</a></p>
    </section>
    <section id="evidence-apa">
      <h2>Evidence and APA <a class="heading-anchor" href="#evidence-apa" aria-label="Link to evidence and APA">#</a></h2>
      <p>An Agent Protection Attestation binds a canonical record to an issuer signature. Local verification can establish whether the bytes match the signature under an applicable key. Freshness, revocation, subject identity, and issuer-key provenance remain separate checks.</p>
      <p><a href="/verify">Verify an attestation</a> · <a href="/spec/APA-SPEC.md">Read APA v0.1</a></p>
    </section>
    <section id="transparency">
      <h2>Transparency verification <a class="heading-anchor" href="#transparency" aria-label="Link to transparency verification">#</a></h2>
      <p>The public log exposes hash-chained entries and checkpoint state. A continuous unanchored chain detects local inconsistency, but cannot by itself expose a complete, internally consistent rewrite.</p>
      <p><a href="/apa/log">Inspect and recompute the log</a></p>
    </section>
    <section id="endpoint-audit">
      <h2>Endpoint audit contract <a class="heading-anchor" href="#endpoint-audit" aria-label="Link to endpoint audit contract">#</a></h2>
      <p>The endpoint service runs a fixed battery against a public endpoint the caller is authorized to test. Its output is point-in-time evidence, not certification, and does not predict every future response.</p>
      <p><a href="/badges">Review Endpoint Audit Records</a></p>
    </section>
    <section id="limits">
      <h2>Known patterns are not the full attack space <a class="heading-anchor" href="#limits" aria-label="Link to limits">#</a></h2>
      <ul><li>Fast and thorough depth do not run identical checks.</li><li>Novel phrasing can evade deterministic and corpus-backed coverage.</li><li>Expected-recipient context is required for the strongest recipient-mismatch gate.</li><li>Hosted availability and timeout policy belong in the caller's enforcement design.</li><li>Do not log pasted secrets or private payloads to analytics.</li></ul>
    </section>
    <section id="troubleshooting">
      <h2>Troubleshooting <a class="heading-anchor" href="#troubleshooting" aria-label="Link to troubleshooting">#</a></h2>
      <dl class="data-list"><div><dt>Timeout or network error</dt><dd>Fail closed on consequential paths, surface the unavailable state, and retry only under caller policy.</dd></div><div><dt>Malformed response</dt><dd>Reject it as unusable evidence; do not infer a verdict.</dd></div><div><dt>Unexpected ALLOW</dt><dd>Confirm depth, context, payload limits, and the documented detector boundary.</dd></div><div><dt>Invalid signature</dt><dd>Stop using the record and inspect version, issuer key, canonicalization, freshness, and revocation independently.</dd></div></dl>
    </section>
  </article>
</div>
"""
    return page_shell(
        "Detection documentation | Warden",
        "Examples and boundaries for Warden's eleven deterministic reason codes.",
        body,
        active="docs",
        scripts=("agents.js",),
        body_class="page-archetype--docs",
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
  <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Home</a><span aria-hidden="true">/</span><a href="/docs">Documentation</a><span aria-hidden="true">/</span><span>{html.escape(document.title)}</span></nav>
  <p class="record-kicker">Reason code · <code>{html.escape(document.reason_code.value)}</code></p>
  <h1>{html.escape(document.title)}</h1>
  <p class="hero-text">{html.escape(document.commerce_impact)}</p>
  <p class="docs-metadata"><span>Documentation version <code>{html.escape(__version__)}</code></span><span>Last updated <time datetime="{DOCS_LAST_UPDATED}">{DOCS_LAST_UPDATED}</time></span></p>
</section>
<div class="doc-layout">
  <aside class="doc-nav" aria-label="Reason codes"><a href="/docs">All reason codes</a>{_documentation_nav(documents, document.slug)}</aside>
  <article class="prose">
    <nav class="table-of-contents" aria-label="On this page">
      <strong>On this page</strong>
      <a href="#corpus-example">Corpus example</a><a href="#observed-contract">Observed contract</a><a href="#detector-behavior">Detector behavior</a><a href="#commerce-impact">Commerce impact</a><a href="#detector-boundary">Detector boundary</a><a href="#integration-guidance">Integration guidance</a>
    </nav>
    <section id="corpus-example">
      <h2>{example_heading} <a class="heading-anchor" href="#corpus-example" aria-label="Link to corpus example">#</a></h2>
      <p>Regression case <code>{html.escape(document.example_id)}</code></p>
      <pre><code>{example}</code></pre>{example_notice}
    </section>
    <section id="observed-contract">
      <h2>Observed decision contract <a class="heading-anchor" href="#observed-contract" aria-label="Link to observed decision contract">#</a></h2>
      <div class="docs-reference-table"><table>
        <caption>{html.escape(document.reason_code.value)} observed detector contract</caption>
        <tbody>
          <tr><th scope="row">Machine-readable value</th><td><strong><code>{html.escape(document.reason_code.value)}</code></strong></td></tr>
          <tr><th scope="row">Fast-path result</th><td><strong>{html.escape(document.fast_result)}</strong></td></tr>
          <tr><th scope="row">Thorough result</th><td><strong>{html.escape(document.thorough_result)}</strong></td></tr>
          <tr><th scope="row">Documented risk</th><td><strong>{html.escape(document.risk_level)}</strong></td></tr>
          <tr><th scope="row">Threat classes</th><td><strong>{html.escape(classes)}</strong></td></tr>
        </tbody>
      </table></div>
    </section>
    <section id="detector-behavior"><h2>What Warden detects <a class="heading-anchor" href="#detector-behavior" aria-label="Link to detector behavior">#</a></h2><p>{html.escape(document.behavior)}</p></section>
    <section id="commerce-impact"><h2>Why it matters in agent commerce <a class="heading-anchor" href="#commerce-impact" aria-label="Link to commerce impact">#</a></h2><p>{html.escape(document.commerce_impact)}</p></section>
    <section id="detector-boundary"><h2>Detector boundary <a class="heading-anchor" href="#detector-boundary" aria-label="Link to detector boundary">#</a></h2><h3>False-positive considerations</h3><aside class="callout"><strong>Boundary:</strong> {html.escape(document.caveat)}</aside></section>
    <section id="integration-guidance"><h2>Related integration guidance <a class="heading-anchor" href="#integration-guidance" aria-label="Link to integration guidance">#</a></h2><p>{html.escape(document.intended_action)}</p><p>Preserve the machine-readable reason value in decision logs, but do not treat it as a probability or a universal statement about the payload.</p></section>
    <div class="hero-actions"><a class="button primary" href="/playground">Test the fast path</a><a class="button secondary" href="/integrate">Integrate in 5 minutes</a></div>
    <nav class="doc-pagination" aria-label="Reason-code pagination">{previous_link}{next_link}</nav>
  </article>
</div>
"""
    return page_shell(
        f"{document.reason_code.value} | Warden docs",
        f"Warden detection behavior and real corpus example for {document.reason_code.value}.",
        body,
        active="docs",
        body_class="page-archetype--docs",
        canonical_path=f"/docs/{document.slug}",
    )


def render_docs(root: Path, output_dir: Path) -> None:
    documents = load_reason_documents(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    expected_pages = {"index.html", *(f"{document.slug}.html" for document in documents)}
    for page in output_dir.glob("*.html"):
        if page.name not in expected_pages:
            page.unlink()
    (output_dir / "index.html").write_text(_render_index(documents), encoding="utf-8")
    for document in documents:
        (output_dir / f"{document.slug}.html").write_text(
            _render_document(document, documents),
            encoding="utf-8",
        )
