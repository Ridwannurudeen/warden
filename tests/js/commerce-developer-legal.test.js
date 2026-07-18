"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..", "..");

function page(name) {
  return fs.readFileSync(path.join(root, "site", `${name}.html`), "utf8");
}

const shellPages = ["hire", "integrate", "privacy", "terms"];
const canonicalLinks = [
  ["/", "Overview"],
  ["/playground", "Live Playground"],
  ["/theater", "Attack Theater"],
  ["/hire", "Use Warden"],
  ["/integrate#sdk-first", "5-Minute Quickstart"],
  ["/integrate", "Integrations"],
  ["/docs", "Documentation"],
  ["/verify", "Verify an Attestation"],
  ["/apa/log", "Transparency Log"],
  ["/badges", "Endpoint Audit Records"],
  ["/agents", "Marketplace Evidence Index"],
  ["/status", "Service Status"],
  ["/gauntlet", "Gauntlet"],
  ["/agents#methodology", "Methodology"],
  ["/showcase", "Product Tour"],
];

test("commerce, developer, and legal routes use the canonical site shell", () => {
  for (const name of shellPages) {
    const html = page(name);

    for (const group of ["Product", "Developers", "Evidence", "Research"]) {
      assert.match(html, new RegExp(`<summary>${group}</summary>`), name);
    }
    for (const [href, label] of canonicalLinks) {
      const escapedHref = href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      assert.match(
        html,
        new RegExp(`<a href="${escapedHref}"[^>]*>${label}</a>`),
        `${name}: ${label}`,
      );
    }

    assert.match(html, /aria-label="Service status: unknown"/, name);
    assert.match(html, /data-health-label>Status unknown</, name);
    assert.match(
      html,
      /class="header-hire" href="\/integrate">Integrate</,
      name,
    );
    assert.match(
      html,
      /class="header-scan" href="\/playground">Run live scan</,
      name,
    );
    assert.match(html, /site-footer__label">Policy</, name);
    assert.match(html, /href="\/trust">Trust &amp; Security<\/a>/, name);
    assert.match(html, /href="\/privacy">Privacy<\/a>/, name);
    assert.match(html, /href="\/terms">Terms<\/a>/, name);
    assert.match(
      html,
      /href="https:\/\/www\.okx\.ai\/" rel="noreferrer">Agent #3808<\/a>/,
      name,
    );
    assert.doesNotMatch(
      html,
      />\s*(?:Loading(?:[^<]*)?|Checking(?:[^<]*)?|--|—)\s*</i,
      name,
    );
  }
});

test("every static route uses the canonical footer brand contract", () => {
  for (const name of [
    "gauntlet",
    "hire",
    "integrate",
    "playground",
    "privacy",
    "showcase",
    "terms",
    "theater",
  ]) {
    const html = page(name);
    const footer = html.match(
      /<footer class="site-footer page-shell">([\s\S]*?)<\/footer>/,
    );

    assert.ok(footer, name);
    assert.match(
      footer[1],
      /Verifiable pre-action security for AI agents\./,
      name,
    );
    assert.match(footer[1], /Gate the action\. Keep the proof\./, name);
    assert.doesNotMatch(footer[1], /immune system of the agent economy/i, name);
  }
});

test("Use Warden exposes four explicit operator boundaries and a persistent summary", () => {
  const html = page("hire");

  assert.match(html, /<title>Use Warden \| Warden<\/title>/);
  assert.match(html, /<h1>Use Warden\.<\/h1>/);
  assert.match(html, /data-purchase-summary/);
  for (const hook of [
    "data-summary-job",
    "data-summary-reviewer",
    "data-service-endpoint",
    "data-service-recipient",
    "data-service-price",
    "data-summary-payment",
    "data-summary-signing",
  ]) {
    assert.match(html, new RegExp(hook), hook);
  }
  assert.match(html, /<details[^>]*data-hire-advanced/);
  assert.match(html, /Advanced and optional fields/);
  assert.match(html, /data-copy-status[^>]*aria-live="polite"/);
  assert.match(html, /data-hire-catalog-stamp[^>]*data-source-stamp="UNKNOWN"/);
  assert.match(
    html,
    /data-hire-challenge-stamp[^>]*data-source-stamp="UNKNOWN"/,
  );
  assert.equal((html.match(/data-command-stage="/g) || []).length, 4);
  assert.match(
    html,
    /website\s+never\s+receives\s+wallet\s+credentials\s+or\s+signing\s+material/i,
  );
});

test("Integrations starts with an exact five-minute path and documents every supported boundary", () => {
  const html = page("integrate");

  assert.match(html, /id="sdk-first"/);
  assert.match(html, /data-five-minute-path/);
  for (const marker of ["0–1 min", "1–2 min", "2–4 min", "4–5 min"]) {
    assert.match(html, new RegExp(marker), marker);
  }
  assert.match(html, /python -m pip install -e \. -e sdk\/python/);
  assert.match(html, /npm ci/);
  assert.match(html, /Receive[\s\S]*Scan[\s\S]*Decide[\s\S]*Act/);
  for (const surface of [
    "OnchainOS",
    "Raw x402",
    "Python",
    "TypeScript",
    "MCP",
    "LangChain",
    "LlamaIndex",
    "FastAPI",
    "TextGuard",
  ]) {
    assert.match(html, new RegExp(surface), surface);
  }
  assert.match(
    html,
    /data-integrate-catalog-stamp[^>]*data-source-stamp="UNKNOWN"/,
  );
  assert.match(html, /Fail open/i);
  assert.match(html, /Fail closed/i);
  assert.match(html, /8 seconds/);
  assert.match(html, /30 seconds/);
  assert.match(html, /Do not automatically retry a paid replay/i);
  assert.match(html, /wallet/i);
  assert.match(html, /secrets/i);
  assert.match(html, /privacy/i);
  assert.match(html, /data-copy-status[^>]*aria-live="polite"/);
});

test("legal routes are dated, deep-linkable, cross-linked, and print-semantic", () => {
  const privacy = page("privacy");
  const terms = page("terms");

  for (const [name, html, peerHref] of [
    ["privacy", privacy, "/terms"],
    ["terms", terms, "/privacy"],
  ]) {
    assert.match(html, /class="breadcrumbs"[^>]*aria-label="Breadcrumb"/, name);
    assert.match(html, /data-print-document/, name);
    assert.match(
      html,
      /<time datetime="2026-07-18">18 July 2026<\/time>/,
      name,
    );
    assert.match(html, /class="doc-nav legal-nav"[^>]*aria-label=/, name);
    assert.match(html, new RegExp(`href="${peerHref}"`), name);
  }

  for (const id of [
    "browser-data",
    "scans-audits",
    "feedback-retention",
    "gauntlet-retention",
    "public-records",
    "operational-metadata",
    "independent-service",
  ]) {
    assert.match(privacy, new RegExp(`href="#${id}"`));
    assert.match(privacy, new RegExp(`id="${id}"`));
  }
  for (const id of [
    "service-surfaces",
    "decision-boundary",
    "authorized-audits",
    "gauntlet-submissions",
    "feedback-submissions",
    "badge-records",
    "payments",
    "availability",
    "disclaimer",
  ]) {
    assert.match(terms, new RegExp(`href="#${id}"`));
    assert.match(terms, new RegExp(`id="${id}"`));
  }
});
