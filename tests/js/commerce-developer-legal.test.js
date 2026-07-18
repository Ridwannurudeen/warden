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
  ["/", "Product"],
  ["/playground", "Playground"],
  ["/integrate", "Developers"],
  ["/docs", "Docs"],
  ["/verify", "Evidence"],
  ["/gauntlet", "Research"],
];

test("commerce, developer, and legal routes use the canonical site shell", () => {
  for (const name of shellPages) {
    const html = page(name);

    const navigation = html.match(
      /<nav class="site-nav"[^>]*>([\s\S]*?)<\/nav>/,
    );
    assert.ok(navigation, name);
    assert.doesNotMatch(navigation[1], /nav-group|<summary>/, name);
    for (const [href, label] of canonicalLinks) {
      const escapedHref = href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      assert.match(
        navigation[1],
        new RegExp(
          `<a class="nav-link" href="${escapedHref}"[^>]*>${label}</a>`,
        ),
        `${name}: ${label}`,
      );
    }

    assert.match(html, /src="\/assets\/warden-mark\.svg"/, name);
    assert.match(html, /aria-label="Service status: unknown"/, name);
    assert.match(html, /data-health-label>Status unknown</, name);
    assert.doesNotMatch(html, /class="header-hire"/, name);
    assert.match(
      html,
      /class="header-scan" href="\/playground">Run a live scan</,
      name,
    );
    assert.match(html, /site-footer__label">Policy</, name);
    assert.match(html, /href="\/trust">Trust &amp; security<\/a>/, name);
    assert.match(html, /href="\/privacy">Privacy<\/a>/, name);
    assert.match(html, /href="\/terms">Terms<\/a>/, name);
    assert.doesNotMatch(
      html,
      />\s*(?:Loading(?:[^<]*)?|Checking(?:[^<]*)?|--|—)\s*</i,
      name,
    );
  }
  assert.match(
    page("hire"),
    /<a class="nav-link" href="\/" aria-current="page">Product<\/a>/,
  );
  assert.match(
    page("integrate"),
    /<a class="nav-link" href="\/integrate" aria-current="page">Developers<\/a>/,
  );
  for (const name of ["privacy", "terms"]) {
    assert.doesNotMatch(page(name), /class="nav-link"[^>]*aria-current/, name);
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
    assert.match(footer[1], /Pre-action security for agent systems\./, name);
    assert.equal(
      (footer[1].split("<nav", 1)[0].match(/<span>/g) || []).length,
      1,
      name,
    );
    assert.doesNotMatch(footer[1], /immune system of the agent economy/i, name);
  }
});

test("Use Warden exposes four explicit operator boundaries and a persistent summary", () => {
  const html = page("hire");

  assert.match(html, /<title>Use Warden \| Warden<\/title>/);
  assert.match(html, /<h1>Choose a Warden service<\/h1>/);
  assert.match(html, /data-purchase-summary/);
  assert.ok(
    html.indexOf("data-hire-service") < html.indexOf('class="readiness-panel"'),
  );
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
  assert.match(html, /Recommended: local Python guard/);
  assert.match(
    html,
    /<summary>Hosted Python and TypeScript SDK modes<\/summary>/,
  );
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

  assert.match(privacy, /<title>Data handling summary \| Warden<\/title>/);
  assert.match(privacy, /not a complete\s+legal privacy notice/);
  assert.match(terms, /<title>Service terms summary \| Warden<\/title>/);
  assert.match(terms, /not a complete\s+legal contract/);

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
