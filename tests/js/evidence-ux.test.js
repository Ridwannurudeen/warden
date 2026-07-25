"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const SITE = path.join(__dirname, "..", "..", "site");
const ROUTES = [
  "badges.html",
  "badge.html",
  "verify.html",
  "log.html",
  "trust.html",
  "status.html",
];

function page(name) {
  return fs.readFileSync(path.join(SITE, name), "utf8");
}

test("evidence routes use the canonical direct site shell", () => {
  const expectedLinks = [
    ["/", "Product"],
    ["/playground", "Playground"],
    ["/theater", "Replay"],
    ["/hire", "Hire"],
    ["/integrate", "Developers"],
    ["/docs", "Docs"],
    ["/verify", "Evidence"],
    ["/gauntlet", "Research"],
  ];

  for (const name of ROUTES) {
    const html = page(name);
    const navigation = html.match(
      /<nav class="site-nav"[^>]*>([\s\S]*?)<\/nav>/,
    );
    assert.ok(navigation, name);
    assert.doesNotMatch(navigation[1], /nav-group|<summary>/, name);
    assert.deepEqual(
      [
        ...navigation[1].matchAll(
          /<a class="nav-link(?: is-active-section)?" href="([^"]+)"[^>]*>([^<]+)<\/a>/g,
        ),
      ].map((entry) => [entry[1], entry[2]]),
      expectedLinks,
      name,
    );
    assert.match(html, /src="\/assets\/warden-mark\.svg"/, name);
    assert.match(html, />Status unknown</);
    assert.match(html, /href="\/integrate">Integrate</);
    assert.match(
      html,
      /class="header-integrate" href="\/integrate">Integrate</,
    );
    assert.match(html, /href="\/playground">Run a live scan</);
    assert.doesNotMatch(html, /class="header-hire"/, name);
    assert.match(
      html,
      /<footer class="site-footer page-shell">\s*<div>\s*<strong>Warden<\/strong>\s*<span>Pre-action security for agent systems\.<\/span>\s*<\/div>/,
      `${name}: footer positioning`,
    );
    assert.match(
      html,
      /<span class="site-footer__label">Policy<\/span>[\s\S]*?href="\/trust">Trust &amp; security<\/a>[\s\S]*?href="\/privacy">Privacy<\/a>[\s\S]*?href="\/terms">Terms<\/a>/,
      `${name}: policy footer`,
    );
  }
  assert.match(
    page("verify.html"),
    /<a class="nav-link" href="\/verify" aria-current="page">Evidence<\/a>/,
  );
  for (const name of ["badges.html", "badge.html", "log.html", "status.html"]) {
    assert.match(
      page(name),
      /<a class="nav-link is-active-section" href="\/verify">Evidence<\/a>/,
      name,
    );
    assert.doesNotMatch(
      page(name).match(/<nav class="site-nav"[^>]*>([\s\S]*?)<\/nav>/)[1],
      /aria-current="page"/,
      name,
    );
  }
  assert.doesNotMatch(page("trust.html"), /class="nav-link"[^>]*aria-current/);
});

test("evidence routes expose explicit provenance without ambiguous placeholders", () => {
  for (const name of ROUTES) {
    const html = page(name);
    assert.match(html, /source-stamp/, name);
    assert.doesNotMatch(html, />\s*(?:Loading|Checking|--|—)\s*</, name);
  }
});

test("endpoint audit records remain bounded, searchable, and inspectable", () => {
  const registry = page("badges.html");
  const detail = page("badge.html");
  const script = page("badge.js");

  assert.match(registry, /data-badge-search/);
  assert.match(registry, /data-badge-integrity-filter/);
  assert.match(registry, /This is point-in-time evidence, not certification/);
  assert.ok(
    registry.indexOf("data-badge-registry") <
      registry.indexOf("What an audit record contains"),
  );
  assert.match(detail, /data-badge-raw-json/);
  assert.match(detail, /data-badge-evidence-type/);
  assert.match(detail, /data-badge-lifecycle/);
  assert.match(detail, /data-badge-subject/);
  assert.match(detail, /data-badge-expires/);
  assert.match(detail, /data-badge-battery/);
  assert.match(detail, /data-badge-battery-hash/);
  assert.match(detail, /data-badge-log-seq/);
  assert.match(detail, /data-badge-revoked/);
  assert.match(detail, /data-badge-limitations/);
  assert.match(detail, /expiry (?:and|or) revocation\s+status/);
  assert.match(script, /renderRegistryFilters/);
  assert.match(script, /\/apa\/audit\//);
  assert.match(script, /\/badge\//);
  assert.match(script, /JSON\.stringify\(rawRecord, null, 2\)/);
  assert.doesNotMatch(script, /innerHTML|insertAdjacentHTML|document\.write/);
});

test("attestation verifier offers explicit real-record and local-file paths", () => {
  const html = page("verify.html");
  const script = page("verify.js");

  for (const label of [
    "Parse",
    "Resolve key",
    "Verify",
    "Freshness",
    "Read boundary",
  ]) {
    assert.match(html, new RegExp(`>${label}<`));
  }
  assert.match(html, /data-apa-load-latest/);
  assert.match(html, /data-apa-verify-reference/);
  assert.match(html, /cross-language fixture dated 14 July 2026/);
  assert.match(html, /data-apa-verify-file/);
  assert.match(html, /maximum 256 KiB/i);
  assert.match(html, /A valid signature is not a safe-endpoint verdict/);
  assert.ok(
    html.indexOf('id="record-verifier"') <
      html.indexOf("How local verification works"),
  );
  assert.match(script, /loadLatestPublicAttestation/);
  assert.match(script, /verifySignedReference/);
  assert.match(script, /Logged APA identifiers are currently unavailable/);
  assert.match(script, /loadJsonFile/);
  assert.match(script, /form\.addEventListener\("drop"/);
});

test("transparency ledger exposes local recomputation and a one-byte challenge", () => {
  const html = page("log.html");
  const script = page("log.js");

  assert.match(html, /data-apa-log-checkpoint/);
  assert.match(html, /data-apa-log-raw/);
  assert.match(html, /data-apa-log-copy-raw/);
  assert.match(html, /data-apa-log-tamper/);
  assert.match(html, /endpoint audit lifecycle/i);
  assert.ok(
    html.indexOf('class="status-live-panel"') <
      html.indexOf("How chain continuity is checked"),
  );
  assert.match(script, /verifiedMaterial/);
  assert.match(script, /Local tamper rejected/);
  assert.match(script, /verifySignedLog\(\s*changed,/);
});

test("status and trust pages keep unlike evidence layers separate", () => {
  const status = page("status.html");
  const trust = page("trust.html");

  for (const hook of [
    "data-status-live-source",
    "data-monitor-source",
    "data-status-metadata-source",
    "data-status-marketplace-source",
    "data-status-corpus-source",
    "data-evaluation-source",
    "data-payment-source",
  ]) {
    assert.match(status, new RegExp(hook));
  }
  assert.match(status, /not\s+a\s+contractual SLA/);
  assert.match(status, />Historical uptime<\/span/);
  assert.match(status, />Not measured<\/strong/);
  for (const layer of [
    "Local enforcement",
    "Agent Protection Attestation",
    "Public transparency",
    "Dated context",
  ]) {
    assert.match(trust, new RegExp(layer));
  }
  assert.match(trust, /<table>/);
  assert.match(trust, /Warden evidence layers and their limits/);
  const layers = trust.match(
    /<section aria-labelledby="trust-stack-title">[\s\S]*?<\/section>/,
  );
  assert.ok(layers);
  assert.equal((layers[0].match(/<th scope="row">/g) || []).length, 4);
  assert.equal((trust.match(/class="badge-evidence"/g) || []).length, 0);
});
