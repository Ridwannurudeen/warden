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

test("evidence routes use the canonical four-group information architecture", () => {
  const expectedGroups = {
    Product: ["/", "/playground", "/theater", "/hire"],
    Developers: ["/integrate#sdk-first", "/integrate", "/docs"],
    Evidence: ["/verify", "/apa/log", "/badges", "/agents", "/status"],
    Research: ["/gauntlet", "/agents#methodology", "/showcase"],
  };

  for (const name of ROUTES) {
    const html = page(name);
    for (const [group, hrefs] of Object.entries(expectedGroups)) {
      const match = html.match(
        new RegExp(
          `<details class="nav-group[^"]*">\\s*<summary>${group}</summary>\\s*<div class="nav-menu">([\\s\\S]*?)</div>`,
        ),
      );
      assert.ok(match, `${name}: ${group}`);
      assert.deepEqual(
        [...match[1].matchAll(/href="([^"]+)"/g)].map((entry) => entry[1]),
        hrefs,
        `${name}: ${group}`,
      );
    }
    assert.match(html, />Status unknown</);
    assert.match(html, /href="\/integrate">Integrate</);
    assert.match(html, /href="\/playground">Run live scan</);
    assert.match(
      html,
      /<span class="site-footer__label">Policy<\/span>[\s\S]*?href="\/trust">Trust &amp; Security<\/a>[\s\S]*?href="\/privacy">Privacy<\/a>[\s\S]*?href="\/terms">Terms<\/a>/,
      `${name}: policy footer`,
    );
  }
  assert.doesNotMatch(
    page("trust.html"),
    /<details class="nav-group has-current">\s*<summary>Evidence<\/summary>/,
  );
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
  assert.match(detail, /expiry and revocation\s+status/);
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
  assert.match(html, /dated cross-language fixture/);
  assert.match(html, /data-apa-verify-file/);
  assert.match(html, /maximum 256 KiB/);
  assert.match(html, /A valid signature is not a safe-endpoint verdict/);
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
  assert.match(status, /not a contractual SLA/);
  assert.match(status, />Historical uptime<\/span/);
  assert.match(status, />Not measured<\/strong/);
  for (const layer of [
    "Caller-side enforcement",
    "Signed APA evidence",
    "Public transparency",
    "Dated context",
  ]) {
    assert.match(trust, new RegExp(layer));
  }
  assert.equal((trust.match(/<dt>What it proves<\/dt>/g) || []).length, 4);
  assert.equal(
    (trust.match(/<dt>What it does not prove<\/dt>/g) || []).length,
    4,
  );
  assert.equal((trust.match(/<dt>Who verifies it<\/dt>/g) || []).length, 4);
  assert.equal((trust.match(/<dt>Where to inspect<\/dt>/g) || []).length, 4);
});
