"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const appApi = require(path.join(__dirname, "..", "..", "site", "app.js"));
const appSource = fs.readFileSync(
  path.join(__dirname, "..", "..", "site", "app.js"),
  "utf8",
);
const themeInitializer = fs.readFileSync(
  path.join(__dirname, "..", "..", "site", "theme.js"),
  "utf8",
);

const {
  applyAsyncPanelState,
  applySourceStamp,
  catalogServiceByKey,
  copyButtonBaseLabel,
  cycleFocusIndex,
  focusStatusTarget,
  healthStatusPresentation,
  homeProofEvidence,
  isHealthyResponse,
  isOutsideNavigationPointer,
  marketplaceCoverageText,
  normalizeAsyncPanelState,
  normalizeEvidenceCount,
  normalizeMarketplaceSummary,
  normalizeProductProof,
  resolveTheme,
  sourceStampPresentation,
} = appApi;

const productProof = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "data", "product-proof.json"),
    "utf8",
  ),
);

test("theme resolution respects a stored choice and otherwise defaults to dark", () => {
  assert.equal(resolveTheme("light", false), "light");
  assert.equal(resolveTheme("dark", true), "dark");
  assert.equal(resolveTheme(null, true), "dark");
  assert.equal(resolveTheme(null, false), "dark");
});

test("early theme initialization applies persisted choices and defaults to dark", () => {
  for (const [storedTheme, expectedTheme] of [
    ["light", "light"],
    ["dark", "dark"],
    ["unsupported", "dark"],
    [null, "dark"],
  ]) {
    const document = { documentElement: { dataset: {} } };
    vm.runInNewContext(themeInitializer, {
      document,
      localStorage: {
        getItem(key) {
          assert.equal(key, "warden-theme");
          return storedTheme;
        },
      },
    });
    assert.equal(document.documentElement.dataset.theme, expectedTheme);
  }
});

test("early theme initialization stays dark when storage is unavailable", () => {
  const document = { documentElement: { dataset: {} } };
  vm.runInNewContext(themeInitializer, {
    document,
    localStorage: {
      getItem() {
        throw new Error("Storage denied");
      },
    },
  });
  assert.equal(document.documentElement.dataset.theme, "dark");
});

test("shared app consumes the theme already initialized on the root element", () => {
  assert.match(
    appSource,
    /resolveTheme\(\s*document\.documentElement\.dataset\.theme,\s*false,\s*\)/,
  );
  assert.doesNotMatch(appSource, /localStorage\.getItem\("warden-theme"\)/);
});

test("header reachability accepts only the documented healthy response", () => {
  assert.equal(isHealthyResponse({ status: "ok" }), true);
  assert.equal(isHealthyResponse({ status: "degraded" }), false);
  assert.equal(isHealthyResponse({}), false);
  assert.equal(isHealthyResponse(null), false);
});

test("source stamps normalize the five honest evidence states", () => {
  const expected = {
    LIVE: "Observed live in this browser session.",
    DATED: "Dated snapshot; not a live claim.",
    ILLUSTRATIVE: "Illustrative example; not observed evidence.",
    DEGRADED: "Source is incomplete or currently degraded.",
    UNKNOWN: "Source state has not been established.",
  };

  for (const [state, description] of Object.entries(expected)) {
    assert.deepEqual(sourceStampPresentation(state.toLowerCase()), {
      state,
      label: state,
      description,
    });
  }
  assert.equal(sourceStampPresentation("unsupported").state, "UNKNOWN");
  assert.equal(sourceStampPresentation(null).state, "UNKNOWN");
});

test("source-stamp behavior updates state, visible label, and accessible copy", () => {
  const label = { textContent: "" };
  const attributes = new Map();
  const classes = new Set(["source-stamp", "source-stamp--unknown"]);
  const stamp = {
    dataset: { sourceStamp: "dated" },
    classList: {
      add(...values) {
        values.forEach((value) => classes.add(value));
      },
      remove(...values) {
        values.forEach((value) => classes.delete(value));
      },
    },
    querySelector(selector) {
      assert.equal(selector, "[data-source-stamp-label]");
      return label;
    },
    getAttribute(name) {
      return attributes.get(name) || null;
    },
    setAttribute(name, value) {
      attributes.set(name, value);
    },
  };

  assert.equal(applySourceStamp(stamp).state, "DATED");
  assert.equal(stamp.dataset.sourceState, "DATED");
  assert.equal(stamp.dataset.sourceStamp, "DATED");
  assert.equal(label.textContent, "DATED");
  assert.match(attributes.get("aria-label"), /Dated snapshot/);
  assert.equal(classes.has("source-stamp--dated"), true);
  assert.equal(classes.has("source-stamp--unknown"), false);
  assert.equal(applySourceStamp(stamp, "LIVE").state, "LIVE");
  assert.equal(stamp.dataset.sourceState, "LIVE");
  assert.equal(label.textContent, "LIVE");
  assert.match(attributes.get("aria-label"), /Observed live/);
  assert.equal(classes.has("source-stamp--live"), true);
  assert.equal(classes.has("source-stamp--dated"), false);
  assert.equal(applySourceStamp(null, "LIVE"), null);
});

test("shared initialization manages legacy and canonical source-stamp markup", () => {
  assert.match(
    appSource,
    /querySelectorAll\(\s*"\[data-source-stamp\], \.source-stamp\[data-source-state\]"/,
  );
});

test("evaluation fetch failures retain explicit metric labels", () => {
  assert.match(appSource, /Recall unavailable/);
  assert.match(appSource, /False-positive rate unavailable/);
  assert.match(appSource, /Evaluation corpus unavailable/);
  assert.doesNotMatch(
    appSource,
    /element\.dataset\.evalStat === "benign-cases"\s*\?\s*"Evaluation snapshot unavailable"\s*:\s*"—"/,
  );
});

test("async-panel behavior exposes loading and settled states without stale busy state", () => {
  const status = { textContent: "" };
  const attributes = new Map();
  const panel = {
    dataset: {},
    querySelector(selector) {
      assert.equal(selector, "[data-async-status]");
      return status;
    },
    setAttribute(name, value) {
      attributes.set(name, value);
    },
    removeAttribute(name) {
      attributes.delete(name);
    },
  };

  assert.equal(normalizeAsyncPanelState(" Loading "), "loading");
  assert.equal(normalizeAsyncPanelState("unsupported"), "unknown");
  assert.equal(
    applyAsyncPanelState(panel, "loading", "Loading evidence"),
    "loading",
  );
  assert.equal(panel.dataset.asyncState, "loading");
  assert.equal(attributes.get("aria-busy"), "true");
  assert.equal(status.textContent, "Loading evidence");
  assert.equal(
    applyAsyncPanelState(panel, "degraded", "Partial evidence"),
    "degraded",
  );
  assert.equal(attributes.has("aria-busy"), false);
  assert.equal(status.textContent, "Partial evidence");
  assert.equal(applyAsyncPanelState(null, "ready"), null);
});

test("header status starts unknown and maps only observed results to live or unavailable", () => {
  assert.deepEqual(healthStatusPresentation("unknown", false), {
    state: "unknown",
    label: "Status unknown",
    ariaLabel: "Service status: unknown",
    dotClass: "is-unknown",
  });
  assert.equal(healthStatusPresentation("live", false).label, "API live");
  assert.equal(healthStatusPresentation("live", true).label, "API ok");
  assert.equal(
    healthStatusPresentation("unavailable", false).label,
    "API unavailable",
  );
  assert.equal(healthStatusPresentation("checking", false).state, "unknown");
});

test("home proof evidence exposes key, freshness, and browser check time", () => {
  assert.deepEqual(
    homeProofEvidence(
      {
        material: {
          attestation: { attestation_id: "0123456789abcdef" },
          issuerDocument: { keys: [{ kid: "python-fixture-1" }] },
        },
        attestation: { freshness: "archival" },
        honestChain: { headHash: "a".repeat(64) },
        tamper: { entryIndex: 1 },
      },
      "2026-07-17T21:15:00.000Z",
    ),
    {
      attestationId: "0123456789abcdef",
      chainHead: "a".repeat(64),
      tamperIndex: "Entry 2",
      keyId: "python-fixture-1",
      freshness: "archival",
      checkedAt: "2026-07-17T21:15:00.000Z",
    },
  );
});

test("shared app leaves marketplace filtering to the route module", () => {
  assert.equal(appApi.matchesAgentFilters, undefined);
});

test("mobile navigation focus cycles in both directions", () => {
  assert.equal(cycleFocusIndex(0, "forward", 4), 1);
  assert.equal(cycleFocusIndex(3, "forward", 4), 0);
  assert.equal(cycleFocusIndex(0, "backward", 4), 3);
  assert.equal(cycleFocusIndex(-1, "forward", 4), 0);
  assert.equal(cycleFocusIndex(-1, "backward", 4), 3);
  assert.equal(cycleFocusIndex(0, "forward", 0), -1);
});

test("mobile navigation recognizes pointer interaction outside the dialog", () => {
  const siteNav = { contains: (target) => target === "nav" };
  const navToggle = { contains: (target) => target === "toggle" };

  assert.equal(
    isOutsideNavigationPointer(siteNav, navToggle, "page-content"),
    true,
  );
  assert.equal(isOutsideNavigationPointer(siteNav, navToggle, "nav"), false);
  assert.equal(isOutsideNavigationPointer(siteNav, navToggle, "toggle"), false);
});

test("async status focus and copy labels remain stable across retries", () => {
  let focused = false;
  const status = {
    tabIndex: 0,
    focus() {
      focused = true;
    },
  };
  assert.equal(focusStatusTarget(status), true);
  assert.equal(status.tabIndex, -1);
  assert.equal(focused, true);

  const button = { dataset: {}, textContent: "Copy result" };
  assert.equal(copyButtonBaseLabel(button), "Copy result");
  button.textContent = "Copy failed";
  assert.equal(copyButtonBaseLabel(button), "Copy result");
});

test("service metadata resolves only from a normalized catalog", () => {
  const catalog = {
    services: [
      { key: "scan", serviceId: "33460", feeAmount: "0.01" },
      { key: "audit", serviceId: "33461", feeAmount: "0.5" },
    ],
  };
  assert.equal(catalogServiceByKey(catalog, "audit").serviceId, "33461");
  assert.equal(catalogServiceByKey(catalog, "missing"), null);
  assert.equal(catalogServiceByKey({}, "scan"), null);
});

test("live evidence counts accept only non-negative integers", () => {
  assert.equal(normalizeEvidenceCount(0, "badges"), 0);
  assert.equal(normalizeEvidenceCount(12, "attempts"), 12);
  assert.throws(() => normalizeEvidenceCount(-1, "badges"), /badges/);
  assert.throws(() => normalizeEvidenceCount(1.5, "badges"), /badges/);
  assert.throws(() => normalizeEvidenceCount("2", "badges"), /badges/);
});

test("marketplace summary normalizes complete schema-v2 coverage", () => {
  assert.deepEqual(
    normalizeMarketplaceSummary({
      schemaVersion: 2,
      capturedAt: "2026-07-14T14:50:30Z",
      query: "a",
      sampled: 579,
      expected: 579,
      dropped: 0,
      matchedCount: 1,
      auditedCount: 0,
    }),
    {
      schemaVersion: 2,
      capturedAt: "2026-07-14T14:50:30Z",
      query: "a",
      sampled: 579,
      expected: 579,
      dropped: 0,
      matchedCount: 1,
      auditedCount: 0,
      complete: true,
    },
  );
});

test("marketplace summary exposes degraded coverage without inventing a cause", () => {
  assert.deepEqual(
    normalizeMarketplaceSummary({
      schemaVersion: 2,
      capturedAt: "2026-07-14T14:50:30Z",
      query: "a",
      sampled: 576,
      expected: 579,
      dropped: 3,
      matchedCount: 1,
      auditedCount: 0,
    }),
    {
      schemaVersion: 2,
      capturedAt: "2026-07-14T14:50:30Z",
      query: "a",
      sampled: 576,
      expected: 579,
      dropped: 3,
      matchedCount: 1,
      auditedCount: 0,
      complete: false,
    },
  );
});

test("marketplace coverage copy distinguishes missing results from inconsistent totals", () => {
  assert.match(
    marketplaceCoverageText({
      query: "a",
      sampled: 576,
      expected: 579,
      dropped: 3,
      complete: false,
    }),
    /marketplace query "a".*3 expected agents not present in this response/,
  );
  const inconsistent = marketplaceCoverageText({
    query: "a",
    sampled: 580,
    expected: 579,
    dropped: 0,
    complete: false,
  });
  assert.match(
    inconsistent,
    /sample exceeded the highest reported result total/,
  );
  assert.match(inconsistent, /upstream counts disagree/);
  assert.doesNotMatch(inconsistent, /0 expected agents not present/);
});

test("marketplace summary rejects inconsistent counts and non-UTC timestamps", () => {
  assert.throws(
    () =>
      normalizeMarketplaceSummary({
        schemaVersion: 2,
        capturedAt: "2026-07-14T14:50:30Z",
        query: "a",
        sampled: 579,
        expected: 579,
        dropped: 0,
        matchedCount: -1,
        auditedCount: 0,
      }),
    /matched count/,
  );
  assert.throws(
    () =>
      normalizeMarketplaceSummary({
        schemaVersion: 2,
        capturedAt: "2026-07-14T14:50:30+00:00",
        query: "a",
        sampled: 579,
        expected: 579,
        dropped: 0,
        matchedCount: 1,
        auditedCount: 0,
      }),
    /UTC timestamp/,
  );
  assert.throws(
    () =>
      normalizeMarketplaceSummary({
        schemaVersion: 2,
        capturedAt: "2026-07-14T14:50:30Z",
        query: "a",
        sampled: 576,
        expected: 579,
        dropped: 0,
        matchedCount: 1,
        auditedCount: 0,
      }),
    /dropped count/,
  );
  assert.throws(
    () =>
      normalizeMarketplaceSummary({
        schemaVersion: 2,
        capturedAt: "2026-07-14T14:50:30Z",
        query: "   ",
        sampled: 579,
        expected: 579,
        dropped: 0,
        matchedCount: 1,
        auditedCount: 0,
      }),
    /query/,
  );
});

test("product proof normalizes the dated marketplace and corpus evidence", () => {
  assert.deepEqual(normalizeProductProof(productProof), productProof);
});

test("product proof rejects corpus, benchmark, and marketplace drift", () => {
  assert.throws(
    () =>
      normalizeProductProof({
        ...productProof,
        evaluationCorpus: { ...productProof.evaluationCorpus, total: 122 },
      }),
    /corpus counts/,
  );
  assert.throws(
    () =>
      normalizeProductProof({
        ...productProof,
        marketplace: { ...productProof.marketplace, sold: "15" },
      }),
    /sold count/,
  );
});
