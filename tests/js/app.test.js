"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  catalogServiceByKey,
  cycleFocusIndex,
  isHealthyResponse,
  matchesAgentFilters,
  normalizeEvidenceCount,
  resolveTheme,
  summaryToRestoreOnEscape,
} = require(path.join(__dirname, "..", "..", "site", "app.js"));

test("theme resolution respects a stored choice before system preference", () => {
  assert.equal(resolveTheme("light", false), "light");
  assert.equal(resolveTheme("dark", true), "dark");
  assert.equal(resolveTheme(null, true), "light");
  assert.equal(resolveTheme(null, false), "dark");
});

test("header reachability accepts only the documented healthy response", () => {
  assert.equal(isHealthyResponse({ status: "ok" }), true);
  assert.equal(isHealthyResponse({ status: "degraded" }), false);
  assert.equal(isHealthyResponse({}), false);
  assert.equal(isHealthyResponse(null), false);
});

test("agent filters require both selected category and match state", () => {
  assert.equal(
    matchesAgentFilters(
      { category: "SOFTWARE_SERVICES DEFI", match: "yes" },
      "SOFTWARE_SERVICES",
      "yes",
    ),
    true,
  );
  assert.equal(
    matchesAgentFilters(
      { category: "DEFI", match: "yes" },
      "SOFTWARE_SERVICES",
      "yes",
    ),
    false,
  );
  assert.equal(
    matchesAgentFilters({ category: "DEFI", match: "no" }, "", "yes"),
    false,
  );
});

test("mobile navigation focus cycles in both directions", () => {
  assert.equal(cycleFocusIndex(0, "forward", 4), 1);
  assert.equal(cycleFocusIndex(3, "forward", 4), 0);
  assert.equal(cycleFocusIndex(0, "backward", 4), 3);
  assert.equal(cycleFocusIndex(-1, "forward", 4), 0);
  assert.equal(cycleFocusIndex(-1, "backward", 4), 3);
  assert.equal(cycleFocusIndex(0, "forward", 0), -1);
});

test("desktop menu escape restores focus to the owning summary", () => {
  const summary = { focus() {} };
  const activeElement = {
    closest(selector) {
      assert.equal(selector, "details[open]");
      return {
        querySelector(query) {
          assert.equal(query, "summary");
          return summary;
        },
      };
    },
  };
  assert.equal(summaryToRestoreOnEscape(activeElement), summary);
  assert.equal(summaryToRestoreOnEscape(null), null);
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
