"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const appApi = require(path.join(__dirname, "..", "..", "site", "app.js"));

const {
  catalogServiceByKey,
  copyButtonBaseLabel,
  cycleFocusIndex,
  focusStatusTarget,
  isHealthyResponse,
  isOutsideNavigationPointer,
  normalizeEvidenceCount,
  resolveTheme,
  summaryToRestoreOnEscape,
} = appApi;

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

test("desktop menus recognize pointer interaction outside the navigation", () => {
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
