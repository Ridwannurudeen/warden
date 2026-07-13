"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { matchesAgentFilters, resolveTheme } = require(
  path.join(__dirname, "..", "..", "site", "app.js"),
);

test("theme resolution respects a stored choice before system preference", () => {
  assert.equal(resolveTheme("light", false), "light");
  assert.equal(resolveTheme("dark", true), "dark");
  assert.equal(resolveTheme(null, true), "light");
  assert.equal(resolveTheme(null, false), "dark");
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
