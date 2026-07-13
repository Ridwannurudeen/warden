"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  AGENT_PAGE_SIZE,
  compareAgentRows,
  focusIndexAfterAgentExpansion,
  matchesAgentFilters,
  matchesDocumentFilters,
  selectAgentRows,
} = require(path.join(__dirname, "..", "..", "site", "agents.js"));

test("marketplace search and filters require every selected condition", () => {
  const dataset = {
    search:
      "3808 Warden SOFTWARE_SERVICES public-text pattern match TOOL_HIJACK linked signed audit",
    category: "SOFTWARE_SERVICES|SECURITY",
    match: "signal",
    audit: "audited",
  };

  assert.equal(
    matchesAgentFilters(dataset, {
      query: "warden tool_hijack",
      category: "SECURITY",
      match: "signal",
      audit: "audited",
    }),
    true,
  );
  assert.equal(
    matchesAgentFilters(dataset, { query: "warden", category: "DEFI" }),
    false,
  );
  assert.equal(matchesAgentFilters(dataset, { match: "none" }), false);
  assert.equal(matchesAgentFilters(dataset, { audit: "not-audited" }), false);
});

test("marketplace sorting handles missing numbers and deterministic ties", () => {
  const agents = [
    {
      name: "Zulu",
      agentId: "3",
      sold: "",
      review: "",
      match: "unscanned",
      audit: "not-audited",
    },
    {
      name: "Alpha",
      agentId: "1",
      sold: "10",
      review: "4.5",
      match: "none",
      audit: "not-audited",
    },
    {
      name: "Beta",
      agentId: "2",
      sold: "10",
      review: "5",
      match: "signal",
      audit: "audited",
    },
  ];

  assert.deepEqual(
    [...agents]
      .sort((left, right) => compareAgentRows(left, right, "sold-desc"))
      .map((agent) => agent.name),
    ["Alpha", "Beta", "Zulu"],
  );
  assert.deepEqual(
    [...agents]
      .sort((left, right) => compareAgentRows(left, right, "review-desc"))
      .map((agent) => agent.name),
    ["Beta", "Alpha", "Zulu"],
  );
  assert.equal(
    compareAgentRows(agents[2], agents[1], "signal-first") < 0,
    true,
  );
  assert.equal(compareAgentRows(agents[2], agents[1], "audit-first") < 0, true);
});

test("marketplace window filters every cached row before slicing", () => {
  const rows = Array.from({ length: 120 }, (_, index) => ({
    dataset: {
      search: `agent ${index}`,
      category: "SOFTWARE_SERVICES",
      match: "none",
      audit: "not-audited",
    },
  }));
  rows[100].dataset.search += " offscreen-target";

  const initial = selectAgentRows(rows, {}, AGENT_PAGE_SIZE);
  assert.equal(AGENT_PAGE_SIZE, 50);
  assert.equal(initial.matchingRows.length, 120);
  assert.deepEqual(initial.renderedRows, rows.slice(0, 50));

  const searched = selectAgentRows(
    rows,
    { query: "offscreen-target" },
    AGENT_PAGE_SIZE,
  );
  assert.deepEqual(searched.matchingRows, [rows[100]]);
  assert.deepEqual(searched.renderedRows, [rows[100]]);

  const expanded = selectAgentRows(rows, {}, AGENT_PAGE_SIZE * 2);
  assert.equal(expanded.matchingRows.length, 120);
  assert.deepEqual(expanded.renderedRows, rows.slice(0, 100));
});

test("marketplace expansion moves focus to the first new row", () => {
  assert.equal(focusIndexAfterAgentExpansion(50, 100), 50);
  assert.equal(focusIndexAfterAgentExpansion(350, 376), 350);
  assert.equal(focusIndexAfterAgentExpansion(50, 50), -1);
});

test("documentation filters search the matrix by decision and availability", () => {
  const dataset = {
    search: "CORPUS_MATCH corpus similarity thorough regression",
    decisions: "ALLOW SANITIZE",
    availability: "thorough-only",
  };

  assert.equal(
    matchesDocumentFilters(dataset, {
      query: "corpus regression",
      decision: "SANITIZE",
      availability: "thorough-only",
    }),
    true,
  );
  assert.equal(matchesDocumentFilters(dataset, { decision: "BLOCK" }), false);
  assert.equal(
    matchesDocumentFilters(dataset, { availability: "fast-and-thorough" }),
    false,
  );
});
