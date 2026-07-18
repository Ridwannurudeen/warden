"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  AGENT_PAGE_SIZE,
  agentRecordDataset,
  compareAgentRows,
  createAgentIndexLoader,
  fetchAgentIndex,
  filtersFromSearchParams,
  filtersToSearchParams,
  focusIndexAfterAgentExpansion,
  hydrateAgentRows,
  languageForText,
  loadAgentRows,
  matchesAgentFilters,
  matchesDocumentFilters,
  selectAgentRows,
} = require(path.join(__dirname, "..", "..", "site", "agents.js"));

test("marketplace language tags identify supported scripts without tagging symbols", () => {
  assert.equal(languageForText("安全代理"), "zh");
  assert.equal(languageForText("監査サービス"), "ja");
  assert.equal(languageForText("감사 서비스"), "ko");
  assert.equal(languageForText("Agent 🚀"), "");
});

test("marketplace search and filters require every selected condition", () => {
  const dataset = {
    search:
      "3808 Warden SOFTWARE_SERVICES public-text pattern match TOOL_HIJACK linked signed endpoint audit record",
    category: "SOFTWARE_SERVICES|SECURITY",
    match: "signal",
    audit: "audited",
    apa: "attested",
  };

  assert.equal(
    matchesAgentFilters(dataset, {
      query: "warden tool_hijack",
      category: "SECURITY",
      match: "signal",
      audit: "audited",
      apa: "attested",
    }),
    true,
  );
  assert.equal(
    matchesAgentFilters(dataset, { query: "warden", category: "DEFI" }),
    false,
  );
  assert.equal(matchesAgentFilters(dataset, { match: "none" }), false);
  assert.equal(matchesAgentFilters(dataset, { audit: "not-audited" }), false);
  assert.equal(matchesAgentFilters(dataset, { apa: "not-attested" }), false);
});

test("marketplace filters round-trip through shareable query parameters", () => {
  const filters = filtersFromSearchParams(
    "?q=warden&category=SECURITY&signal=none&audit=audited&apa=attested&sort=name-asc",
  );

  assert.deepEqual(filters, {
    query: "warden",
    category: "SECURITY",
    match: "none",
    audit: "audited",
    apa: "attested",
    sort: "name-asc",
  });
  assert.equal(
    filtersToSearchParams(filters),
    "q=warden&category=SECURITY&signal=none&audit=audited&apa=attested&sort=name-asc",
  );
  assert.equal(filtersToSearchParams({}), "");
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
      apa: "not-attested",
    },
    {
      name: "Alpha",
      agentId: "1",
      sold: "10",
      review: "4.5",
      match: "none",
      audit: "not-audited",
      apa: "not-attested",
    },
    {
      name: "Beta",
      agentId: "2",
      sold: "10",
      review: "5",
      match: "signal",
      audit: "audited",
      apa: "attested",
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
      apa: "not-attested",
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

function marketplaceRecord(index, overrides = {}) {
  return {
    agentId: String(index),
    name: `Agent ${index}`,
    categories: ["SOFTWARE_SERVICES"],
    sold: index,
    review: 4.5,
    match: "none",
    publicTextLabel: "No implemented public-text pattern match",
    verdict: "ALLOW",
    threatClasses: [],
    audit: "not-audited",
    apa: "not-attested",
    ...overrides,
  };
}

function marketplacePayload(records) {
  return {
    schemaVersion: 1,
    capturedAt: "2026-07-13T15:30:00Z",
    sampled: records.length,
    hasAudits: false,
    hasAttestations: false,
    records,
  };
}

test("full marketplace hydration reaches an off-window signal and expands 50 to 100", () => {
  const records = Array.from({ length: 120 }, (_, index) =>
    marketplaceRecord(index + 1),
  );
  records[100] = marketplaceRecord(101, {
    match: "signal",
    verdict: "SANITIZE",
    threatClasses: ["TOOL_HIJACK"],
  });
  const payload = marketplacePayload(records);
  const rows = hydrateAgentRows(payload, (record, context) => ({
    agentId: record.agentId,
    dataset: agentRecordDataset(record, context),
  }));

  const searched = selectAgentRows(rows, { match: "signal" }, AGENT_PAGE_SIZE);
  assert.deepEqual(
    searched.renderedRows.map((row) => row.agentId),
    ["101"],
  );
  const expanded = selectAgentRows(rows, {}, AGENT_PAGE_SIZE * 2);
  assert.equal(expanded.renderedRows.length, 100);
});

test("malformed or unavailable full index retains the first-50 fallback", async () => {
  const fallbackRows = Array.from({ length: 50 }, (_, index) => ({
    dataset: { search: `fallback ${index}` },
  }));
  const malformed = await loadAgentRows(
    async () => ({
      ok: true,
      json: async () =>
        marketplacePayload([
          marketplaceRecord(1, { agentId: "../unsafe-agent" }),
        ]),
    }),
    fallbackRows,
    () => {
      throw new Error("malformed data must not reach the row factory");
    },
  );
  assert.equal(malformed.degraded, true);
  assert.strictEqual(malformed.rows, fallbackRows);
  assert.match(malformed.error.message, /agentId/);

  const unavailable = await loadAgentRows(
    async () => {
      throw new Error("network unavailable");
    },
    fallbackRows,
    () => {
      throw new Error("failed fetch must not reach the row factory");
    },
  );
  assert.equal(unavailable.degraded, true);
  assert.strictEqual(unavailable.rows, fallbackRows);
  assert.match(unavailable.error.message, /network unavailable/);
});

test("marketplace index fetch validates the response before hydration", async () => {
  const payload = marketplacePayload([marketplaceRecord(1)]);
  assert.deepEqual(
    await fetchAgentIndex(async (url, options) => {
      assert.equal(url, "/agents/index-data.json");
      assert.equal(options.headers.Accept, "application/json");
      return { ok: true, json: async () => payload };
    }),
    payload,
  );
  await assert.rejects(
    fetchAgentIndex(async () => ({ ok: false, status: 503 })),
    /503/,
  );
});

test("marketplace index fetch times out and aborts a stalled request", async () => {
  let requestSignal;
  await assert.rejects(
    fetchAgentIndex(
      async (_url, options) => {
        requestSignal = options.signal;
        return new Promise((_resolve, reject) => {
          const safetyTimer = setTimeout(
            () => reject(new Error("test safety timeout")),
            100,
          );
          options.signal?.addEventListener(
            "abort",
            () => {
              clearTimeout(safetyTimer);
              reject(new Error("request aborted"));
            },
            { once: true },
          );
        });
      },
      "/agents/index-data.json",
      { timeoutMs: 5 },
    ),
    /timed out after 5ms/,
  );
  assert.equal(requestSignal.aborted, true);

  let responseBodySignal;
  await assert.rejects(
    fetchAgentIndex(
      async (_url, options) => {
        responseBodySignal = options.signal;
        return {
          ok: true,
          json: async () => new Promise(() => {}),
        };
      },
      "/agents/index-data.json",
      { timeoutMs: 5 },
    ),
    /timed out after 5ms/,
  );
  assert.equal(responseBodySignal.aborted, true);
});

test("marketplace full-index loader retries degraded state and revalidates metadata", async () => {
  const fallbackRows = Array.from({ length: 50 }, (_, index) => ({
    dataset: { search: `fallback ${index}` },
  }));
  const hydratedRows = Array.from({ length: 60 }, (_, index) => ({
    dataset: { search: `hydrated ${index}` },
  }));
  const payload = marketplacePayload(
    Array.from({ length: 60 }, (_, index) => marketplaceRecord(index + 1)),
  );
  let attempts = 0;
  const loader = createAgentIndexLoader({
    fallbackRows,
    expectedTotal: 60,
    expectedCapturedAt: payload.capturedAt,
    loadRows: async () => {
      attempts += 1;
      if (attempts === 1) {
        return {
          degraded: true,
          error: new Error("network unavailable"),
          payload: null,
          rows: fallbackRows,
        };
      }
      if (attempts === 2) {
        return {
          degraded: false,
          error: null,
          payload: { ...payload, capturedAt: "2026-07-14T15:30:00Z" },
          rows: hydratedRows,
        };
      }
      return {
        degraded: false,
        error: null,
        payload,
        rows: hydratedRows,
      };
    },
  });

  assert.equal(loader.state, "fallback");
  assert.equal((await loader.load()).state, "degraded");
  assert.strictEqual(loader.rows, fallbackRows);
  assert.equal((await loader.load()).state, "degraded");
  assert.equal(attempts, 1);

  const mismatched = await loader.retry();
  assert.equal(mismatched.state, "degraded");
  assert.strictEqual(mismatched.rows, fallbackRows);
  assert.match(mismatched.error.message, /metadata/);

  const recovered = await loader.retry();
  assert.equal(recovered.state, "loaded");
  assert.strictEqual(recovered.rows, hydratedRows);
  assert.equal(attempts, 3);
});

test("marketplace hydration does not use HTML parsing sinks", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "agents.js"),
    "utf8",
  );
  assert.doesNotMatch(
    source,
    /innerHTML|insertAdjacentHTML|outerHTML|document\.write/u,
  );
});

test("marketplace hydrated rows omit raw scanner verdict labels", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "agents.js"),
    "utf8",
  );
  const start = source.indexOf("function createAgentRow");
  const end = source.indexOf("\n  const agentResults", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const rowRenderer = source.slice(start, end);
  assert.doesNotMatch(rowRenderer, /Verdict:|record\.verdict/u);
  assert.match(rowRenderer, /Endpoint audit record:/u);
  assert.doesNotMatch(rowRenderer, /Endpoint audit:/u);
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
