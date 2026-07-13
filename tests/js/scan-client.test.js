"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  ScanClientError,
  assertScanResponse,
  classifyFetchFailure,
  formatScanError,
  getJson,
  normalizeExpectedAddresses,
  postJson,
} = require(path.join(__dirname, "..", "..", "site", "scan-client.js"));

const EVM_CHECKSUM = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SOLANA_ADDRESS = "11111111111111111111111111111111";

function response({ status = 200, payload = {}, retryAfter = null } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return name.toLowerCase() === "retry-after" ? retryAfter : null;
      },
    },
    async json() {
      if (payload instanceof Error) {
        throw payload;
      }
      return payload;
    },
  };
}

function scanResponse(overrides = {}) {
  return {
    verdict: "BLOCK",
    risk_level: "CRITICAL",
    threat_classes: ["DRAIN_ADDRESS"],
    detections: [],
    sanitized_payload: "payment blocked",
    recommendation: "Block this payload.",
    checks: {},
    latency_ms: 1.5,
    ...overrides,
  };
}

test("expected addresses validate and deduplicate EVM and Solana recipients", () => {
  assert.deepEqual(
    normalizeExpectedAddresses([
      EVM_CHECKSUM,
      EVM_CHECKSUM.toLowerCase(),
      SOLANA_ADDRESS,
      SOLANA_ADDRESS,
    ]),
    [EVM_CHECKSUM.toLowerCase(), SOLANA_ADDRESS],
  );
  assert.throws(() => normalizeExpectedAddresses("0x1234"), /40 hexadecimal/);
  assert.throws(() => normalizeExpectedAddresses("not-an-address"), /Solana/);
  assert.throws(
    () =>
      normalizeExpectedAddresses(
        Array.from(
          { length: 21 },
          (_, index) => `0x${index.toString(16).padStart(40, "0")}`,
        ),
      ),
    /20/,
  );
});

test("scan response validation rejects malformed success envelopes", () => {
  assert.equal(assertScanResponse(scanResponse()).verdict, "BLOCK");
  assert.throws(
    () => assertScanResponse(scanResponse({ threat_classes: "DRAIN_ADDRESS" })),
    (error) => error instanceof ScanClientError && error.kind === "malformed",
  );
  assert.throws(
    () =>
      assertScanResponse(
        scanResponse({
          detections: [
            {
              class: "DRAIN_ADDRESS",
              match: "0x2222222222222222222222222222222222222222",
              confidence: 0.95,
            },
          ],
        }),
      ),
    (error) => error instanceof ScanClientError && error.kind === "malformed",
  );
  assert.throws(
    () => assertScanResponse(scanResponse(), { gauntlet: true }),
    (error) => error instanceof ScanClientError && error.kind === "malformed",
  );
  assert.equal(
    assertScanResponse(
      scanResponse({ claim_status: "pending", claim_id: "claim-1" }),
      { gauntlet: true },
    ).claim_status,
    "pending",
  );
});

test("postJson classifies rate limits and successful malformed JSON", async () => {
  await assert.rejects(
    () =>
      postJson(
        "/api/demo/scan",
        { payload: "test" },
        {
          fetchImpl: async () =>
            response({
              status: 429,
              payload: { detail: "Rate limit exceeded" },
              retryAfter: "42",
            }),
        },
      ),
    (error) =>
      error instanceof ScanClientError &&
      error.kind === "rate_limit" &&
      error.retryAfter === 42,
  );

  await assert.rejects(
    () =>
      postJson(
        "/api/demo/scan",
        { payload: "test" },
        {
          fetchImpl: async () =>
            response({ payload: new SyntaxError("bad JSON") }),
        },
      ),
    (error) => error instanceof ScanClientError && error.kind === "malformed",
  );
});

test("getJson keeps status polling same-origin and body-free", async () => {
  let captured;
  const payload = await getJson("/api/demo/gauntlet/stats", {
    fetchImpl: async (endpoint, request) => {
      captured = { endpoint, request };
      return response({ payload: { attempts: 0 } });
    },
  });

  assert.deepEqual(payload, { attempts: 0 });
  assert.equal(captured.endpoint, "/api/demo/gauntlet/stats");
  assert.equal(captured.request.method, "GET");
  assert.equal("body" in captured.request, false);
  assert.equal("content-type" in captured.request.headers, false);
});

test("fetch failures distinguish timeout and offline recovery guidance", () => {
  const timeout = classifyFetchFailure({ name: "AbortError" }, true);
  const offline = classifyFetchFailure(new TypeError("failed"), false, false);
  assert.equal(timeout.kind, "timeout");
  assert.match(formatScanError(timeout), /timed out/);
  assert.equal(offline.kind, "offline");
  assert.match(formatScanError(offline), /offline/);
  assert.match(
    formatScanError(
      new ScanClientError("Rate limit exceeded", {
        kind: "rate_limit",
        retryAfter: 12,
      }),
    ),
    /12 seconds/,
  );
});
