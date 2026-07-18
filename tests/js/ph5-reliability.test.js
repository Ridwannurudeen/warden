"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { normalizeMonitor } = require(
  path.join(__dirname, "..", "..", "site", "status.js"),
);

test("monitor surface stays unmeasured until a scheduled probe is running", () => {
  assert.deepEqual(
    normalizeMonitor({ schema_version: 2, status: "not_running", samples: [] }),
    {
      state: "Monitor not running",
      monitorState: "not_running",
      sourceState: "degraded",
      window: "No scheduled readiness samples have been recorded",
      applicationAvailability: "Not measured",
      challengeReadiness: "Not measured",
      latest: "No probe recorded",
      applicationLatest: "No probe recorded",
      challengeLatest: "No probe recorded",
    },
  );
});

test("monitor summary validates samples and labels an incomplete window", () => {
  const summary = normalizeMonitor(
    {
      schema_version: 2,
      status: "collecting",
      samples: [
        {
          checked_at: "2026-06-20T00:00:00Z",
          application: {
            status: "ready",
            http_status: 200,
            latency_ms: 25,
          },
          x402_challenge: {
            status: "ready",
            http_status: 402,
            latency_ms: 35,
          },
        },
        {
          checked_at: "2026-07-16T00:00:00Z",
          application: {
            status: "not_ready",
            http_status: 503,
            latency_ms: 40,
          },
          x402_challenge: {
            status: "error",
            http_status: null,
            latency_ms: 50,
          },
        },
      ],
    },
    new Date("2026-07-16T00:00:00Z"),
  );

  assert.equal(summary.state, "Collecting evidence");
  assert.equal(
    summary.window,
    "2 of 8,640 current-window slots observed; 30-day window incomplete",
  );
  assert.equal(summary.applicationAvailability, "Not measured");
  assert.equal(summary.challengeReadiness, "Not measured");
  assert.equal(
    summary.latest,
    "2026-07-16T00:00:00Z \u2014 application not ready; unsigned x402 challenge error",
  );
  assert.equal(
    summary.applicationLatest,
    "2026-07-16T00:00:00Z \u2014 not ready",
  );
  assert.equal(summary.challengeLatest, "2026-07-16T00:00:00Z \u2014 error");
  assert.throws(
    () =>
      normalizeMonitor({
        schema_version: 2,
        status: "collecting",
        samples: [{ status: "ready" }],
      }),
    /sample/,
  );
});

test("complete rolling window reports application and challenge readiness", () => {
  const start = Date.parse("2026-06-01T00:00:00Z");
  const samples = Array.from({ length: 8_640 }, (_, index) => ({
    checked_at: new Date(start + index * 5 * 60 * 1000)
      .toISOString()
      .replace(".000Z", "Z"),
    application: {
      status: "ready",
      http_status: 200,
      latency_ms: 10,
    },
    x402_challenge: {
      status: index === 0 ? "error" : "ready",
      http_status: index === 0 ? null : 402,
      latency_ms: 20,
    },
  }));

  const summary = normalizeMonitor(
    {
      schema_version: 2,
      status: "collecting",
      samples,
    },
    new Date(samples.at(-1).checked_at),
  );

  assert.equal(summary.state, "30-day window measured");
  assert.equal(summary.applicationAvailability, "100.00%");
  assert.equal(summary.challengeReadiness, "99.99%");
  assert.equal(summary.monitorState, "collecting");
  assert.equal(summary.sourceState, "dated");
});

test("rolling completeness is anchored to now and exposes a stale monitor", () => {
  const start = Date.parse("2026-06-01T00:00:00Z");
  const samples = Array.from({ length: 8_640 }, (_, index) => ({
    checked_at: new Date(start + index * 5 * 60 * 1000)
      .toISOString()
      .replace(".000Z", "Z"),
    application: {
      status: "ready",
      http_status: 200,
      latency_ms: 10,
    },
    x402_challenge: {
      status: "ready",
      http_status: 402,
      latency_ms: 20,
    },
  }));

  const oneSlotLate = normalizeMonitor(
    { schema_version: 2, status: "collecting", samples },
    new Date("2026-07-01T00:00:00Z"),
  );
  assert.equal(oneSlotLate.state, "Collecting evidence");
  assert.equal(oneSlotLate.applicationAvailability, "Not measured");
  assert.match(oneSlotLate.window, /8,639 of 8,640/);

  const stale = normalizeMonitor(
    { schema_version: 2, status: "collecting", samples },
    new Date("2026-07-01T00:10:01Z"),
  );
  assert.equal(stale.state, "Monitor stale");
  assert.equal(stale.monitorState, "stale");
  assert.equal(stale.sourceState, "degraded");
  assert.equal(stale.challengeReadiness, "Not measured");
});

test("status page states the objective and its evidence boundary", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "status.html"),
    "utf8",
  );
  const normalizedHtml = html.replace(/\s+/g, " ");
  assert.match(normalizedHtml, /99\.5% application-readiness objective/);
  assert.match(normalizedHtml, /not a contractual SLA/);
  assert.match(
    normalizedHtml,
    /does not establish payment settlement or facilitator uptime/,
  );
  assert.match(html, /data-monitor-application-availability/);
  assert.match(html, /data-monitor-challenge-readiness/);
  assert.doesNotMatch(html, /End-to-end paid-route availability/);
});
