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
    normalizeMonitor({ schema_version: 1, status: "not_running", samples: [] }),
    {
      state: "Not measured",
      window: "No recorded readiness samples",
      availability: "Not measured",
      latest: "No probe recorded",
    },
  );
});

test("monitor summary validates samples and labels an incomplete window", () => {
  const summary = normalizeMonitor({
    schema_version: 1,
    status: "collecting",
    samples: [
      {
        checked_at: "2026-06-20T00:00:00Z",
        status: "ready",
        http_status: 200,
        latency_ms: 25,
      },
      {
        checked_at: "2026-07-16T00:00:00Z",
        status: "not_ready",
        http_status: 503,
        latency_ms: 40,
      },
    ],
  });

  assert.equal(summary.state, "Collecting evidence");
  assert.equal(
    summary.window,
    "2 recorded readiness samples; 30-day window incomplete",
  );
  assert.equal(summary.availability, "Not measured");
  assert.equal(summary.latest, "2026-07-16T00:00:00Z — not ready");
  assert.throws(
    () =>
      normalizeMonitor({
        schema_version: 1,
        status: "collecting",
        samples: [{ status: "ready" }],
      }),
    /sample/,
  );
});

test("status page states the objective and its evidence boundary", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "status.html"),
    "utf8",
  );
  assert.match(html, /99\.5% application-readiness objective/);
  assert.match(html, /not a contractual SLA/);
  assert.match(
    html,
    /Third-party payment-facilitator availability is outside this measurement/,
  );
  assert.match(html, /data-monitor-availability/);
});
