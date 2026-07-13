"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  buildDemoRequest,
  defaultExampleId,
  deriveScanPresentation,
  isCurrentPlaygroundRequest,
  recipientFocusIndexAfterRemoval,
} = require(path.join(__dirname, "..", "..", "site", "playground.js"));

const SOLANA_ADDRESS = "11111111111111111111111111111111";

test("playground builds the frozen fast-demo request shape", () => {
  assert.deepEqual(
    buildDemoRequest(
      "payment confirmed",
      `0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, ${SOLANA_ADDRESS}, 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
    ),
    {
      payload: "payment confirmed",
      context: {
        expected_addresses: [
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          SOLANA_ADDRESS,
        ],
      },
    },
  );
});

test("playground rejects blank, oversized, and excessive context", () => {
  assert.throws(() => buildDemoRequest("   ", ""), /payload/);
  assert.throws(() => buildDemoRequest("x".repeat(4001), ""), /4,000/);
  assert.throws(
    () =>
      buildDemoRequest(
        "test",
        Array.from(
          { length: 21 },
          (_, index) => `0x${index.toString(16).padStart(40, "0")}`,
        ).join(","),
      ),
    /20/,
  );
  assert.throws(() => buildDemoRequest("test", "0x1234"), /40 hexadecimal/);
});

test("playground selects the drain-address regression as its strongest default", () => {
  assert.equal(
    defaultExampleId([
      { id: "benign-001", reason_code: null },
      { id: "drain-001", reason_code: "DRAIN_ADDRESS" },
    ]),
    "drain-001",
  );
  assert.equal(
    defaultExampleId([{ id: "tool-001", reason_code: "TOOL_HIJACK" }]),
    "tool-001",
  );
});

test("playground ignores a scan response superseded by changed input", () => {
  assert.equal(isCurrentPlaygroundRequest(1, 2), false);
  assert.equal(isCurrentPlaygroundRequest(2, 2), true);
});

test("playground presentation separates decision, risk, and sanitized output", () => {
  const scanData = {
    verdict: "SANITIZE",
    risk_level: "NONE",
    threat_classes: ["MALICIOUS_LINK", "MALICIOUS_LINK"],
    detections: [{ class: "MALICIOUS_LINK" }],
    sanitized_payload: "Open [URL REDACTED]",
    recommendation: "Sanitize before agent execution.",
    latency_ms: 2,
  };
  const presentation = deriveScanPresentation(
    scanData,
    "Open http://127.0.0.1/now",
  );

  assert.equal(presentation.verdict, "SANITIZE");
  assert.equal(presentation.riskLevel, "NONE");
  assert.deepEqual(presentation.reasons, ["MALICIOUS_LINK"]);
  assert.equal(presentation.changed, true);
  assert.match(presentation.action, /Do not use the original/);
  assert.match(presentation.riskNote, /different questions/);

  assert.match(
    deriveScanPresentation(
      { ...scanData, verdict: "BLOCK", threat_classes: [], detections: [] },
      "test",
    ).action,
    /Do not execute/,
  );
  assert.match(
    deriveScanPresentation(
      { ...scanData, verdict: "ALLOW", threat_classes: [], detections: [] },
      "test",
    ).action,
    /own action policy/,
  );
});

test("recipient removal keeps focus on the nearest remaining control", () => {
  assert.equal(recipientFocusIndexAfterRemoval(0, 2), 0);
  assert.equal(recipientFocusIndexAfterRemoval(2, 2), 1);
  assert.equal(recipientFocusIndexAfterRemoval(0, 0), -1);
});
