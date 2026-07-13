"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { buildIntegrationExamples, decisionPayload, nextTabIndex } = require(
  path.join(__dirname, "..", "..", "site", "integrate.js"),
);

const catalog = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "data", "warden-services.json"),
    "utf8",
  ),
);

test("integration examples take service identifiers, prices, and endpoints from the catalog", () => {
  for (const service of catalog.services) {
    const examples = buildIntegrationExamples({
      providerAgentId: catalog.providerAgentId,
      service,
    });
    const combined = Object.values(examples).join("\n");

    assert.match(combined, new RegExp(`service #${service.serviceId}`));
    assert.match(combined, new RegExp(service.endpoint.replaceAll(".", "\\.")));
    assert.match(combined, new RegExp(`${service.feeAmount} USDT`));
    assert.doesNotMatch(combined, /31669|31670|18954|18955/);
    assert.doesNotMatch(combined, /PRIVATE_KEY|SECRET_KEY|sk_live_/);
  }
});

test("raw x402 curl has valid continuation lines and required request fields", () => {
  const service = catalog.services.find(
    (candidate) => candidate.key === "scan",
  );
  const examples = buildIntegrationExamples({
    providerAgentId: catalog.providerAgentId,
    service,
  });

  assert.doesNotMatch(examples.curl, /\n\+/);
  assert.match(examples.curl, /-H "content-type: application\/json"/);
  assert.match(examples.curl, /-H "PAYMENT-SIGNATURE:/);
  assert.match(examples.curl, /--data/);
});

test("audit examples parse the audit contract instead of a scan verdict", () => {
  const service = catalog.services.find(
    (candidate) => candidate.key === "audit",
  );
  const examples = buildIntegrationExamples({
    providerAgentId: catalog.providerAgentId,
    service,
  });

  for (const example of [examples.python, examples.typescript]) {
    assert.match(example, /score/);
    assert.match(example, /grade/);
    assert.match(example, /results/);
    assert.match(example, /recommendations/);
    assert.doesNotMatch(example, /result\.verdict|result\.get\("verdict"\)/);
    assert.doesNotMatch(example, /Unknown Warden verdict/);
  }
});

test("three-decision gate allows original, requires sanitized output, and blocks execution", () => {
  assert.equal(
    decisionPayload(
      { verdict: "ALLOW", sanitized_payload: "ignored" },
      "original",
    ),
    "original",
  );
  assert.equal(
    decisionPayload(
      { verdict: "SANITIZE", sanitized_payload: "clean" },
      "original",
    ),
    "clean",
  );
  assert.throws(
    () => decisionPayload({ verdict: "SANITIZE" }, "original"),
    /sanitized_payload/,
  );
  assert.throws(
    () =>
      decisionPayload(
        { verdict: "BLOCK", recommendation: "Do not execute" },
        "original",
      ),
    /Do not execute/,
  );
  assert.throws(
    () => decisionPayload({ verdict: "UNKNOWN" }, "original"),
    /Unknown Warden verdict/,
  );
});

test("surface tab navigation wraps and supports Home and End", () => {
  assert.equal(nextTabIndex(0, "ArrowRight", 5), 1);
  assert.equal(nextTabIndex(4, "ArrowRight", 5), 0);
  assert.equal(nextTabIndex(0, "ArrowLeft", 5), 4);
  assert.equal(nextTabIndex(2, "Home", 5), 0);
  assert.equal(nextTabIndex(2, "End", 5), 4);
  assert.equal(nextTabIndex(2, "Enter", 5), 2);
});
