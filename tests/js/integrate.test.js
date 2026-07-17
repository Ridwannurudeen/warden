"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  buildIntegrationExamples,
  decisionPayload,
  nextTabIndex,
  setIntegrationCopiesEnabled,
  validateAuditResponse,
} = require(path.join(__dirname, "..", "..", "site", "integrate.js"));

const catalog = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "data", "warden-services.json"),
    "utf8",
  ),
);

function validAuditResponse() {
  return {
    score: 95,
    grade: "A",
    results: [
      {
        attack_class: "prompt_injection",
        sent: "Ignore previous instructions",
        blocked: true,
      },
    ],
    badge: "verified",
    recommendations: ["Keep the current policy enabled"],
    badge_record: {
      audit_id: "audit-123",
      target_host: "agent.example",
      grade: "A",
      score: 95,
      blocked: 1,
      total: 1,
      issued_at: "2026-07-16T00:00:00Z",
      consent_verified: true,
      signature: "signed-record",
    },
    consent_verified: true,
  };
}

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

test("paid HTTP examples use finite timeouts and never automate payment replay", () => {
  const service = catalog.services.find(
    (candidate) => candidate.key === "scan",
  );
  const examples = buildIntegrationExamples({
    providerAgentId: catalog.providerAgentId,
    service,
  });

  assert.match(examples.python, /timeout=30/);
  assert.match(examples.typescript, /AbortSignal\.timeout\(30_000\)/);
  for (const example of [examples.python, examples.typescript]) {
    assert.match(example, /Do not automatically retry/i);
    assert.doesNotMatch(example, /\bwhile\s*\(|\bfor\s*\(.*retry/is);
  }
});

test("integration examples reject non-canonical endpoints before generating code", () => {
  const service = catalog.services.find(
    (candidate) => candidate.key === "scan",
  );

  for (const endpoint of [
    "https://warden.gudman.xyz/scan; echo INJECTED",
    "https://evil.example/scan",
    "https://warden.gudman.xyz/scan?redirect=https://evil.example",
  ]) {
    assert.throws(
      () =>
        buildIntegrationExamples({
          providerAgentId: catalog.providerAgentId,
          service: { ...service, endpoint },
        }),
      /canonical Warden route/,
    );
  }

  const examples = buildIntegrationExamples({
    providerAgentId: catalog.providerAgentId,
    service,
  });
  assert.match(examples.curl, /curl -i 'https:\/\/warden\.gudman\.xyz\/scan'/);
  assert.match(
    examples.curl,
    /curl --fail-with-body -sS 'https:\/\/warden\.gudman\.xyz\/scan'/,
  );
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
  assert.match(
    examples.typescript,
    /function validateAuditResponse\([\s\S]*asserts value is WardenAuditResponse/,
  );
  assert.match(examples.typescript, /validateAuditResponse\(result\);/);
  assert.doesNotMatch(examples.typescript, /result as WardenAuditResponse/);
});

test("audit response validation accepts the full contract and inert extra fields", () => {
  const response = validAuditResponse();
  response.extra = "ignored";
  response.results[0].extra = "ignored";
  response.badge_record.extra = "ignored";

  assert.equal(validateAuditResponse(response), response);
  assert.equal(
    validateAuditResponse({
      ...response,
      badge_record: null,
      consent_verified: false,
    }).badge_record,
    null,
  );
});

test("audit response validation rejects malformed boundary fields", () => {
  const cases = [
    ["object", null],
    ["finite score", { score: Number.NaN }],
    ["score range", { score: 101 }],
    ["grade", { grade: "E" }],
    ["results", { results: [{ attack_class: 1, sent: "x", blocked: true }] }],
    ["results", { results: [{ attack_class: "x", sent: 1, blocked: true }] }],
    ["results", { results: [{ attack_class: "x", sent: "x", blocked: 1 }] }],
    ["badge", { badge: null }],
    ["recommendations", { recommendations: ["valid", 1] }],
    ["badge_record", { badge_record: {} }],
    [
      "badge_record",
      { badge_record: { ...validAuditResponse().badge_record, score: "95" } },
    ],
    [
      "badge_record",
      { badge_record: { ...validAuditResponse().badge_record, blocked: 0.5 } },
    ],
    [
      "badge_record",
      { badge_record: { ...validAuditResponse().badge_record, total: "1" } },
    ],
    [
      "badge_record",
      {
        badge_record: {
          ...validAuditResponse().badge_record,
          consent_verified: "yes",
        },
      },
    ],
    ["consent_verified", { consent_verified: null }],
  ];

  for (const [label, replacement] of cases) {
    const candidate =
      replacement === null ? null : { ...validAuditResponse(), ...replacement };
    assert.throws(() => validateAuditResponse(candidate), new RegExp(label));
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

test("integration copy controls stay locked until examples are valid", () => {
  const buttons = [{ disabled: false }, { disabled: false }];

  setIntegrationCopiesEnabled(buttons, false);
  assert.deepEqual(
    buttons.map((button) => button.disabled),
    [true, true],
  );

  setIntegrationCopiesEnabled(buttons, true);
  assert.deepEqual(
    buttons.map((button) => button.disabled),
    [false, false],
  );
});
