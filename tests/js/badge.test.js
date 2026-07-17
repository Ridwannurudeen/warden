"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  badgeState,
  badgeViewModel,
  isValidAuditId,
  resolveAuditId,
  safeBadgeShareUrl,
} = require(path.join(__dirname, "..", "..", "site", "badge.js"));

test("badge detail resolves query and plural clean-route ids", () => {
  assert.equal(resolveAuditId("?id=query-id", "/badge.html"), "query-id");
  assert.equal(resolveAuditId("", "/badges/path-id"), "path-id");
  assert.equal(resolveAuditId("", "/badges"), "");
});

test("badge detail accepts only issued 16-character lowercase hex ids", () => {
  assert.equal(isValidAuditId("0123456789abcdef"), true);
  assert.equal(isValidAuditId("0123456789abcde"), false);
  assert.equal(isValidAuditId("0123456789abcdeF"), false);
  assert.equal(isValidAuditId("0123456789abcdef0"), false);
  assert.equal(isValidAuditId("../../etc/passwd"), false);
});

test("badge view model keeps integrity, result, target, and time fields separate", () => {
  const view = badgeViewModel({
    verified: true,
    badge: {
      audit_id: "0123456789abcdef",
      target_host: "agent.example",
      grade: "A",
      score: 95,
      blocked: 19,
      total: 20,
      issued_at: "2026-07-13T10:00:00Z",
      signature: "signed-record",
    },
  });

  assert.deepEqual(view, {
    auditId: "0123456789abcdef",
    target: "agent.example",
    grade: "A",
    score: "95.00 / 100",
    blocked: "19 / 20",
    issuedAt: "2026-07-13T10:00:00Z",
    signature: "signed-record",
    verified: true,
  });
});

test("badge state labels distinguish lookup failures from signature failure", () => {
  assert.equal(badgeState("loading").integrity, "Unknown until checked");
  assert.equal(badgeState("invalid").integrity, "Not checked");
  assert.equal(badgeState("empty").integrity, "No issued record");
  assert.equal(badgeState("error").integrity, "Unavailable");
  assert.equal(badgeState("verified").integrity, "Signature verified");
  assert.equal(badgeState("signature-invalid").integrity, "Signature invalid");
  assert.throws(() => badgeState("unknown"), /Unknown badge state/);
});

test("badge sharing produces only a canonical same-origin verification URL", () => {
  assert.equal(
    safeBadgeShareUrl(
      "https://warden.gudman.xyz/anything?secret=value",
      "0123456789abcdef",
    ),
    "https://warden.gudman.xyz/badges/0123456789abcdef",
  );
  assert.throws(
    () => safeBadgeShareUrl("https://warden.gudman.xyz", "../../etc/passwd"),
    /valid audit ID/,
  );
  assert.throws(
    () => safeBadgeShareUrl("javascript:alert(1)", "0123456789abcdef"),
    /HTTP origin/,
  );
});
