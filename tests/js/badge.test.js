"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  auditEvidenceViewModel,
  badgeState,
  badgeViewModel,
  isValidAuditId,
  recordCorrection,
  resolveAuditId,
  safeBadgeShareUrl,
} = require(path.join(__dirname, "..", "..", "site", "badge.js"));

const endpointCanonicalizationCases = JSON.parse(
  fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "fixtures",
      "audit_endpoint_canonicalization.json",
    ),
    "utf8",
  ),
).cases;

function portableAuditEvidence(overrides = {}) {
  const limitations =
    "Point-in-time endpoint audit; not certification, continuous monitoring, or proof of future safety.";
  return {
    attestation: {
      spec_version: "apa-audit/0.1",
      predicate_type: "https://warden.gudman.xyz/spec/endpoint-audit/v1",
      audit_id: "0123456789abcdef",
      issuer: "warden",
      subject: "https://agent.example/scan?mode=strict",
      endpoint_host: "agent.example",
      battery_id: "warden-core-http",
      battery_version: "2026-07",
      battery_sha256: "a".repeat(64),
      blocked: 19,
      total: 20,
      conclusive: 20,
      inconclusive: 0,
      benign_total: 3,
      benign_passed: 3,
      grade: "A",
      consent_verified: true,
      liveness_passed: true,
      observed_on: "2026-07-18",
      issued_at: 1784000000,
      expires_at: 1786592000,
      limitations,
      log_seq: 7,
      issuer_sig: "sig:portable",
      ...overrides,
    },
    status: "revoked",
    verified: true,
    revoked_at: 1784000100,
    limitations,
  };
}

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

test("portable audit evidence keeps status, signature, battery, and limits separate", () => {
  const view = auditEvidenceViewModel(portableAuditEvidence());

  assert.deepEqual(view, {
    auditId: "0123456789abcdef",
    target: "agent.example",
    subject: "https://agent.example/scan?mode=strict",
    grade: "A",
    blocked: "19 / 20",
    observedOn: "2026-07-18",
    issuedAt: "2026-07-14T03:33:20.000Z",
    expiresAt: "2026-08-13T03:33:20.000Z",
    signature: "sig:portable",
    verified: true,
    status: "revoked",
    revokedAt: "2026-07-14T03:35:00.000Z",
    battery: "warden-core-http / 2026-07",
    batteryHash: "a".repeat(64),
    logSeq: "7",
    limitations:
      "Point-in-time endpoint audit; not certification, continuous monitoring, or proof of future safety.",
  });
});

test("portable audit evidence accepts the Python canonical endpoint fixtures", () => {
  for (const endpoint of endpointCanonicalizationCases) {
    const view = auditEvidenceViewModel(
      portableAuditEvidence({
        subject: endpoint.subject,
        endpoint_host: endpoint.endpoint_host,
      }),
    );

    assert.equal(view.subject, endpoint.subject, endpoint.name);
    assert.equal(view.target, endpoint.endpoint_host, endpoint.name);
  }
});

test("portable audit evidence rejects noncanonical Unicode and IPv6 authorities", () => {
  assert.throws(
    () =>
      auditEvidenceViewModel(
        portableAuditEvidence({
          subject: "https://faß.de/guard?check=idn",
          endpoint_host: "xn--fa-hia.de",
        }),
      ),
    /subject/,
  );
  assert.throws(
    () =>
      auditEvidenceViewModel(
        portableAuditEvidence({
          subject: "https://[2001:4860:4860::8888]:8443/scan?mode=strict",
          endpoint_host: "2001:4860:4860:0:0:0:0:8888",
        }),
      ),
    /subject/,
  );
  assert.throws(
    () =>
      auditEvidenceViewModel(
        portableAuditEvidence({
          subject: "https://agent.example",
          endpoint_host: "agent.example",
        }),
      ),
    /subject/,
  );
});

test("portable audit evidence rejects contradictory or malformed success", () => {
  assert.throws(
    () =>
      auditEvidenceViewModel({
        attestation: null,
        status: "active",
        verified: true,
        revoked_at: null,
        limitations: "missing record",
      }),
    /attestation/,
  );
  assert.throws(
    () =>
      auditEvidenceViewModel({
        attestation: { audit_id: "0123456789abcdef" },
        status: "invalid",
        verified: false,
        revoked_at: null,
        limitations: "invalid",
      }),
    /invalid|attestation/,
  );
});

test("badge states distinguish portable lifecycle from legacy integrity", () => {
  assert.equal(badgeState("active").integrity, "Active issuer evidence");
  assert.equal(badgeState("stale").integrity, "Valid signature · stale");
  assert.equal(badgeState("revoked").integrity, "Valid signature · revoked");
  assert.equal(badgeState("evidence-invalid").integrity, "Evidence rejected");
});

test("a badge that misdescribes its target carries a correction beside it", () => {
  // The PolicyPool F measured Warden's own probe reach, not the endpoint. The
  // record is signed and badges have no revocation path, so the correction has
  // to ride alongside rather than edit or hide the record.
  const note = recordCorrection("7885a4880f5d258e");

  assert.ok(note, "the known-misleading record must carry a correction");
  assert.match(note, /fault in our own probe, not a weakness in the endpoint/);
  assert.match(note, /declined to issue any grade/);

  assert.equal(recordCorrection("48f8635fbb71d696"), null);
  assert.equal(recordCorrection("unknown"), null);
  // A prototype key must not masquerade as a correction.
  assert.equal(recordCorrection("constructor"), null);
  assert.equal(recordCorrection("toString"), null);
});
