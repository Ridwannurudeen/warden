"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const lineagePath = path.join(__dirname, "..", "..", "site", "lineage.js");
const {
  fetchLineage,
  gradeTrajectory,
  normalizeLineage,
  verifyLogInclusion,
} = require(lineagePath);
const logPath = path.join(__dirname, "..", "..", "site", "log.js");
const transparencyLog = require(logPath);

function attestation(auditId, grade, logSeq) {
  return {
    audit_id: auditId,
    grade,
    blocked: grade === "A" ? 20 : 8,
    total: 20,
    log_seq: logSeq,
    observed_on: "2026-07-10",
  };
}

function entry(auditId, grade, logSeq, occurredAt, overrides = {}) {
  return {
    comparison: "initial",
    reason: "first conclusive audit",
    occurred_at: occurredAt,
    accepted_as_baseline: true,
    enrollment_revision: 1,
    status: "active",
    verified: true,
    revoked_at: null,
    attestation: attestation(auditId, grade, logSeq),
    ...overrides,
  };
}

function lineage(entries) {
  return {
    schema_version: 1,
    target_id: "enrolled-target",
    total: entries.length,
    limitations: "Point-in-time evidence, not certification.",
    entries,
  };
}

const FIRST = "0".repeat(15) + "1";
const SECOND = "0".repeat(15) + "2";

test("ordered lineage renders a grade trajectory", () => {
  const parsed = normalizeLineage(
    lineage([
      entry(FIRST, "F", 1, 1_000),
      entry(SECOND, "A", 2, 2_000, { comparison: "improved" }),
    ]),
  );

  assert.equal(parsed.total, 2);
  assert.equal(gradeTrajectory(parsed), "F → A");
  assert.deepEqual(
    parsed.entries.map((item) => item.auditId),
    [FIRST, SECOND],
  );
});

test("an unverified or out-of-order lineage is refused", () => {
  assert.throws(
    () =>
      normalizeLineage(
        lineage([entry(FIRST, "A", 1, 1_000, { verified: false })]),
      ),
    /not verified/,
  );
  assert.throws(
    () =>
      normalizeLineage(
        lineage([entry(SECOND, "A", 2, 5_000), entry(FIRST, "F", 1, 1_000)]),
      ),
    /observation order/,
  );
  const mismatched = lineage([entry(FIRST, "A", 1, 1_000)]);
  mismatched.total = 7;
  assert.throws(() => normalizeLineage(mismatched), /total does not match/);
});

test("an unknown target yields an empty state rather than an error", async () => {
  const result = await fetchLineage("missing-target", async () => ({
    status: 404,
    ok: false,
  }));
  assert.equal(result, null);
});

test("a malformed target id never reaches the network", async () => {
  let called = false;
  await assert.rejects(
    () =>
      fetchLineage("bad target!", async () => {
        called = true;
        return { status: 200, ok: true, json: async () => ({}) };
      }),
    /target id/,
  );
  assert.equal(called, false);
});

test("log inclusion verifies against a real chain and fails on tampering", async () => {
  const genesis = {
    seq: 1,
    ts: 1_789_000_001,
    event: "audit-issued",
    attestation_id: "attestation-1",
    endpoint_host: "asp.example.org",
    status: "active",
    record_hash: "a".repeat(64),
    prev_hash: transparencyLog.GENESIS_PREV_HASH,
  };
  const second = {
    ...genesis,
    seq: 2,
    ts: 1_789_000_002,
    attestation_id: "attestation-2",
    prev_hash: await transparencyLog.sha256Hex(
      transparencyLog.canonicalJson(genesis),
      webcrypto,
    ),
  };
  const parsed = normalizeLineage(
    lineage([
      entry(FIRST, "F", 1, 1_000),
      entry(SECOND, "A", 2, 2_000, { comparison: "improved" }),
    ]),
  );

  const included = await verifyLogInclusion(
    parsed,
    {
      ...transparencyLog,
      fetchLogPages: async () => ({ entries: [genesis, second] }),
    },
    async () => ({ ok: true, status: 200, json: async () => ({}) }),
    webcrypto,
  );
  assert.equal(included.ok, true);
  assert.equal(included.checked, 2);

  // A record the verified log does not contain must not be reported as included.
  const absent = await verifyLogInclusion(
    parsed,
    { ...transparencyLog, fetchLogPages: async () => ({ entries: [genesis] }) },
    async () => ({ ok: true, status: 200, json: async () => ({}) }),
    webcrypto,
  );
  assert.equal(absent.ok, false);
  assert.match(absent.reason, /not present in the verified log/);

  // A broken hash chain must fail before inclusion is even considered.
  const tampered = { ...second, prev_hash: "b".repeat(64) };
  const broken = await verifyLogInclusion(
    parsed,
    {
      ...transparencyLog,
      fetchLogPages: async () => ({ entries: [genesis, tampered] }),
    },
    async () => ({ ok: true, status: 200, json: async () => ({}) }),
    webcrypto,
  );
  assert.equal(broken.ok, false);
});
