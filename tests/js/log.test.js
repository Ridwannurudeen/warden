"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const logPath = path.join(__dirname, "..", "..", "site", "log.js");
const {
  GENESIS_PREV_HASH,
  canonicalJson,
  normalizeLogPayload,
  sha256Hex,
  verifyLogChain,
} = require(logPath);
const BREAKER_ID = "0123456789abcdef0123456789abcdef";
const BENCHMARK_CASE_ID = "gauntlet-0123456789abcdef";
const AUDIT_ID = "0123456789abcdef";

function entry(seq, prevHash, overrides = {}) {
  return {
    seq,
    ts: 1_789_000_000 + seq,
    event: "issued",
    attestation_id: `attestation-${seq}`,
    endpoint_host: "asp.example.org",
    status: "active",
    record_hash: "a".repeat(64),
    prev_hash: prevHash,
    ...overrides,
  };
}

function breakerEntry(seq, prevHash, overrides = {}) {
  return {
    seq,
    ts: 1_789_000_000 + seq,
    event: "breaker-confirmed",
    record_type: "breaker-certificate",
    certificate_id: BREAKER_ID,
    benchmark_case_id: BENCHMARK_CASE_ID,
    record_hash: "c".repeat(64),
    prev_hash: prevHash,
    ...overrides,
  };
}

function auditEntry(seq, prevHash, overrides = {}) {
  return {
    seq,
    ts: 1_789_000_000 + seq,
    event: "audit-issued",
    record_type: "endpoint-audit-attestation",
    audit_id: AUDIT_ID,
    endpoint_host: "audit.example.org",
    record_hash: "e".repeat(64),
    prev_hash: prevHash,
    ...overrides,
  };
}

async function validChain() {
  const first = entry(1, GENESIS_PREV_HASH);
  const second = entry(2, await sha256Hex(canonicalJson(first), webcrypto), {
    event: "revoked",
    status: "revoked",
    record_hash: "b".repeat(64),
  });
  return [first, second];
}

test("canonical JSON recursively sorts keys without ASCII rewriting", () => {
  assert.equal(
    canonicalJson({ z: "é", a: { b: 2, a: 1 } }),
    '{"a":{"a":1,"b":2},"z":"é"}',
  );
});

test("log payload validation rejects incomplete or contradictory envelopes", () => {
  const entries = [entry(1, GENESIS_PREV_HASH)];
  assert.deepEqual(normalizeLogPayload({ entries, total: 1 }), entries);
  assert.throws(
    () => normalizeLogPayload({ entries, total: 2 }),
    /does not match/,
  );
  assert.throws(
    () =>
      normalizeLogPayload({
        entries: [{ ...entries[0], record_hash: "not-a-hash" }],
        total: 1,
      }),
    /record_hash/,
  );
  for (const field of ["seq", "ts"]) {
    assert.throws(
      () =>
        normalizeLogPayload({
          entries: [
            {
              ...entries[0],
              [field]: Number.MAX_SAFE_INTEGER + 1,
            },
          ],
          total: 1,
        }),
      /safe integer/,
    );
  }
});

test("log payload normalization accepts typed BREAKER entries and rejects ambiguous subjects", () => {
  const breaker = breakerEntry(1, GENESIS_PREV_HASH);
  assert.deepEqual(normalizeLogPayload({ entries: [breaker], total: 1 }), [
    breaker,
  ]);
  assert.throws(
    () =>
      normalizeLogPayload({
        entries: [
          breakerEntry(1, GENESIS_PREV_HASH, {
            certificate_id: undefined,
          }),
        ],
        total: 1,
      }),
    /certificate_id/,
  );
  assert.throws(
    () =>
      normalizeLogPayload({
        entries: [
          breakerEntry(1, GENESIS_PREV_HASH, {
            benchmark_case_id: undefined,
          }),
        ],
        total: 1,
      }),
    /benchmark_case_id/,
  );
  assert.throws(
    () =>
      normalizeLogPayload({
        entries: [
          breakerEntry(1, GENESIS_PREV_HASH, {
            attestation_id: "ambiguous-subject",
          }),
        ],
        total: 1,
      }),
    /attestation_id/,
  );
  assert.throws(
    () =>
      normalizeLogPayload({
        entries: [
          breakerEntry(1, GENESIS_PREV_HASH, {
            record_type: "attestation",
          }),
        ],
        total: 1,
      }),
    /record_type|attestation_id/,
  );
});

test("log payload normalization accepts endpoint-audit lifecycle entries and rejects ambiguous shapes", () => {
  const issued = auditEntry(1, GENESIS_PREV_HASH);
  const revoked = auditEntry(2, "f".repeat(64), {
    event: "audit-revoked",
  });
  assert.deepEqual(
    normalizeLogPayload({ entries: [issued, revoked], total: 2 }),
    [issued, revoked],
  );
  for (const overrides of [
    { event: "issued" },
    { audit_id: "0123456789abcdeF" },
    { endpoint_host: "" },
    { attestation_id: "ambiguous-subject" },
    { record_type: "endpoint-audit" },
  ]) {
    assert.throws(
      () =>
        normalizeLogPayload({
          entries: [auditEntry(1, GENESIS_PREV_HASH, overrides)],
          total: 1,
        }),
      /audit|record_type|endpoint_host|attestation_id/,
    );
  }
});

test("browser-compatible SHA-256 verifies continuity and detects tampering", async () => {
  const entries = await validChain();
  const verified = await verifyLogChain(entries, webcrypto);
  assert.equal(verified.ok, true);
  assert.equal(verified.total, 2);
  assert.match(verified.headHash, /^[0-9a-f]{64}$/);

  const tampered = entries.map((item) => ({ ...item }));
  tampered[0].status = "forged";
  const rejected = await verifyLogChain(tampered, webcrypto);
  assert.equal(rejected.ok, false);
  assert.equal(rejected.index, 1);
  assert.match(rejected.reason, /previous entry hash/);
});

test("mixed APA and BREAKER entries verify as one chain and reject breaker tampering", async () => {
  const first = entry(1, GENESIS_PREV_HASH);
  const second = breakerEntry(
    2,
    await sha256Hex(canonicalJson(first), webcrypto),
  );
  const third = entry(3, await sha256Hex(canonicalJson(second), webcrypto), {
    attestation_id: "attestation-3",
    record_hash: "d".repeat(64),
  });
  const entries = [first, second, third];

  const verified = await verifyLogChain(entries, webcrypto);
  assert.equal(verified.ok, true);
  assert.equal(verified.total, 3);

  const tampered = entries.map((item) => ({ ...item }));
  tampered[1].certificate_id = "f".repeat(32);
  const rejected = await verifyLogChain(tampered, webcrypto);
  assert.equal(rejected.ok, false);
  assert.equal(rejected.index, 2);
  assert.match(rejected.reason, /previous entry hash/);
});

test("APA, BREAKER, and endpoint-audit entries verify in one chain", async () => {
  const first = entry(1, GENESIS_PREV_HASH);
  const second = breakerEntry(
    2,
    await sha256Hex(canonicalJson(first), webcrypto),
  );
  const third = auditEntry(
    3,
    await sha256Hex(canonicalJson(second), webcrypto),
  );
  const fourth = auditEntry(
    4,
    await sha256Hex(canonicalJson(third), webcrypto),
    {
      event: "audit-revoked",
    },
  );

  const verified = await verifyLogChain(
    [first, second, third, fourth],
    webcrypto,
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.total, 4);
});

test("sequence and genesis failures stay distinguishable from valid chains", async () => {
  const badGenesis = [entry(1, "f".repeat(64))];
  const genesisResult = await verifyLogChain(badGenesis, webcrypto);
  assert.equal(genesisResult.ok, false);
  assert.match(genesisResult.reason, /genesis/);

  const badSequence = [entry(2, GENESIS_PREV_HASH)];
  const sequenceResult = await verifyLogChain(badSequence, webcrypto);
  assert.equal(sequenceResult.ok, false);
  assert.match(sequenceResult.reason, /sequence/);
});

test("human log renderer uses text nodes and never HTML injection", () => {
  const source = fs.readFileSync(logPath, "utf8");
  assert.match(source, /textContent/);
  assert.match(source, /Endpoint audit/);
  assert.match(source, /Audit ID/);
  assert.doesNotMatch(source, /innerHTML|insertAdjacentHTML|document\.write/);
});

test("empty log renders a no-chain state instead of verified continuity", () => {
  const source = fs.readFileSync(logPath, "utf8");
  const emptyState = source.indexOf('container.dataset.state = "empty"');
  const verifiedState = source.indexOf('container.dataset.state = "verified"');

  assert.notEqual(emptyState, -1);
  assert.ok(emptyState < verifiedState);
  const emptyBranch = source.slice(emptyState, verifiedState);
  assert.match(emptyBranch, /No chain \(empty log\)/);
  assert.match(emptyBranch, /No entries/);
  assert.match(emptyBranch, /There is no entry chain to verify/);
  assert.match(emptyBranch, /return;/);
});
