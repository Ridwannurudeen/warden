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
