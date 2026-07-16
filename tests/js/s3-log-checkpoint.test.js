"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const {
  GENESIS_PREV_HASH,
  canonicalJson,
  sha256Hex,
  verifySignedLog,
} = require(path.join(__dirname, "..", "..", "site", "log.js"));

function prefixedBase64Url(prefix, bytes) {
  return `${prefix}:${Buffer.from(bytes).toString("base64url")}`;
}

function entry(seq, prevHash, endpointHost = "asp.example.org") {
  return {
    seq,
    ts: 1_789_000_000 + seq,
    event: "issued",
    attestation_id: `attestation-${seq}`,
    endpoint_host: endpointHost,
    status: "active",
    record_hash: "a".repeat(64),
    prev_hash: prevHash,
  };
}

async function signedMaterial() {
  const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const publicKey = await webcrypto.subtle.exportKey("raw", keys.publicKey);
  const first = entry(1, GENESIS_PREV_HASH);
  const second = entry(2, await sha256Hex(canonicalJson(first), webcrypto));
  const entries = [first, second];
  const core = {
    spec_version: "apa-log/0.1",
    issuer: "warden",
    seq: 2,
    head_hash: await sha256Hex(canonicalJson(second), webcrypto),
    issued_at: 1_789_000_002,
  };
  const signature = await webcrypto.subtle.sign(
    { name: "Ed25519" },
    keys.privateKey,
    new TextEncoder().encode(canonicalJson(core)),
  );
  const checkpoint = {
    ...core,
    issuer_sig: prefixedBase64Url("sig", signature),
  };
  const issuerDocument = {
    issuer: "warden",
    keys: [
      {
        kid: "warden-issuer-1",
        pub: prefixedBase64Url("ed25519", publicKey),
        not_after: Number.MAX_SAFE_INTEGER,
      },
    ],
  };
  return { entries, checkpoint, issuerDocument };
}

test("signed head accepts an honest log and rejects truncation", async () => {
  const { entries, checkpoint, issuerDocument } = await signedMaterial();

  const honest = await verifySignedLog(
    entries,
    checkpoint,
    issuerDocument,
    webcrypto,
  );
  const truncated = await verifySignedLog(
    entries.slice(0, 1),
    checkpoint,
    issuerDocument,
    webcrypto,
  );

  assert.equal(honest.ok, true);
  assert.equal(truncated.ok, false);
  assert.match(truncated.reason, /signed checkpoint/i);
});

test("signed head rejects an internally consistent full rewrite", async () => {
  const { entries, checkpoint, issuerDocument } = await signedMaterial();
  const rewritten = entries.map((item) => ({ ...item }));
  rewritten[0].endpoint_host = "rewritten.example.org";
  rewritten[1].prev_hash = await sha256Hex(
    canonicalJson(rewritten[0]),
    webcrypto,
  );

  const result = await verifySignedLog(
    rewritten,
    checkpoint,
    issuerDocument,
    webcrypto,
  );

  assert.equal(result.ok, false);
  assert.match(result.reason, /signed checkpoint/i);
});
