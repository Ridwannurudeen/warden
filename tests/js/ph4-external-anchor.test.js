"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const {
  GENESIS_PREV_HASH,
  canonicalJson,
  sha256Hex,
  verifyPublishedAnchor,
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

async function signedPrefixWithAppend() {
  const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const publicKey = await webcrypto.subtle.exportKey("raw", keys.publicKey);
  const first = entry(1, GENESIS_PREV_HASH);
  const second = entry(2, await sha256Hex(canonicalJson(first), webcrypto));
  const third = entry(3, await sha256Hex(canonicalJson(second), webcrypto));
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
  return {
    entries: [first, second, third],
    publication: {
      schema_version: 1,
      status: "published",
      checkpoint,
    },
    issuerDocument: {
      issuer: "warden",
      keys: [
        {
          kid: "warden-issuer-1",
          pub: prefixedBase64Url("ed25519", publicKey),
          not_after: Number.MAX_SAFE_INTEGER,
        },
      ],
    },
  };
}

test("published checkpoint accepts an honest append after its signed prefix", async () => {
  const { entries, publication, issuerDocument } =
    await signedPrefixWithAppend();

  const result = await verifyPublishedAnchor(
    entries,
    publication,
    issuerDocument,
    webcrypto,
  );

  assert.equal(result.ok, true);
  assert.equal(result.status, "verified");
  assert.equal(result.pinnedSeq, 2);
});

test("published checkpoint rejects a consistent rewrite and truncation", async () => {
  const { entries, publication, issuerDocument } =
    await signedPrefixWithAppend();
  const rewritten = entries.map((item) => ({ ...item }));
  rewritten[0].endpoint_host = "rewritten.example.org";
  rewritten[1].prev_hash = await sha256Hex(
    canonicalJson(rewritten[0]),
    webcrypto,
  );
  rewritten[2].prev_hash = await sha256Hex(
    canonicalJson(rewritten[1]),
    webcrypto,
  );

  const rewriteResult = await verifyPublishedAnchor(
    rewritten,
    publication,
    issuerDocument,
    webcrypto,
  );
  const truncationResult = await verifyPublishedAnchor(
    entries.slice(0, 1),
    publication,
    issuerDocument,
    webcrypto,
  );

  assert.equal(rewriteResult.ok, false);
  assert.match(rewriteResult.reason, /published checkpoint/i);
  assert.equal(truncationResult.ok, false);
  assert.match(truncationResult.reason, /truncated/i);
});

test("missing, unpublished, and invalid pins stay explicit offline", async () => {
  const { entries, issuerDocument } = await signedPrefixWithAppend();
  const missing = await verifyPublishedAnchor(
    entries,
    null,
    issuerDocument,
    webcrypto,
  );
  const unpublished = await verifyPublishedAnchor(
    entries,
    { schema_version: 1, status: "unpublished", checkpoint: null },
    issuerDocument,
    webcrypto,
  );
  const invalid = await verifyPublishedAnchor(
    entries,
    { schema_version: 1, status: "published", checkpoint: null },
    issuerDocument,
    webcrypto,
  );

  assert.deepEqual(
    [missing.status, unpublished.status, invalid.status],
    ["missing", "unpublished", "invalid"],
  );
  assert.equal(missing.ok, false);
  assert.equal(unpublished.ok, false);
  assert.equal(invalid.ok, false);
  assert.match(missing.reason, /not available/i);
  assert.match(unpublished.reason, /not been published/i);
  assert.match(invalid.reason, /invalid/i);
});
