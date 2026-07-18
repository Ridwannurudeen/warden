"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const {
  GENESIS_PREV_HASH,
  canonicalJson,
  sha256Hex,
  verifyAnchorHistory,
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
    keys,
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

async function checkpointFor(keys, entries, seq, issuedAt) {
  const core = {
    spec_version: "apa-log/0.1",
    issuer: "warden",
    seq,
    head_hash:
      seq === 0
        ? GENESIS_PREV_HASH
        : await sha256Hex(canonicalJson(entries[seq - 1]), webcrypto),
    issued_at: issuedAt,
  };
  const signature = await webcrypto.subtle.sign(
    { name: "Ed25519" },
    keys.privateKey,
    new TextEncoder().encode(canonicalJson(core)),
  );
  return {
    ...core,
    issuer_sig: prefixedBase64Url("sig", signature),
  };
}

async function publishedHistory() {
  const { keys, entries, issuerDocument } = await signedPrefixWithAppend();
  const first = {
    anchor_seq: 1,
    previous_anchor_hash: GENESIS_PREV_HASH,
    checkpoint: await checkpointFor(keys, entries, 2, 1_789_000_002),
  };
  const firstHead = await sha256Hex(canonicalJson(first), webcrypto);
  const second = {
    anchor_seq: 2,
    previous_anchor_hash: firstHead,
    checkpoint: await checkpointFor(keys, entries, 3, 1_789_000_003),
  };
  const history = {
    schema_version: 1,
    status: "published",
    history_head_hash: await sha256Hex(canonicalJson(second), webcrypto),
    anchors: [first, second],
  };
  return { entries, firstHead, history, issuerDocument };
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

test("public anchor history verifies every signed prefix and a retained head", async () => {
  const { entries, firstHead, history, issuerDocument } =
    await publishedHistory();

  const result = await verifyAnchorHistory(
    history,
    entries,
    issuerDocument,
    webcrypto,
    firstHead,
  );

  assert.equal(result.ok, true);
  assert.equal(result.status, "verified");
  assert.equal(result.anchorCount, 2);
  assert.equal(result.headHash, history.history_head_hash);
  assert.equal(result.pinned, true);
  assert.equal(result.latestCheckpoint.seq, 3);
});

test("a coherent history replacement is visible to a retained prior head", async () => {
  const { entries, firstHead, history, issuerDocument } =
    await publishedHistory();
  const replacementAnchor = {
    anchor_seq: 1,
    previous_anchor_hash: GENESIS_PREV_HASH,
    checkpoint: history.anchors[1].checkpoint,
  };
  const replacement = {
    schema_version: 1,
    status: "published",
    history_head_hash: await sha256Hex(
      canonicalJson(replacementAnchor),
      webcrypto,
    ),
    anchors: [replacementAnchor],
  };

  const unpinned = await verifyAnchorHistory(
    replacement,
    entries,
    issuerDocument,
    webcrypto,
  );
  const pinned = await verifyAnchorHistory(
    replacement,
    entries,
    issuerDocument,
    webcrypto,
    firstHead,
  );

  assert.equal(unpinned.ok, true);
  assert.equal(unpinned.pinned, false);
  assert.equal(pinned.ok, false);
  assert.equal(pinned.status, "rejected");
  assert.match(pinned.reason, /retained history head/i);
});

test("broken and unpublished public histories stay explicit", async () => {
  const { entries, history, issuerDocument } = await publishedHistory();
  const broken = structuredClone(history);
  broken.anchors[1].previous_anchor_hash = GENESIS_PREV_HASH;

  const rejected = await verifyAnchorHistory(
    broken,
    entries,
    issuerDocument,
    webcrypto,
  );
  const unpublished = await verifyAnchorHistory(
    {
      schema_version: 1,
      status: "unpublished",
      history_head_hash: GENESIS_PREV_HASH,
      anchors: [],
    },
    entries,
    issuerDocument,
    webcrypto,
  );

  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, "rejected");
  assert.match(rejected.reason, /chain/i);
  assert.equal(unpublished.ok, false);
  assert.equal(unpublished.status, "unpublished");
});

test("anchor history verification hashes log prefixes in linear time", async () => {
  const size = 24;
  const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const publicKey = await webcrypto.subtle.exportKey("raw", keys.publicKey);
  const entries = [];
  const anchors = [];
  let previousEntryHash = GENESIS_PREV_HASH;
  let previousAnchorHash = GENESIS_PREV_HASH;
  for (let sequence = 1; sequence <= size; sequence += 1) {
    const currentEntry = entry(sequence, previousEntryHash);
    entries.push(currentEntry);
    previousEntryHash = await sha256Hex(canonicalJson(currentEntry), webcrypto);
    const anchor = {
      anchor_seq: sequence,
      previous_anchor_hash: previousAnchorHash,
      checkpoint: await checkpointFor(
        keys,
        entries,
        sequence,
        1_789_100_000 + sequence,
      ),
    };
    anchors.push(anchor);
    previousAnchorHash = await sha256Hex(canonicalJson(anchor), webcrypto);
  }
  const history = {
    schema_version: 1,
    status: "published",
    history_head_hash: previousAnchorHash,
    anchors,
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
  let digestCalls = 0;
  const countingCrypto = {
    subtle: {
      digest(...args) {
        digestCalls += 1;
        return webcrypto.subtle.digest(...args);
      },
      importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
      verify: webcrypto.subtle.verify.bind(webcrypto.subtle),
    },
  };

  const result = await verifyAnchorHistory(
    history,
    entries,
    issuerDocument,
    countingCrypto,
  );

  assert.equal(result.ok, true);
  assert.equal(digestCalls, size * 2);
});
