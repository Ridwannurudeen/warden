"use strict";

const assert = require("node:assert/strict");
const { createHash, webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..", "..");
const fixture = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "fixtures", "apa_cross_language.json"),
    "utf8",
  ),
);
const apaVerifier = require(path.join(root, "site", "verify.js"));
const transparencyLog = require(path.join(root, "site", "log.js"));
const homeProofPath = path.join(root, "site", "home-proof.js");
const { proofPresentation, referenceMaterial, runOfflineProof } = require(
  homeProofPath,
);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

test("embedded proof material preserves the signed cross-language fixture", () => {
  const material = referenceMaterial();

  assert.deepEqual(material.attestation, fixture.attestation);
  assert.deepEqual(material.issuerDocument, fixture.issuer_document);
  assert.equal(material.logEntries.length, 2);
  assert.equal(
    material.logEntries[0].record_hash,
    sha256(apaVerifier.canonicalJson(fixture.attestation)),
  );
  assert.equal(
    material.logEntries[1].record_hash,
    sha256(apaVerifier.canonicalJson(fixture.revoked_attestation)),
  );

  material.attestation.status = "revoked";
  material.logEntries[0].endpoint_host = "changed.example";
  const freshMaterial = referenceMaterial();
  assert.equal(freshMaterial.attestation.status, "active");
  assert.equal(freshMaterial.logEntries[0].endpoint_host, "agent.example");
});

test("explicit offline proof verifies the signature, chain, and one-byte tamper", async () => {
  const result = await runOfflineProof({
    cryptoImpl: webcrypto,
    nowSeconds: fixture.attestation.expires_at + 1,
  });

  assert.equal(result.attestation.signatureValid, true);
  assert.equal(result.attestation.accepted, false);
  assert.equal(result.attestation.code, "expired");
  assert.equal(result.attestation.freshness, "archival");
  assert.equal(result.honestChain.ok, true);
  assert.equal(result.honestChain.total, 2);
  assert.match(result.honestChain.headHash, /^[0-9a-f]{64}$/);
  assert.equal(result.tamperedChain.ok, false);
  assert.equal(result.tamperedChain.index, 1);
  assert.match(result.tamperedChain.reason, /previous entry hash/i);

  const before = Buffer.from(result.tamper.before, "utf8");
  const after = Buffer.from(result.tamper.after, "utf8");
  assert.equal(before.length, after.length);
  assert.equal(
    before.reduce(
      (differences, byte, index) => differences + Number(byte !== after[index]),
      0,
    ),
    1,
  );
});

test("offline runner never calls fetch or any server", async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = () => {
    fetchCalls += 1;
    throw new Error("offline proof attempted a network request");
  };

  try {
    const result = await runOfflineProof({
      cryptoImpl: webcrypto,
      nowSeconds: fixture.attestation.expires_at + 1,
    });
    assert.equal(result.honestChain.ok, true);
    assert.equal(result.tamperedChain.ok, false);
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }

  const source = fs.readFileSync(homeProofPath, "utf8");
  assert.doesNotMatch(source, /\bfetch\s*\(/);
});

test("presentation states archival freshness without weakening the proof", async () => {
  const result = await runOfflineProof({
    cryptoImpl: webcrypto,
    nowSeconds: fixture.attestation.expires_at + 1,
  });
  const presentation = proofPresentation(result);

  assert.equal(presentation.passed, true);
  assert.equal(presentation.signature.state, "verified");
  assert.match(presentation.signature.label, /signature verified/i);
  assert.match(presentation.signature.detail, /archival|expired/i);
  assert.equal(presentation.honestChain.state, "verified");
  assert.equal(presentation.tamperedChain.state, "rejected");
  assert.match(presentation.tamperedChain.detail, /entry 2/i);
  assert.match(presentation.summary, /offline/i);
});
