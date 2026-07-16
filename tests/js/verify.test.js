"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  APA_BOUNDARY,
  KEY_THEFT_BOUNDARY,
  TOFU_BOUNDARY,
  ApaVerifierError,
  canonicalJson,
  decodeBase64Url,
  loadVerificationMaterial,
  parseVerifierInput,
  verifyApaAttestation,
} = require(path.join(__dirname, "..", "..", "site", "verify.js"));

const fixture = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "fixtures", "apa_cross_language.json"),
    "utf8",
  ),
);
const BASE_URL = "https://warden.gudman.xyz/verify";
const ATTESTATION_ID = "0123456789abcdef0123456789abcdef";

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return payload;
    },
  };
}

function nonCanonicalBase64Url(value) {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const separator = value.indexOf(":") + 1;
  const encoded = value.slice(separator);
  const lastIndex = alphabet.indexOf(encoded.at(-1));
  assert.equal(lastIndex % 4, 0);
  return `${value.slice(0, separator)}${encoded.slice(0, -1)}${alphabet[lastIndex + 1]}`;
}

test("canonical JSON matches Python recursively, including Unicode code-point key order", () => {
  assert.equal(
    canonicalJson({ z: { b: "\u03bb", a: 1 }, a: [true, null, "guard"] }),
    '{"a":[true,null,"guard"],"z":{"a":1,"b":"\u03bb"}}',
  );
  assert.equal(
    canonicalJson({ "\ud83d\ude00": 1, "\ue000": 2 }),
    '{"\ue000":2,"\ud83d\ude00":1}',
  );
  assert.throws(() => canonicalJson({ nested: { score: 0.5 } }), /integer/);
  assert.throws(
    () => canonicalJson({ count: Number.MAX_SAFE_INTEGER + 1 }),
    /safe integer/,
  );
});

test("Python-shaped fixture verifies independently with WebCrypto Ed25519", async () => {
  const result = await verifyApaAttestation(
    fixture.attestation,
    fixture.issuer_document,
    { nowSeconds: 1784000100 },
  );

  assert.equal(result.accepted, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.effectiveStatus, "active");
  assert.equal(result.issuerKey.kid, "python-fixture-1");
});

test("retired issuer keys are selected by the signed verified_at cutoff", async () => {
  const rotatedDocument = {
    issuer: "warden",
    keys: [
      {
        kid: "current",
        pub: fixture.attestation.pub,
        not_after: Number.MAX_SAFE_INTEGER,
      },
      {
        ...fixture.issuer_document.keys[0],
        kid: "retired",
        not_after: fixture.attestation.verified_at,
      },
    ],
  };

  const result = await verifyApaAttestation(
    fixture.attestation,
    rotatedDocument,
    { nowSeconds: 1784000100 },
  );

  assert.equal(result.accepted, true);
  assert.equal(result.issuerKey.kid, "retired");

  rotatedDocument.keys[1].not_after = fixture.attestation.verified_at - 1;
  const outsideCutoff = await verifyApaAttestation(
    fixture.attestation,
    rotatedDocument,
    { nowSeconds: 1784000100 },
  );
  assert.equal(outsideCutoff.accepted, false);
  assert.equal(outsideCutoff.code, "signature-invalid");
});

test("duplicate, malformed, and out-of-order issuer histories fail closed", async () => {
  const validKey = {
    ...fixture.issuer_document.keys[0],
    not_after: Number.MAX_SAFE_INTEGER,
  };
  const documents = [
    { ...fixture.issuer_document, extra: "unsupported" },
    {
      issuer: "warden",
      keys: [
        validKey,
        { ...validKey, not_after: fixture.attestation.verified_at },
      ],
    },
    {
      issuer: "warden",
      keys: [
        validKey,
        {
          ...validKey,
          kid: "duplicate-pub",
          not_after: fixture.attestation.verified_at,
        },
      ],
    },
    { issuer: "warden", keys: [{ ...validKey, not_after: null }] },
    { issuer: "warden", keys: [{ ...validKey, not_after: true }] },
    { issuer: "warden", keys: [{ ...validKey, extra: "unsupported" }] },
    {
      issuer: "warden",
      keys: [{ ...validKey, not_after: Number.MAX_SAFE_INTEGER - 1 }],
    },
    {
      issuer: "warden",
      keys: [
        validKey,
        {
          ...validKey,
          kid: "retired-sentinel",
          pub: fixture.attestation.pub,
          not_after: Number.MAX_SAFE_INTEGER,
        },
      ],
    },
    {
      issuer: "warden",
      keys: [
        {
          ...validKey,
          pub: nonCanonicalBase64Url(validKey.pub),
        },
      ],
    },
    {
      issuer: "warden",
      keys: [
        validKey,
        {
          ...validKey,
          kid: "decoded-duplicate",
          pub: nonCanonicalBase64Url(validKey.pub),
          not_after: fixture.attestation.verified_at,
        },
      ],
    },
    {
      issuer: "warden",
      keys: [
        { ...validKey, kid: "older", not_after: 1 },
        {
          ...validKey,
          kid: "newer",
          pub: fixture.attestation.pub,
          not_after: 2,
        },
      ],
    },
  ];

  for (const document of documents) {
    await assert.rejects(
      verifyApaAttestation(fixture.attestation, document, {
        nowSeconds: 1784000100,
      }),
      (error) => error instanceof ApaVerifierError && error.kind === "issuer",
    );
  }
});

test("tampering and an unrelated issuer key fail even if an API flag says verified", async () => {
  const tampered = { ...fixture.attestation, scans_24h: 999999 };
  const parsed = parseVerifierInput(
    JSON.stringify({ attestation: tampered, verified: true }),
    BASE_URL,
  );
  const tamperedResult = await verifyApaAttestation(
    parsed.attestation,
    fixture.issuer_document,
    { nowSeconds: 1784000100 },
  );
  assert.equal(tamperedResult.accepted, false);
  assert.equal(tamperedResult.signatureValid, false);
  assert.equal(tamperedResult.code, "signature-invalid");

  const wrongIssuer = {
    issuer: "warden",
    keys: [
      {
        kid: "wrong-key",
        pub: fixture.attestation.pub,
        not_after: Number.MAX_SAFE_INTEGER,
      },
    ],
  };
  const wrongKeyResult = await verifyApaAttestation(
    fixture.attestation,
    wrongIssuer,
    { nowSeconds: 1784000100 },
  );
  assert.equal(wrongKeyResult.accepted, false);
  assert.equal(wrongKeyResult.signatureValid, false);
});

test("valid signatures never override expiry or revoked status", async () => {
  const expired = await verifyApaAttestation(
    fixture.expired_attestation,
    fixture.issuer_document,
    { nowSeconds: 1784000100 },
  );
  assert.equal(expired.signatureValid, true);
  assert.equal(expired.accepted, false);
  assert.equal(expired.code, "expired");
  assert.equal(expired.effectiveStatus, "stale");

  const revoked = await verifyApaAttestation(
    fixture.revoked_attestation,
    fixture.issuer_document,
    { nowSeconds: 1784000100 },
  );
  assert.equal(revoked.signatureValid, true);
  assert.equal(revoked.accepted, false);
  assert.equal(revoked.code, "status-revoked");
  assert.equal(revoked.effectiveStatus, "revoked");
});

test("attestation timestamps must be non-negative and chronological", async () => {
  await assert.rejects(
    verifyApaAttestation(
      { ...fixture.attestation, verified_at: -1 },
      fixture.issuer_document,
      { nowSeconds: 1784000100 },
    ),
    /verified_at/,
  );
  await assert.rejects(
    verifyApaAttestation(
      {
        ...fixture.attestation,
        expires_at: fixture.attestation.verified_at - 1,
      },
      fixture.issuer_document,
      { nowSeconds: 1784000100 },
    ),
    /expires_at/,
  );
  await assert.rejects(
    verifyApaAttestation(
      {
        ...fixture.attestation,
        expires_at: fixture.attestation.verified_at + 3601,
      },
      fixture.issuer_document,
      { nowSeconds: 1784000100 },
    ),
    /expires_at/,
  );
});

test("parser accepts raw records, wrappers, ids, and same-origin attestation or badge URLs", () => {
  const raw = parseVerifierInput(JSON.stringify(fixture.attestation), BASE_URL);
  const wrapped = parseVerifierInput(
    JSON.stringify({ attestation: fixture.attestation }),
    BASE_URL,
  );
  assert.equal(raw.kind, "inline");
  assert.equal(wrapped.kind, "inline");
  assert.equal(raw.attestation.attestation_id, ATTESTATION_ID);

  for (const value of [
    ATTESTATION_ID,
    `/apa/attestation/${ATTESTATION_ID}`,
    `https://warden.gudman.xyz/apa/attestation/${ATTESTATION_ID}`,
    `https://warden.gudman.xyz/apa/attestation/${ATTESTATION_ID}/badge.svg`,
  ]) {
    assert.deepEqual(parseVerifierInput(value, BASE_URL), {
      kind: "remote",
      attestationId: ATTESTATION_ID,
      endpoint: `/apa/attestation/${ATTESTATION_ID}`,
    });
  }
});

test("parser rejects cross-origin URLs and malformed ids or JSON", () => {
  for (const value of [
    `https://evil.example/apa/attestation/${ATTESTATION_ID}`,
    `//evil.example/apa/attestation/${ATTESTATION_ID}/badge.svg`,
  ]) {
    assert.throws(
      () => parseVerifierInput(value, BASE_URL),
      (error) => error instanceof ApaVerifierError && error.kind === "input",
    );
  }
  for (const value of [
    ATTESTATION_ID.toUpperCase(),
    "not-an-attestation",
    "[]",
    "{bad",
  ]) {
    assert.throws(
      () => parseVerifierInput(value, BASE_URL),
      (error) => error instanceof ApaVerifierError && error.kind === "input",
    );
  }
  assert.throws(
    () => decodeBase64Url("sig:not+base64url", "sig", 64),
    /base64url/,
  );
});

test("material loader fetches only the canonical attestation path and issuer document", async () => {
  const calls = [];
  const resolved = parseVerifierInput(ATTESTATION_ID, BASE_URL);
  const material = await loadVerificationMaterial(
    resolved,
    async (endpoint) => {
      calls.push(endpoint);
      if (endpoint === resolved.endpoint) {
        return response({ attestation: fixture.attestation, verified: false });
      }
      if (endpoint === "/.well-known/apa-issuer.json") {
        return response(fixture.issuer_document);
      }
      return response({}, 404);
    },
  );

  assert.deepEqual(calls.sort(), [
    "/.well-known/apa-issuer.json",
    `/apa/attestation/${ATTESTATION_ID}`,
  ]);
  assert.equal(material.attestation.attestation_id, ATTESTATION_ID);
  assert.equal(material.issuerDocument.issuer, "warden");
});

test("exported boundaries state APA, TOFU, and key-theft limits without a safety upgrade", () => {
  assert.match(APA_BOUNDARY, /endpoint signed that proof/);
  assert.match(APA_BOUNDARY, /issuer separately signed the attestation/);
  assert.match(APA_BOUNDARY, /does not prove that every request/);
  assert.doesNotMatch(APA_BOUNDARY, /counter-signed/);
  assert.match(TOFU_BOUNDARY, /trust-on-first-use/);
  assert.match(TOFU_BOUNDARY, /independently anchored/);
  assert.match(TOFU_BOUNDARY, /full rewrite/);
  assert.match(KEY_THEFT_BOUNDARY, /stolen endpoint private key/);
  for (const statement of [APA_BOUNDARY, TOFU_BOUNDARY, KEY_THEFT_BOUNDARY]) {
    assert.doesNotMatch(statement, /certified safe|secure endpoint/i);
  }
});
