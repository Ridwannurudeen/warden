"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
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
  loadBreakerVerificationMaterial,
  loadVerificationMaterial,
  parseBreakerQuery,
  parseVerifierInput,
  verifyApaAttestation,
  verifyBreakerCertificate,
  verifyBreakerInclusion,
} = require(path.join(__dirname, "..", "..", "site", "verify.js"));
const {
  GENESIS_PREV_HASH,
  canonicalJson: canonicalLogJson,
  sha256Hex,
} = require(path.join(__dirname, "..", "..", "site", "log.js"));

const fixture = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "fixtures", "apa_cross_language.json"),
    "utf8",
  ),
);
const BASE_URL = "https://warden.gudman.xyz/verify";
const ATTESTATION_ID = "0123456789abcdef0123456789abcdef";
const BREAKER_ID = "fedcba9876543210fedcba9876543210";
const BREAKER_CONFIRMED_AT = 1_789_000_002;

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

function prefixedBase64Url(prefix, bytes) {
  return `${prefix}:${Buffer.from(bytes).toString("base64url")}`;
}

async function signRecord(core, privateKey, signatureField) {
  const signature = await webcrypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    new TextEncoder().encode(canonicalJson(core)),
  );
  return {
    ...core,
    [signatureField]: prefixedBase64Url("sig", signature),
  };
}

function breakerCore(overrides = {}) {
  return {
    spec_version: "warden-breaker/1",
    predicate_type: "https://warden.gudman.xyz/spec/gauntlet-breaker/v1",
    certificate_id: BREAKER_ID,
    issuer: "warden",
    award: "WARDEN BREAKER",
    benchmark_case_id: "gauntlet-fedcba9876543210",
    threat_class: "PROMPT_INJECTION",
    payload_sha256: "b".repeat(64),
    payload_scope: "human-reviewed-redacted-reproducer",
    finder: "researcher.example",
    confirmed_at: BREAKER_CONFIRMED_AT,
    log_seq: 2,
    ...overrides,
  };
}

async function signCheckpoint(entries, privateKey) {
  const core = {
    spec_version: "apa-log/0.1",
    issuer: "warden",
    seq: entries.length,
    head_hash:
      entries.length === 0
        ? GENESIS_PREV_HASH
        : await sha256Hex(canonicalLogJson(entries.at(-1)), webcrypto),
    issued_at: BREAKER_CONFIRMED_AT + 1,
  };
  return signRecord(core, privateKey, "issuer_sig");
}

async function breakerMaterial() {
  const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const publicKey = await webcrypto.subtle.exportKey("raw", keys.publicKey);
  const certificate = await signRecord(
    breakerCore(),
    keys.privateKey,
    "issuer_sig",
  );
  const issuerDocument = {
    issuer: "warden",
    keys: [
      {
        kid: "breaker-test-key",
        pub: prefixedBase64Url("ed25519", publicKey),
        not_after: Number.MAX_SAFE_INTEGER,
      },
    ],
  };
  const first = {
    seq: 1,
    ts: BREAKER_CONFIRMED_AT - 1,
    event: "issued",
    attestation_id: "attestation-1",
    endpoint_host: "asp.example.org",
    status: "active",
    record_hash: "a".repeat(64),
    prev_hash: GENESIS_PREV_HASH,
  };
  const second = {
    seq: 2,
    ts: BREAKER_CONFIRMED_AT,
    event: "breaker-confirmed",
    record_type: "breaker-certificate",
    certificate_id: BREAKER_ID,
    benchmark_case_id: certificate.benchmark_case_id,
    record_hash: await sha256Hex(canonicalLogJson(certificate), webcrypto),
    prev_hash: await sha256Hex(canonicalLogJson(first), webcrypto),
  };
  const entries = [first, second];
  const checkpoint = await signCheckpoint(entries, keys.privateKey);
  return { certificate, checkpoint, entries, issuerDocument, keys };
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

test("BREAKER certificate schema and issuer signature verify independently", async () => {
  const material = await breakerMaterial();
  const result = await verifyBreakerCertificate(
    material.certificate,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );

  assert.equal(result.accepted, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.code, "verified");
  assert.equal(result.issuerKey.kid, "breaker-test-key");

  const anonymous = await signRecord(
    breakerCore({ finder: null }),
    material.keys.privateKey,
    "issuer_sig",
  );
  const anonymousResult = await verifyBreakerCertificate(
    anonymous,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(anonymousResult.accepted, true);

  const unicodeFinder = await signRecord(
    breakerCore({ finder: "\ud83d\ude00".repeat(128) }),
    material.keys.privateKey,
    "issuer_sig",
  );
  const unicodeResult = await verifyBreakerCertificate(
    unicodeFinder,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(unicodeResult.accepted, true);
});

test("BREAKER issuer-key history uses the signed confirmation-time cutoff", async () => {
  const material = await breakerMaterial();
  const currentKeys = await webcrypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const currentPub = await webcrypto.subtle.exportKey(
    "raw",
    currentKeys.publicKey,
  );
  const issuerDocument = {
    issuer: "warden",
    keys: [
      {
        kid: "current",
        pub: prefixedBase64Url("ed25519", currentPub),
        not_after: Number.MAX_SAFE_INTEGER,
      },
      {
        ...material.issuerDocument.keys[0],
        kid: "retired",
        not_after: BREAKER_CONFIRMED_AT,
      },
    ],
  };

  const accepted = await verifyBreakerCertificate(
    material.certificate,
    issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.issuerKey.kid, "retired");

  issuerDocument.keys[1].not_after = BREAKER_CONFIRMED_AT - 1;
  const outsideCutoff = await verifyBreakerCertificate(
    material.certificate,
    issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(outsideCutoff.accepted, false);
  assert.equal(outsideCutoff.code, "signature-invalid");
});

test("BREAKER certificate validation rejects signed malformed or payload-bearing records", async () => {
  const material = await breakerMaterial();
  const malformedCores = [
    breakerCore({ award: "Almost a BREAKER" }),
    breakerCore({ payload_scope: "raw-submission" }),
    breakerCore({ payload_sha256: "not-a-sha256" }),
    breakerCore({ benchmark_case_id: "gauntlet-not-hex" }),
    breakerCore({ threat_class: "NOT_A_REASON_CODE" }),
    breakerCore({ finder: { html: "<img src=x onerror=alert(1)>" } }),
    breakerCore({ finder: " untrimmed " }),
    breakerCore({ finder: "\ud83d\ude00".repeat(129) }),
    breakerCore({ confirmed_at: "2026-09-10T00:00:00Z" }),
    breakerCore({ log_seq: 0 }),
    { ...breakerCore(), payload: "raw payload must never be public" },
  ];

  for (const core of malformedCores) {
    const signed = await signRecord(
      core,
      material.keys.privateKey,
      "issuer_sig",
    );
    await assert.rejects(
      async () =>
        verifyBreakerCertificate(signed, material.issuerDocument, {
          cryptoImpl: webcrypto,
        }),
      (error) => error instanceof ApaVerifierError && error.kind === "parser",
    );
  }
});

test("BREAKER inclusion requires its signed record in a valid full signed log", async () => {
  const material = await breakerMaterial();
  const result = await verifyBreakerInclusion(
    material.certificate,
    material.entries,
    material.checkpoint,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );

  assert.equal(result.accepted, true);
  assert.equal(result.signatureValid, true);
  assert.equal(result.logValid, true);
  assert.equal(result.inclusionValid, true);
  assert.equal(result.code, "verified");
  assert.equal(result.logEntry.seq, material.certificate.log_seq);
  assert.equal(result.logEntry.certificate_id, BREAKER_ID);
});

test("BREAKER tampering and mismatched or unsigned inclusion proofs are rejected", async () => {
  const material = await breakerMaterial();
  const tampered = {
    ...material.certificate,
    threat_class: "DRAIN_ADDRESS",
  };
  const signatureResult = await verifyBreakerCertificate(
    tampered,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(signatureResult.accepted, false);
  assert.equal(signatureResult.signatureValid, false);

  const truncated = await verifyBreakerInclusion(
    material.certificate,
    material.entries.slice(0, 1),
    material.checkpoint,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(truncated.accepted, false);
  assert.equal(truncated.logValid, false);

  for (const overrides of [
    { certificate_id: "0".repeat(32) },
    { benchmark_case_id: "gauntlet-0000000000000000" },
    { record_hash: "0".repeat(64) },
  ]) {
    const mismatchedEntries = material.entries.map((entry) => ({ ...entry }));
    Object.assign(mismatchedEntries[1], overrides);
    const mismatchedCheckpoint = await signCheckpoint(
      mismatchedEntries,
      material.keys.privateKey,
    );
    const mismatch = await verifyBreakerInclusion(
      material.certificate,
      mismatchedEntries,
      mismatchedCheckpoint,
      material.issuerDocument,
      { cryptoImpl: webcrypto },
    );
    assert.equal(mismatch.accepted, false);
    assert.equal(mismatch.logValid, true);
    assert.equal(mismatch.inclusionValid, false);
  }

  const unrelatedKeys = await webcrypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const unsignedCheckpoint = await signCheckpoint(
    material.entries,
    unrelatedKeys.privateKey,
  );
  const unsigned = await verifyBreakerInclusion(
    material.certificate,
    material.entries,
    unsignedCheckpoint,
    material.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(unsigned.accepted, false);
  assert.equal(unsigned.logValid, false);
});

test("BREAKER query loading fetches canonical material and every log page without API trust", async () => {
  const material = await breakerMaterial();
  const calls = [];
  const loaded = await loadBreakerVerificationMaterial(
    BREAKER_ID,
    async (endpoint) => {
      calls.push(endpoint);
      if (endpoint === `/api/demo/gauntlet/breakers/${BREAKER_ID}`) {
        return response({
          certificate: material.certificate,
          verified: true,
        });
      }
      if (endpoint === "/.well-known/apa-issuer.json") {
        return response(material.issuerDocument);
      }
      if (endpoint === "/apa/log/checkpoint") {
        return response(material.checkpoint);
      }
      if (endpoint === "/apa/log?cursor=0&limit=100") {
        return response({
          entries: [material.entries[0]],
          total: 2,
          next_cursor: 1,
          verified: true,
        });
      }
      if (endpoint === "/apa/log?cursor=1&limit=100") {
        return response({
          entries: [material.entries[1]],
          total: 2,
          next_cursor: null,
          verified: true,
        });
      }
      return response({}, 404);
    },
  );

  assert.deepEqual(
    new Set(calls),
    new Set([
      `/api/demo/gauntlet/breakers/${BREAKER_ID}`,
      "/.well-known/apa-issuer.json",
      "/apa/log/checkpoint",
      "/apa/log?cursor=0&limit=100",
      "/apa/log?cursor=1&limit=100",
    ]),
  );
  assert.deepEqual(loaded.certificate, material.certificate);
  assert.deepEqual(loaded.entries, material.entries);
  assert.deepEqual(loaded.checkpoint, material.checkpoint);
  assert.equal(Object.hasOwn(loaded, "verified"), false);

  const verified = await verifyBreakerInclusion(
    loaded.certificate,
    loaded.entries,
    loaded.checkpoint,
    loaded.issuerDocument,
    { cryptoImpl: webcrypto },
  );
  assert.equal(verified.accepted, true);
});

test("BREAKER query loading rejects a different certificate at the requested permalink", async () => {
  const material = await breakerMaterial();
  const differentCertificate = {
    ...material.certificate,
    certificate_id: "0".repeat(32),
  };

  await assert.rejects(
    loadBreakerVerificationMaterial(BREAKER_ID, async (endpoint) => {
      if (endpoint === `/api/demo/gauntlet/breakers/${BREAKER_ID}`) {
        return response({ certificate: differentCertificate });
      }
      if (endpoint === "/.well-known/apa-issuer.json") {
        return response(material.issuerDocument);
      }
      if (endpoint === "/apa/log/checkpoint") {
        return response(material.checkpoint);
      }
      if (endpoint === "/apa/log?cursor=0&limit=100") {
        return response({
          entries: material.entries,
          total: material.entries.length,
          next_cursor: null,
        });
      }
      return response({}, 404);
    }),
    /requested certificate ID/,
  );
});

test("BREAKER query parser accepts one lowercase certificate id and rejects ambiguity", () => {
  assert.equal(parseBreakerQuery(""), null);
  assert.equal(parseBreakerQuery("?source=manual"), null);
  assert.equal(parseBreakerQuery(`?breaker=${BREAKER_ID}`), BREAKER_ID);
  for (const search of [
    `?breaker=${BREAKER_ID.toUpperCase()}`,
    "?breaker=not-an-id",
    `?breaker=${BREAKER_ID}&breaker=${"0".repeat(32)}`,
  ]) {
    assert.throws(
      () => parseBreakerQuery(search),
      (error) => error instanceof ApaVerifierError && error.kind === "input",
    );
  }
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
