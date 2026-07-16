(function (root) {
  "use strict";

  const ATTESTATION_ID = /^[0-9a-f]{32}$/;
  const ATTESTATION_PATH =
    /^\/apa\/attestation\/([0-9a-f]{32})(?:\/badge\.svg)?\/?$/;
  const APA_STATUSES = new Set([
    "active",
    "stale",
    "key-changed",
    "revoked",
    "invalid",
  ]);
  const APA_TIERS = new Set(["guard-live", "audited"]);
  const SPEC_VERSION = "apa/0.1";
  const PREDICATE_TYPE = "https://warden.gudman.xyz/spec/protection/v1";

  const APA_BOUNDARY =
    "A valid, fresh attestation proves that the host serving endpoint_host controlled the key pub when the issuer verified a live APA-conformant Protection Proof. The endpoint signed that proof, including its rolling 24-hour screened-payload count or an explicit unavailable state; the issuer separately signed the attestation. It does not prove that every request is routed through the guard or independently audit the endpoint owner's local counter state.";
  const TOFU_BOUNDARY =
    "First registration is trust-on-first-use: the issuer records the first valid endpoint key. A preserved or independently anchored log checkpoint makes later silent re-binding detectable; an unanchored chain cannot expose a full rewrite or remove first-use trust.";
  const KEY_THEFT_BOUNDARY =
    "A stolen endpoint private key can produce valid endpoint proofs for the victim host. Revocation and key rotation can surface compromise; signature validity alone cannot rule out key theft.";

  class ApaVerifierError extends Error {
    constructor(message, { kind = "verification", status = null } = {}) {
      super(message);
      this.name = "ApaVerifierError";
      this.kind = kind;
      this.status = status;
    }
  }

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function assertUnicodeScalarString(value) {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new ApaVerifierError(
            "Signed JSON strings must contain valid Unicode scalar values",
            { kind: "parser" },
          );
        }
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new ApaVerifierError(
          "Signed JSON strings must contain valid Unicode scalar values",
          { kind: "parser" },
        );
      }
    }
  }

  function compareUnicodeCodePoints(left, right) {
    const leftPoints = Array.from(left, (character) =>
      character.codePointAt(0),
    );
    const rightPoints = Array.from(right, (character) =>
      character.codePointAt(0),
    );
    const length = Math.min(leftPoints.length, rightPoints.length);
    for (let index = 0; index < length; index += 1) {
      if (leftPoints[index] !== rightPoints[index]) {
        return leftPoints[index] - rightPoints[index];
      }
    }
    return leftPoints.length - rightPoints.length;
  }

  function canonicalJson(value) {
    if (value === null) {
      return "null";
    }
    if (typeof value === "string") {
      assertUnicodeScalarString(value);
      return JSON.stringify(value);
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new ApaVerifierError("Signed JSON numbers must be integers", {
          kind: "parser",
        });
      }
      if (!Number.isSafeInteger(value)) {
        throw new ApaVerifierError(
          "Signed JSON numbers must be safe integers",
          { kind: "parser" },
        );
      }
      return String(value);
    }
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
    }
    if (isObject(value)) {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new ApaVerifierError(
          "Signed JSON objects must be plain objects",
          { kind: "parser" },
        );
      }
      const keys = Object.keys(value).sort(compareUnicodeCodePoints);
      return `{${keys
        .map((key) => {
          assertUnicodeScalarString(key);
          return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
        })
        .join(",")}}`;
    }
    throw new ApaVerifierError("Signed values must use JSON-compatible types", {
      kind: "parser",
    });
  }

  function canonicalBytes(value) {
    return new TextEncoder().encode(canonicalJson(value));
  }

  function decodeBase64Url(value, expectedPrefix, expectedLength) {
    if (typeof value !== "string") {
      throw new ApaVerifierError("Key and signature values must be strings", {
        kind: "parser",
      });
    }
    const prefix = `${expectedPrefix}:`;
    if (!value.startsWith(prefix)) {
      throw new ApaVerifierError(
        `Expected a ${expectedPrefix}: base64url value`,
        { kind: "parser" },
      );
    }
    const encoded = value.slice(prefix.length);
    if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
      throw new ApaVerifierError("Value is not unpadded base64url", {
        kind: "parser",
      });
    }
    const padded =
      encoded.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (encoded.length % 4)) % 4);
    let binary;
    try {
      binary = root.atob(padded);
    } catch (error) {
      throw new ApaVerifierError("Value is not valid base64url", {
        kind: "parser",
        cause: error,
      });
    }
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    if (bytes.length !== expectedLength) {
      throw new ApaVerifierError(
        `${expectedPrefix} value must decode to ${expectedLength} bytes`,
        { kind: "parser" },
      );
    }
    const canonical = root
      .btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    if (canonical !== encoded) {
      throw new ApaVerifierError("Value is not canonical base64url", {
        kind: "parser",
      });
    }
    return bytes;
  }

  function requireString(record, field) {
    const value = record[field];
    if (typeof value !== "string" || !value) {
      throw new ApaVerifierError(
        `Attestation field ${field} must be a non-empty string`,
        { kind: "parser" },
      );
    }
    return value;
  }

  function requireSafeInteger(record, field) {
    const value = record[field];
    if (!Number.isSafeInteger(value)) {
      throw new ApaVerifierError(
        `Attestation field ${field} must be a safe integer`,
        { kind: "parser" },
      );
    }
    return value;
  }

  function validateAttestation(attestation) {
    if (!isObject(attestation)) {
      throw new ApaVerifierError("Attestation must be a JSON object", {
        kind: "parser",
      });
    }
    if (requireString(attestation, "spec_version") !== SPEC_VERSION) {
      throw new ApaVerifierError("Attestation spec_version is not apa/0.1", {
        kind: "parser",
      });
    }
    if (requireString(attestation, "predicate_type") !== PREDICATE_TYPE) {
      throw new ApaVerifierError("Attestation predicate_type is unsupported", {
        kind: "parser",
      });
    }
    if (!ATTESTATION_ID.test(requireString(attestation, "attestation_id"))) {
      throw new ApaVerifierError(
        "Attestation IDs must contain 32 lowercase hexadecimal characters",
        { kind: "parser" },
      );
    }
    for (const field of ["issuer", "protector", "endpoint_host"]) {
      requireString(attestation, field);
    }
    const tier = requireString(attestation, "tier");
    if (!APA_TIERS.has(tier)) {
      throw new ApaVerifierError(`Unsupported APA tier: ${tier}`, {
        kind: "parser",
      });
    }
    const status = requireString(attestation, "status");
    if (!APA_STATUSES.has(status)) {
      throw new ApaVerifierError(`Unsupported APA status: ${status}`, {
        kind: "parser",
      });
    }
    const scans = attestation.scans_24h;
    if (scans !== null && (!Number.isSafeInteger(scans) || scans < 0)) {
      throw new ApaVerifierError(
        "Attestation field scans_24h must be null or a non-negative safe integer",
        { kind: "parser" },
      );
    }
    const verifiedAt = requireSafeInteger(attestation, "verified_at");
    const expiresAt = requireSafeInteger(attestation, "expires_at");
    if (verifiedAt < 0) {
      throw new ApaVerifierError(
        "Attestation field verified_at must be non-negative",
        { kind: "parser" },
      );
    }
    if (expiresAt !== verifiedAt + 3600) {
      throw new ApaVerifierError(
        "Attestation field expires_at must equal verified_at + 3600",
        { kind: "parser" },
      );
    }
    decodeBase64Url(requireString(attestation, "pub"), "ed25519", 32);
    decodeBase64Url(requireString(attestation, "issuer_sig"), "sig", 64);

    const core = Object.fromEntries(
      Object.entries(attestation).filter(([key]) => key !== "issuer_sig"),
    );
    canonicalJson(core);
    return attestation;
  }

  function extractAttestation(value) {
    if (!isObject(value)) {
      throw new ApaVerifierError("Attestation input must be a JSON object", {
        kind: "input",
      });
    }
    const candidate = Object.hasOwn(value, "attestation")
      ? value.attestation
      : value;
    if (!isObject(candidate)) {
      throw new ApaVerifierError(
        "The attestation property must contain a JSON object",
        { kind: "input" },
      );
    }
    return candidate;
  }

  function parseVerifierInput(value, baseHref) {
    const input = String(value || "").trim();
    if (!input) {
      throw new ApaVerifierError("Paste an attestation, ID, or URL", {
        kind: "input",
      });
    }
    if (input.startsWith("{") || input.startsWith("[")) {
      let parsed;
      try {
        parsed = JSON.parse(input);
      } catch (error) {
        throw new ApaVerifierError("Attestation input is not valid JSON", {
          kind: "input",
          cause: error,
        });
      }
      return { kind: "inline", attestation: extractAttestation(parsed) };
    }
    if (ATTESTATION_ID.test(input)) {
      return {
        kind: "remote",
        attestationId: input,
        endpoint: `/apa/attestation/${input}`,
      };
    }

    let base;
    let parsed;
    try {
      base = new URL(baseHref);
      parsed = new URL(input, base);
    } catch (error) {
      throw new ApaVerifierError("Input is not a valid attestation URL", {
        kind: "input",
        cause: error,
      });
    }
    if (!/^https?:$/.test(base.protocol) || parsed.origin !== base.origin) {
      throw new ApaVerifierError(
        "Attestation and badge URLs must use this page's origin",
        { kind: "input" },
      );
    }
    if (parsed.username || parsed.password) {
      throw new ApaVerifierError(
        "Attestation URLs must not contain credentials",
        {
          kind: "input",
        },
      );
    }
    const match = ATTESTATION_PATH.exec(parsed.pathname);
    if (!match) {
      throw new ApaVerifierError(
        "Use a 32-lowercase-hex attestation ID, attestation URL, or badge.svg URL",
        { kind: "input" },
      );
    }
    const attestationId = match[1];
    return {
      kind: "remote",
      attestationId,
      endpoint: `/apa/attestation/${attestationId}`,
    };
  }

  async function fetchJson(endpoint, fetchImpl) {
    let response;
    try {
      response = await fetchImpl(endpoint, {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
    } catch (error) {
      throw new ApaVerifierError(
        "The verification source could not be reached",
        {
          kind: "network",
          cause: error,
        },
      );
    }
    if (!response.ok) {
      throw new ApaVerifierError(
        `Verification source returned HTTP ${response.status}`,
        { kind: "http", status: response.status },
      );
    }
    try {
      return await response.json();
    } catch (error) {
      throw new ApaVerifierError(
        "Verification source returned malformed JSON",
        {
          kind: "parser",
          cause: error,
        },
      );
    }
  }

  async function loadVerificationMaterial(resolved, fetchImpl) {
    if (typeof fetchImpl !== "function") {
      throw new ApaVerifierError("Fetch is unavailable", { kind: "network" });
    }
    const attestationRequest =
      resolved.kind === "inline"
        ? Promise.resolve(resolved.attestation)
        : fetchJson(resolved.endpoint, fetchImpl).then(extractAttestation);
    const issuerRequest = fetchJson("/.well-known/apa-issuer.json", fetchImpl);
    const [attestation, issuerDocument] = await Promise.all([
      attestationRequest,
      issuerRequest,
    ]);
    return { attestation, issuerDocument };
  }

  function issuerKeysFor(attestation, issuerDocument) {
    if (
      !isObject(issuerDocument) ||
      Object.keys(issuerDocument).length !== 2 ||
      !Object.hasOwn(issuerDocument, "issuer") ||
      !Object.hasOwn(issuerDocument, "keys")
    ) {
      throw new ApaVerifierError("Issuer document must be a JSON object", {
        kind: "issuer",
      });
    }
    if (
      typeof issuerDocument.issuer !== "string" ||
      issuerDocument.issuer !== attestation.issuer
    ) {
      throw new ApaVerifierError(
        "Issuer document identity does not match the attestation",
        { kind: "issuer" },
      );
    }
    if (
      !Array.isArray(issuerDocument.keys) ||
      issuerDocument.keys.length === 0
    ) {
      throw new ApaVerifierError("Issuer document publishes no keys", {
        kind: "issuer",
      });
    }
    const kids = new Set();
    const pubs = new Set();
    let previousNotAfter = Number.MAX_SAFE_INTEGER;
    const keys = issuerDocument.keys.map((key, index) => {
      if (
        !isObject(key) ||
        Object.keys(key).length !== 3 ||
        !Object.hasOwn(key, "kid") ||
        !Object.hasOwn(key, "pub") ||
        !Object.hasOwn(key, "not_after") ||
        typeof key.kid !== "string" ||
        !key.kid ||
        key.kid.trim() !== key.kid ||
        typeof key.pub !== "string"
      ) {
        throw new ApaVerifierError("Issuer document contains a malformed key", {
          kind: "issuer",
        });
      }
      let decodedPub;
      try {
        decodedPub = decodeBase64Url(key.pub, "ed25519", 32);
      } catch (error) {
        throw new ApaVerifierError(
          "Issuer document key pub must be canonical Ed25519 base64url",
          { kind: "issuer", cause: error },
        );
      }
      if (
        !Number.isSafeInteger(key.not_after) ||
        key.not_after < 0 ||
        key.not_after > previousNotAfter
      ) {
        throw new ApaVerifierError(
          "Issuer key not_after must be non-negative safe Unix seconds in newest-first order",
          { kind: "issuer" },
        );
      }
      if (index === 0 && key.not_after !== Number.MAX_SAFE_INTEGER) {
        throw new ApaVerifierError(
          "The current issuer key must publish the safe-integer sentinel",
          { kind: "issuer" },
        );
      }
      if (index > 0 && key.not_after === Number.MAX_SAFE_INTEGER) {
        throw new ApaVerifierError(
          "Retired issuer key not_after must be finite",
          { kind: "issuer" },
        );
      }
      previousNotAfter = key.not_after;
      if (kids.has(key.kid)) {
        throw new ApaVerifierError("Issuer document contains a duplicate kid", {
          kind: "issuer",
        });
      }
      const pubIdentity = Array.from(decodedPub).join(",");
      if (pubs.has(pubIdentity)) {
        throw new ApaVerifierError("Issuer document contains a duplicate pub", {
          kind: "issuer",
        });
      }
      kids.add(key.kid);
      pubs.add(pubIdentity);
      return key;
    });
    const applicable = keys.filter(
      (key) => attestation.verified_at <= key.not_after,
    );
    return applicable;
  }

  async function verifyApaAttestation(
    attestation,
    issuerDocument,
    options = {},
  ) {
    validateAttestation(attestation);
    const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(nowSeconds)) {
      throw new ApaVerifierError("Verifier time must be Unix seconds", {
        kind: "parser",
      });
    }
    const keys = issuerKeysFor(attestation, issuerDocument);
    const crypto = options.cryptoImpl || root.crypto;
    if (!crypto?.subtle) {
      throw new ApaVerifierError(
        "This browser does not provide WebCrypto Ed25519 verification",
        { kind: "unsupported" },
      );
    }

    const signature = decodeBase64Url(attestation.issuer_sig, "sig", 64);
    const core = Object.fromEntries(
      Object.entries(attestation).filter(([key]) => key !== "issuer_sig"),
    );
    const signedBytes = canonicalBytes(core);
    let issuerKey = null;
    for (const candidate of keys) {
      try {
        const publicKey = await crypto.subtle.importKey(
          "raw",
          decodeBase64Url(candidate.pub, "ed25519", 32),
          { name: "Ed25519" },
          false,
          ["verify"],
        );
        const valid = await crypto.subtle.verify(
          { name: "Ed25519" },
          publicKey,
          signature,
          signedBytes,
        );
        if (valid) {
          issuerKey = candidate;
          break;
        }
      } catch (error) {
        throw new ApaVerifierError(
          "WebCrypto could not perform Ed25519 verification",
          { kind: "unsupported", cause: error },
        );
      }
    }
    if (!issuerKey) {
      return {
        accepted: false,
        signatureValid: false,
        effectiveStatus: "invalid",
        code: "signature-invalid",
        issuerKey: null,
      };
    }
    if (nowSeconds > attestation.expires_at) {
      return {
        accepted: false,
        signatureValid: true,
        effectiveStatus: "stale",
        code: "expired",
        issuerKey,
      };
    }
    if (attestation.status !== "active") {
      return {
        accepted: false,
        signatureValid: true,
        effectiveStatus: attestation.status,
        code: `status-${attestation.status}`,
        issuerKey,
      };
    }
    return {
      accepted: true,
      signatureValid: true,
      effectiveStatus: "active",
      code: "verified",
      issuerKey,
    };
  }

  function formatUnixTime(value) {
    if (!Number.isSafeInteger(value)) {
      return "Unavailable";
    }
    const date = new Date(value * 1000);
    if (!Number.isFinite(date.getTime())) {
      return "Unavailable";
    }
    return `${date.toISOString()} (${value})`;
  }

  function attestationViewModel(attestation, verification) {
    return {
      issuer: attestation.issuer,
      signature: attestation.issuer_sig,
      signatureState: verification.signatureValid
        ? "Valid WebCrypto Ed25519 signature"
        : "Invalid Ed25519 signature",
      endpoint: attestation.endpoint_host,
      tier: attestation.tier,
      scans:
        attestation.scans_24h === null
          ? "Unavailable (not zero)"
          : `${attestation.scans_24h.toLocaleString("en-US")} / stated 24h window`,
      storedStatus: attestation.status,
      effectiveStatus: verification.effectiveStatus,
      verifiedAt: formatUnixTime(attestation.verified_at),
      expiresAt: formatUnixTime(attestation.expires_at),
      issuerKey: verification.issuerKey?.kid || "No matching issuer key",
    };
  }

  const api = {
    APA_BOUNDARY,
    KEY_THEFT_BOUNDARY,
    TOFU_BOUNDARY,
    ApaVerifierError,
    attestationViewModel,
    canonicalBytes,
    canonicalJson,
    decodeBase64Url,
    extractAttestation,
    formatUnixTime,
    loadVerificationMaterial,
    parseVerifierInput,
    verifyApaAttestation,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenApaVerifier = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  const form = document.querySelector("[data-apa-verify-form]");
  const input = document.querySelector("[data-apa-verify-input]");
  const resultPanel = document.querySelector("[data-apa-verify-result]");
  const emptyPanel = document.querySelector("[data-apa-verify-empty]");
  const errorPanel = document.querySelector("[data-apa-verify-error]");
  const submitButton = form?.querySelector('button[type="submit"]');

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function renderBoundaries() {
    text("[data-apa-boundary]", APA_BOUNDARY);
    text("[data-tofu-boundary]", TOFU_BOUNDARY);
    text("[data-key-theft-boundary]", KEY_THEFT_BOUNDARY);
  }

  function setBusy(busy) {
    if (submitButton) {
      submitButton.disabled = busy;
      submitButton.textContent = busy
        ? "Verifying in this browser..."
        : "Verify independently";
    }
  }

  function verificationMessage(verification) {
    if (verification.accepted) {
      return "Signature, expiry, and active status all pass independent browser verification.";
    }
    if (verification.code === "signature-invalid") {
      return "No issuer key applicable at the signed verification time validates this record. The attestation is rejected.";
    }
    if (verification.code === "expired") {
      return "The issuer signature is valid, but the attestation has expired and is stale.";
    }
    return `The issuer signature is valid, but the signed status is ${verification.effectiveStatus}.`;
  }

  function renderVerification(attestation, verification) {
    const view = attestationViewModel(attestation, verification);
    const statusLabel = document.querySelector("[data-apa-verification-label]");
    if (statusLabel) {
      statusLabel.textContent = verification.accepted
        ? "Verified · active"
        : verification.signatureValid
          ? `Rejected · ${verification.effectiveStatus}`
          : "Rejected · invalid signature";
      statusLabel.className = verification.accepted
        ? "status-label status-label--allow"
        : verification.signatureValid
          ? "status-label status-label--pending"
          : "status-label";
    }
    text(
      "[data-apa-result-heading]",
      verification.accepted
        ? "Valid, fresh APA attestation"
        : "Attestation not accepted",
    );
    text("[data-apa-result-message]", verificationMessage(verification));
    text("[data-apa-issuer]", view.issuer);
    text("[data-apa-issuer-key]", view.issuerKey);
    text("[data-apa-signature-state]", view.signatureState);
    text("[data-apa-signature]", view.signature);
    text("[data-apa-endpoint]", view.endpoint);
    text("[data-apa-tier]", view.tier);
    text("[data-apa-scans]", view.scans);
    text("[data-apa-stored-status]", view.storedStatus);
    text("[data-apa-effective-status]", view.effectiveStatus);
    text("[data-apa-verified-at]", view.verifiedAt);
    text("[data-apa-expires-at]", view.expiresAt);
    emptyPanel.hidden = true;
    errorPanel.hidden = true;
    resultPanel.hidden = false;
    resultPanel.focus();
  }

  function renderError(error) {
    text(
      "[data-apa-verify-error-message]",
      error instanceof ApaVerifierError
        ? error.message
        : "The attestation could not be verified.",
    );
    text("[data-apa-verify-status]", "No verification result was accepted.");
    resultPanel.hidden = true;
    emptyPanel.hidden = true;
    errorPanel.hidden = false;
    errorPanel.focus();
  }

  renderBoundaries();
  if (!form || !input || !resultPanel || !emptyPanel || !errorPanel) {
    return;
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(true);
    errorPanel.hidden = true;
    text(
      "[data-apa-verify-status]",
      "Fetching public material and verifying with WebCrypto Ed25519...",
    );
    try {
      const resolved = parseVerifierInput(input.value, root.location.href);
      const material = await loadVerificationMaterial(
        resolved,
        root.fetch?.bind(root),
      );
      const verification = await verifyApaAttestation(
        material.attestation,
        material.issuerDocument,
      );
      renderVerification(material.attestation, verification);
      text(
        "[data-apa-verify-status]",
        "Independent browser verification complete.",
      );
    } catch (error) {
      renderError(error);
    } finally {
      setBusy(false);
    }
  });
})(typeof globalThis === "undefined" ? this : globalThis);
