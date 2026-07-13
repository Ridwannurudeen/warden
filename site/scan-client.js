(function (root) {
  "use strict";

  const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;
  const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  const VERDICTS = new Set(["ALLOW", "SANITIZE", "BLOCK"]);
  const RISK_LEVELS = new Set(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
  const CLAIM_STATUSES = new Set(["not_candidate", "pending", "duplicate"]);

  class ScanClientError extends Error {
    constructor(message, { kind, status = null, retryAfter = null } = {}) {
      super(message);
      this.name = "ScanClientError";
      this.kind = kind || "http";
      this.status = status;
      this.retryAfter = retryAfter;
    }
  }

  function addressValues(value) {
    if (Array.isArray(value)) {
      return value.flatMap((entry) => String(entry).split(/[\n,]/));
    }
    return String(value || "").split(/[\n,]/);
  }

  function normalizeExpectedAddresses(value, maxAddresses = 20) {
    const addresses = [];
    const seen = new Set();
    for (const rawValue of addressValues(value)) {
      const address = rawValue.trim();
      if (!address) {
        continue;
      }

      let normalized = address;
      if (/^0x/i.test(address)) {
        if (!EVM_ADDRESS.test(address)) {
          throw new Error(
            "EVM recipients must contain 0x followed by exactly 40 hexadecimal characters",
          );
        }
        normalized = address.toLowerCase();
      } else if (!SOLANA_ADDRESS.test(address)) {
        throw new Error(
          "Recipients must be a 40-hex EVM address or a 32-44 character Solana address",
        );
      }

      if (!seen.has(normalized)) {
        seen.add(normalized);
        addresses.push(normalized);
      }
    }
    if (addresses.length > maxAddresses) {
      throw new Error(`Use at most ${maxAddresses} expected addresses`);
    }
    return addresses;
  }

  function retryAfterSeconds(response) {
    const raw = response?.headers?.get?.("Retry-After");
    if (!raw || !/^\d+$/.test(raw.trim())) {
      return null;
    }
    return Number(raw);
  }

  function errorDetail(payload, fallback) {
    if (typeof payload?.detail === "string" && payload.detail.trim()) {
      return payload.detail.trim();
    }
    return fallback;
  }

  function classifyFetchFailure(error, timedOut, online = true) {
    if (timedOut || error?.name === "AbortError") {
      return new ScanClientError("The request timed out", { kind: "timeout" });
    }
    return new ScanClientError(
      online
        ? "The Warden API could not be reached"
        : "This browser appears to be offline",
      { kind: "offline" },
    );
  }

  function formatScanError(error) {
    if (!(error instanceof ScanClientError)) {
      return "The request could not be completed. Review the input and retry.";
    }
    if (error.kind === "timeout") {
      return "Warden did not respond before the request timed out. No verdict was accepted; retry when ready.";
    }
    if (error.kind === "offline") {
      return `${error.message}. Check the connection, then retry.`;
    }
    if (error.kind === "rate_limit") {
      return error.retryAfter === null
        ? "The public demo rate limit was reached. Wait before retrying."
        : `The public demo rate limit was reached. Retry in ${error.retryAfter} seconds.`;
    }
    if (error.kind === "malformed") {
      return "Warden returned a response this browser could not validate. Do not act on it; retry the request.";
    }
    return error.message;
  }

  async function requestJson(endpoint, method, body, options = {}) {
    const fetchImpl = options.fetchImpl || root.fetch?.bind(root);
    if (!fetchImpl) {
      throw new ScanClientError("Fetch is unavailable", { kind: "offline" });
    }

    const timeoutMs = options.timeoutMs ?? 12000;
    const controller = new root.AbortController();
    let timedOut = false;
    const timeout = root.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    try {
      const request = {
        method,
        cache: "no-store",
        headers: {
          accept: "application/json",
        },
        signal: controller.signal,
      };
      if (body !== undefined) {
        request.headers["content-type"] = "application/json";
        request.body = JSON.stringify(body);
      }
      const response = await fetchImpl(endpoint, request);

      let payload;
      try {
        payload = await response.json();
      } catch {
        if (response.ok) {
          throw new ScanClientError("Response JSON is malformed", {
            kind: "malformed",
            status: response.status,
          });
        }
        payload = null;
      }

      if (!response.ok) {
        const retryAfter = retryAfterSeconds(response);
        const kind = response.status === 429 ? "rate_limit" : "http";
        throw new ScanClientError(
          errorDetail(payload, `Warden returned HTTP ${response.status}`),
          { kind, status: response.status, retryAfter },
        );
      }
      return payload;
    } catch (error) {
      if (error instanceof ScanClientError) {
        throw error;
      }
      throw classifyFetchFailure(
        error,
        timedOut,
        root.navigator?.onLine !== false,
      );
    } finally {
      root.clearTimeout(timeout);
    }
  }

  function getJson(endpoint, options = {}) {
    return requestJson(endpoint, "GET", undefined, options);
  }

  function postJson(endpoint, body, options = {}) {
    return requestJson(endpoint, "POST", body, options);
  }

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function assertScanResponse(value, { gauntlet = false } = {}) {
    const valid =
      isObject(value) &&
      VERDICTS.has(value.verdict) &&
      RISK_LEVELS.has(value.risk_level) &&
      Array.isArray(value.threat_classes) &&
      value.threat_classes.every((entry) => typeof entry === "string") &&
      Array.isArray(value.detections) &&
      value.detections.every(
        (detection) =>
          isObject(detection) &&
          typeof detection.class === "string" &&
          typeof detection.match === "string" &&
          Number.isFinite(detection.confidence) &&
          detection.confidence >= 0 &&
          detection.confidence <= 1 &&
          typeof detection.source === "string",
      ) &&
      typeof value.sanitized_payload === "string" &&
      typeof value.recommendation === "string" &&
      isObject(value.checks) &&
      Number.isFinite(value.latency_ms);
    const validClaim =
      !gauntlet ||
      (CLAIM_STATUSES.has(value.claim_status) &&
        (value.claim_id === null || typeof value.claim_id === "string"));
    if (!valid || !validClaim) {
      throw new ScanClientError("Response envelope is malformed", {
        kind: "malformed",
      });
    }
    return value;
  }

  const api = {
    ScanClientError,
    assertScanResponse,
    classifyFetchFailure,
    formatScanError,
    getJson,
    normalizeExpectedAddresses,
    postJson,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenScanClient = api;
})(typeof globalThis === "undefined" ? this : globalThis);
