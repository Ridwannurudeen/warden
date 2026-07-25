const DEFAULT_BASE_URL = "https://warden.gudman.xyz";
const FEEDBACK_PATH = "/api/feedback";
const PAID_PATH = "/scan";
const MAX_X402_HEADER_LENGTH = 16_384;
const X402_NETWORK = "eip155:196";
const X402_ASSET = "0x779ded0c9e1022225f8e0630b35a9b54be713736";
const X402_AMOUNT = "100000";
const X402_PAY_TO = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51";
const X402_MIN_REPLAY_WINDOW_SECONDS = 6n;
const X402_CLOCK_TOLERANCE_SECONDS = 5n;
const MAX_UINT256 = (1n << 256n) - 1n;

export type Verdict = "ALLOW" | "SANITIZE" | "BLOCK";
export type RiskLevel = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Detection {
  class: string;
  match: string;
  confidence: number;
  source: string;
}

export interface ScanResponse extends Record<string, unknown> {
  verdict: Verdict;
  risk_level: RiskLevel;
  threat_classes: string[];
  detections: Detection[];
  sanitized_payload: string;
  recommendation: string;
  checks: Record<string, string>;
  latency_ms: number;
}

export interface WardenClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  failOpen?: boolean;
  paymentHandler?: X402PaymentHandler;
}

export interface ScanOptions {
  expectedAddresses?: readonly string[];
  depth?: "fast" | "thorough";
}

export interface X402PaymentRequirement {
  readonly scheme: "exact";
  readonly network: "eip155:196";
  readonly asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736";
  readonly amount: "100000";
  readonly payTo: "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51";
  readonly maxTimeoutSeconds: 300;
  readonly extra: {
    readonly name: "USD₮0";
    readonly version: "1";
  };
}

export interface X402Challenge {
  readonly x402Version: 2;
  readonly resourceUrl: string;
  readonly requirement: X402PaymentRequirement;
}

export type X402PaymentHandler = (
  challenge: X402Challenge,
) => string | Promise<string>;

export type FeedbackOutcome =
  | "missed_attack"
  | "false_positive"
  | "correct_detection";
export type FeedbackStatus = "pending" | "duplicate";
export type FeedbackThreatClass =
  | "PROMPT_INJECTION"
  | "ROLE_OVERRIDE"
  | "WEB3_INJECTION"
  | "HIDDEN_UNICODE"
  | "ENCODING_TRICK"
  | "STATISTICAL_ANOMALY"
  | "CORPUS_MATCH"
  | "DRAIN_ADDRESS"
  | "TOOL_HIJACK"
  | "SECRET_EXFIL"
  | "MALICIOUS_LINK";

interface FeedbackSubmissionFields {
  threatClass: FeedbackThreatClass;
  redactedReproducer: string;
  consentToRetain: true;
  redactionConfirmed: true;
}

export type FeedbackSubmission =
  | (FeedbackSubmissionFields & {
      outcome: "missed_attack";
      observedVerdict: "ALLOW";
    })
  | (FeedbackSubmissionFields & {
      outcome: "false_positive" | "correct_detection";
      observedVerdict: "SANITIZE" | "BLOCK";
    });

export interface FeedbackResult {
  feedbackId: string;
  status: FeedbackStatus;
  retainedUntil: string;
}

interface FeedbackResponse {
  feedback_id: string;
  status: FeedbackStatus;
  retained_until: string;
}

interface ScanResultInit {
  verdict: Verdict;
  riskLevel: RiskLevel;
  threatClasses: string[];
  sanitizedPayload: string | null;
  recommendation: string | null;
  latencyMs: number | null;
  raw: Readonly<Record<string, unknown>>;
}

export class ScanResult {
  readonly verdict: Verdict;
  readonly riskLevel: RiskLevel;
  readonly threatClasses: string[];
  readonly sanitizedPayload: string | null;
  readonly recommendation: string | null;
  readonly latencyMs: number | null;
  readonly raw: Readonly<Record<string, unknown>>;

  constructor(init: ScanResultInit) {
    this.verdict = init.verdict;
    this.riskLevel = init.riskLevel;
    this.threatClasses = init.threatClasses;
    this.sanitizedPayload = init.sanitizedPayload;
    this.recommendation = init.recommendation;
    this.latencyMs = init.latencyMs;
    this.raw = init.raw;
  }

  get blocked(): boolean {
    return this.verdict === "BLOCK";
  }

  get allowed(): boolean {
    return this.verdict === "ALLOW";
  }

  get sanitized(): boolean {
    return this.verdict === "SANITIZE";
  }

  get safePayload(): string | null {
    return this.sanitized ? this.sanitizedPayload : null;
  }
}

export class WardenError extends Error {
  readonly cause: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "WardenError";
    this.cause = cause;
  }
}

export class WardenBlocked extends WardenError {
  readonly result: ScanResult;

  constructor(result: ScanResult) {
    const threats = result.threatClasses.join(", ") || "threat detected";
    super(`Warden BLOCK: ${threats}`);
    this.name = "WardenBlocked";
    this.result = result;
  }
}

export class WardenClient {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly failOpen: boolean;
  private readonly paymentHandler: X402PaymentHandler | undefined;
  private readonly paidUrl: string | undefined;

  constructor(options: WardenClientOptions = {}) {
    const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    const timeoutMs = options.timeoutMs ?? 8_000;

    if (baseUrl.length === 0) {
      throw new TypeError("baseUrl must not be empty");
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive number");
    }
    if (
      options.paymentHandler !== undefined &&
      typeof options.paymentHandler !== "function"
    ) {
      throw new TypeError("paymentHandler must be a function");
    }

    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
    this.failOpen = options.failOpen ?? true;
    this.paymentHandler = options.paymentHandler;
    this.paidUrl =
      options.paymentHandler === undefined
        ? undefined
        : canonicalPaidUrl(this.baseUrl);
  }

  async scan(payload: string, options: ScanOptions = {}): Promise<ScanResult> {
    if (
      this.paymentHandler !== undefined &&
      options.depth !== undefined &&
      options.depth !== "fast" &&
      options.depth !== "thorough"
    ) {
      throw new WardenError("depth must be 'fast' or 'thorough'");
    }
    const body: {
      payload: string;
      depth: "fast" | "thorough";
      context?: { expected_addresses: readonly string[] };
    } = {
      payload,
      depth:
        this.paymentHandler === undefined ? "fast" : (options.depth ?? "fast"),
    };

    if (options.expectedAddresses && options.expectedAddresses.length > 0) {
      body.context = { expected_addresses: options.expectedAddresses };
    }
    if (this.paymentHandler !== undefined && this.paidUrl !== undefined) {
      return this.scanWithPayment(body, this.paymentHandler, this.paidUrl);
    }

    const controller = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);

    try {
      let response: Response;
      try {
        response = await globalThis.fetch(`${this.baseUrl}/api/demo/scan`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (error) {
        const requestError = timedOut
          ? this.timeoutError(error)
          : new WardenError(errorMessage(error), error);
        return this.handleRequestFailure(requestError);
      }

      if (!response.ok) {
        const suffix = response.statusText ? ` ${response.statusText}` : "";
        return this.handleRequestFailure(
          new WardenError(
            `Warden request failed with HTTP ${response.status}${suffix}`,
          ),
        );
      }

      let data: unknown;
      try {
        data = await response.json();
      } catch (error) {
        if (timedOut) {
          return this.handleRequestFailure(this.timeoutError(error));
        }
        if (error instanceof SyntaxError) {
          throw new WardenError(
            "Invalid Warden response: expected JSON",
            error,
          );
        }
        return this.handleRequestFailure(
          new WardenError(errorMessage(error), error),
        );
      }
      validateScanResponse(data);
      return scanResultFromResponse(data);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async scanWithPayment(
    body: {
      payload: string;
      depth: "fast" | "thorough";
      context?: { expected_addresses: readonly string[] };
    },
    paymentHandler: X402PaymentHandler,
    requestUrl: string,
  ): Promise<ScanResult> {
    const requestBody = JSON.stringify(body);
    const firstController = new AbortController();
    let firstTimedOut = false;
    const firstTimeout = setTimeout(() => {
      firstTimedOut = true;
      firstController.abort();
    }, this.timeoutMs);

    let response: Response;
    try {
      try {
        response = await globalThis.fetch(requestUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: requestBody,
          signal: firstController.signal,
          redirect: "error",
        });
      } catch (error) {
        if (firstTimedOut) {
          throw this.timeoutError(error);
        }
        throw new WardenError(
          `Warden x402 request failed: ${errorMessage(error)}`,
          error,
        );
      }
      if (response.status >= 300 && response.status < 400) {
        throw new WardenError("Warden x402 challenge returned a redirect");
      }
      if (response.status !== 402) {
        if (!response.ok) {
          const suffix = response.statusText ? ` ${response.statusText}` : "";
          throw new WardenError(
            `Warden x402 request failed with HTTP ${response.status}${suffix}`,
          );
        }
        const data = await readPaidScanResponse(
          response,
          () => firstTimedOut,
          (cause) => this.timeoutError(cause),
        );
        return scanResultFromResponse(data);
      }
    } finally {
      clearTimeout(firstTimeout);
    }

    const challenge = parseX402Challenge(response.headers, requestUrl);
    let suppliedHeader: unknown;
    try {
      suppliedHeader = await paymentHandler(challenge);
    } catch (error) {
      throw new WardenError("Warden x402 payment handler failed", error);
    }
    const paymentHeader = validateX402PaymentHeader(suppliedHeader, challenge);

    const replayController = new AbortController();
    let replayTimedOut = false;
    const replayTimeout = setTimeout(() => {
      replayTimedOut = true;
      replayController.abort();
    }, this.timeoutMs);
    try {
      let replay: Response;
      try {
        replay = await globalThis.fetch(requestUrl, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "PAYMENT-SIGNATURE": paymentHeader,
          },
          body: requestBody,
          signal: replayController.signal,
          redirect: "error",
        });
      } catch (error) {
        if (replayTimedOut) {
          throw this.timeoutError(error);
        }
        throw new WardenError(
          `Warden x402 replay failed: ${errorMessage(error)}`,
          error,
        );
      }
      if (replay.status === 402) {
        let replayChallenge: X402Challenge;
        try {
          replayChallenge = parseX402Challenge(replay.headers, requestUrl);
        } catch (error) {
          throw new WardenError(
            "Warden x402 challenge changed or became malformed on replay",
            error,
          );
        }
        if (!sameX402Challenge(challenge, replayChallenge)) {
          throw new WardenError("Warden x402 challenge changed on replay");
        }
        throw new WardenError(
          "Warden permits only one paid replay; payment was not accepted",
        );
      }
      if (replay.status >= 300 && replay.status < 400) {
        throw new WardenError("Warden x402 replay returned a redirect");
      }
      if (replay.status !== 200) {
        throw new WardenError(
          `Warden x402 replay failed with HTTP ${replay.status}`,
        );
      }
      validateX402SettlementHeader(replay.headers);
      const data = await readPaidScanResponse(
        replay,
        () => replayTimedOut,
        (cause) => this.timeoutError(cause),
      );
      return scanResultFromResponse(data);
    } finally {
      clearTimeout(replayTimeout);
    }
  }

  async guard(payload: string, options: ScanOptions = {}): Promise<string> {
    const result = await this.scan(payload, options);
    if (result.blocked) {
      throw new WardenBlocked(result);
    }
    if (result.sanitized) {
      return result.sanitizedPayload!;
    }
    return payload;
  }

  async submitFeedback(
    submission: FeedbackSubmission,
  ): Promise<FeedbackResult> {
    validateFeedbackSubmission(submission);
    const body = {
      outcome: submission.outcome,
      observed_verdict: submission.observedVerdict,
      threat_class: submission.threatClass,
      redacted_reproducer: submission.redactedReproducer,
      consent_to_retain: true,
      redaction_confirmed: true,
    };
    const controller = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);

    try {
      let response: Response;
      try {
        response = await globalThis.fetch(`${this.baseUrl}${FEEDBACK_PATH}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (error) {
        if (timedOut) {
          throw this.timeoutError(error);
        }
        throw new WardenError(
          `Warden feedback submission failed: ${errorMessage(error)}`,
          error,
        );
      }
      if (!response.ok) {
        const suffix = response.statusText ? ` ${response.statusText}` : "";
        throw new WardenError(
          `Warden feedback submission failed with HTTP ${response.status}${suffix}`,
        );
      }

      let data: unknown;
      try {
        data = await response.json();
      } catch (error) {
        if (timedOut) {
          throw this.timeoutError(error);
        }
        throw new WardenError(
          "Invalid Warden feedback response: expected JSON",
          error,
        );
      }
      validateFeedbackResponse(data);
      return {
        feedbackId: data.feedback_id,
        status: data.status,
        retainedUntil: data.retained_until,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private handleRequestFailure(error: WardenError): ScanResult {
    if (!this.failOpen) {
      throw error;
    }

    return new ScanResult({
      verdict: "ALLOW",
      riskLevel: "NONE",
      threatClasses: [],
      sanitizedPayload: null,
      recommendation: null,
      latencyMs: null,
      raw: { error: error.message },
    });
  }

  private timeoutError(cause: unknown): WardenError {
    return new WardenError(
      `Warden request timed out after ${this.timeoutMs}ms`,
      cause,
    );
  }
}

function canonicalPaidUrl(baseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch (error) {
    throw new WardenError(
      "x402 payment requires a canonical HTTPS baseUrl",
      error,
    );
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin !== baseUrl
  ) {
    throw new WardenError("x402 payment requires a canonical HTTPS baseUrl");
  }
  return `${parsed.origin}${PAID_PATH}`;
}

function decodeX402Header(value: unknown, label: string): unknown {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_X402_HEADER_LENGTH ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new WardenError(`Invalid ${label} header`);
  }
  try {
    const binary = atob(value);
    if (btoa(binary) !== value) {
      throw new Error("noncanonical base64");
    }
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(decoded) as unknown;
  } catch (error) {
    throw new WardenError(`Invalid ${label} header`, error);
  }
}

function hasOnlyKeys(
  value: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function optionalStringIsValid(
  value: Readonly<Record<string, unknown>>,
  key: string,
): boolean {
  return value[key] === undefined || value[key] === null
    ? true
    : typeof value[key] === "string";
}

function parseX402Requirement(
  value: unknown,
  label: string,
): X402PaymentRequirement {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "scheme",
      "network",
      "asset",
      "amount",
      "payTo",
      "maxTimeoutSeconds",
      "extra",
      "outputSchema",
    ]) ||
    (value.outputSchema !== undefined &&
      value.outputSchema !== null &&
      !isRecord(value.outputSchema)) ||
    value.scheme !== "exact" ||
    value.network !== X402_NETWORK ||
    value.asset !== X402_ASSET ||
    value.amount !== X402_AMOUNT ||
    value.payTo !== X402_PAY_TO ||
    value.maxTimeoutSeconds !== 300 ||
    !isRecord(value.extra) ||
    Object.keys(value.extra).length !== 2 ||
    value.extra.name !== "USD₮0" ||
    value.extra.version !== "1"
  ) {
    throw new WardenError(`Invalid ${label} header`);
  }
  const extra = Object.freeze({
    name: "USD₮0" as const,
    version: "1" as const,
  });
  return Object.freeze({
    scheme: "exact" as const,
    network: X402_NETWORK,
    asset: X402_ASSET,
    amount: X402_AMOUNT,
    payTo: X402_PAY_TO,
    maxTimeoutSeconds: 300 as const,
    extra,
  });
}

function parseX402Challenge(
  headers: Headers,
  expectedResourceUrl: string,
): X402Challenge {
  const encoded = headers.get("PAYMENT-REQUIRED");
  const document = decodeX402Header(encoded, "x402 payment challenge");
  if (
    !isRecord(document) ||
    !hasOnlyKeys(document, [
      "x402Version",
      "error",
      "resource",
      "accepts",
      "extensions",
      "outputSchema",
    ]) ||
    document.x402Version !== 2 ||
    !optionalStringIsValid(document, "error") ||
    (document.extensions !== undefined &&
      document.extensions !== null &&
      !isRecord(document.extensions)) ||
    (document.outputSchema !== undefined &&
      document.outputSchema !== null &&
      !isRecord(document.outputSchema)) ||
    !isRecord(document.resource) ||
    !hasOnlyKeys(document.resource, ["url", "description", "mimeType"]) ||
    document.resource.url !== expectedResourceUrl ||
    !optionalStringIsValid(document.resource, "description") ||
    !optionalStringIsValid(document.resource, "mimeType") ||
    !Array.isArray(document.accepts) ||
    document.accepts.length !== 1
  ) {
    throw new WardenError("Invalid x402 payment challenge header");
  }
  const requirement = parseX402Requirement(
    document.accepts[0],
    "x402 payment challenge",
  );
  return Object.freeze({
    x402Version: 2 as const,
    resourceUrl: expectedResourceUrl,
    requirement,
  });
}

function validateX402PaymentHeader(
  value: unknown,
  challenge: X402Challenge,
): string {
  if (typeof value !== "string") {
    throw new WardenError("Invalid x402 payment handler header");
  }
  const document = decodeX402Header(value, "x402 payment handler");
  if (
    !isRecord(document) ||
    !hasOnlyKeys(document, [
      "x402Version",
      "payload",
      "accepted",
      "resource",
      "extensions",
    ]) ||
    document.x402Version !== 2 ||
    (document.extensions !== undefined &&
      document.extensions !== null &&
      !isRecord(document.extensions))
  ) {
    throw new WardenError("Invalid x402 payment handler header");
  }
  const accepted = parseX402Requirement(
    document.accepted,
    "x402 payment handler",
  );
  if (!sameX402Requirement(accepted, challenge.requirement)) {
    throw new WardenError("Invalid x402 payment handler header");
  }
  if (document.resource !== undefined && document.resource !== null) {
    if (
      !isRecord(document.resource) ||
      !hasOnlyKeys(document.resource, ["url", "description", "mimeType"]) ||
      document.resource.url !== challenge.resourceUrl ||
      !optionalStringIsValid(document.resource, "description") ||
      !optionalStringIsValid(document.resource, "mimeType")
    ) {
      throw new WardenError("Invalid x402 payment handler header");
    }
  }
  if (
    !isRecord(document.payload) ||
    !hasOnlyKeys(document.payload, ["authorization", "signature"]) ||
    Object.keys(document.payload).length !== 2 ||
    !isRecord(document.payload.authorization) ||
    !hasOnlyKeys(document.payload.authorization, [
      "from",
      "to",
      "value",
      "validAfter",
      "validBefore",
      "nonce",
    ]) ||
    Object.keys(document.payload.authorization).length !== 6
  ) {
    throw new WardenError("Invalid x402 payment handler header");
  }
  const authorization = document.payload.authorization;
  const payer = authorization.from;
  const validAfter = authorization.validAfter;
  const validBefore = authorization.validBefore;
  const nonce = authorization.nonce;
  const signature = document.payload.signature;
  let validityIsBounded = false;
  if (
    typeof validAfter === "string" &&
    /^\d+$/.test(validAfter) &&
    validAfter.length <= 78 &&
    typeof validBefore === "string" &&
    /^\d+$/.test(validBefore) &&
    validBefore.length <= 78
  ) {
    const validAfterNumber = BigInt(validAfter);
    const validBeforeNumber = BigInt(validBefore);
    const now = BigInt(Math.floor(Date.now() / 1_000));
    validityIsBounded =
      validAfterNumber <= MAX_UINT256 &&
      validBeforeNumber <= MAX_UINT256 &&
      validBeforeNumber > validAfterNumber &&
      validAfterNumber <= now &&
      validBeforeNumber >= now + X402_MIN_REPLAY_WINDOW_SECONDS &&
      validBeforeNumber <=
        now +
          BigInt(challenge.requirement.maxTimeoutSeconds) +
          X402_CLOCK_TOLERANCE_SECONDS;
  }
  if (
    typeof payer !== "string" ||
    !/^0x[0-9a-fA-F]{40}$/.test(payer) ||
    /^0x0{40}$/.test(payer) ||
    authorization.to !== challenge.requirement.payTo ||
    authorization.value !== challenge.requirement.amount ||
    !validityIsBounded ||
    typeof nonce !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(nonce) ||
    typeof signature !== "string" ||
    !/^0x(?:[0-9a-fA-F]{2})+$/.test(signature)
  ) {
    throw new WardenError("Invalid x402 payment handler header");
  }
  return value;
}

function validateX402SettlementHeader(headers: Headers): void {
  const document = decodeX402Header(
    headers.get("PAYMENT-RESPONSE"),
    "PAYMENT-RESPONSE",
  );
  if (
    !isRecord(document) ||
    !hasOnlyKeys(document, [
      "success",
      "errorReason",
      "errorMessage",
      "status",
      "payer",
      "transaction",
      "network",
    ]) ||
    !optionalStringIsValid(document, "errorReason") ||
    !optionalStringIsValid(document, "errorMessage") ||
    !optionalStringIsValid(document, "status") ||
    (document.payer !== undefined &&
      document.payer !== null &&
      (typeof document.payer !== "string" ||
        !/^0x[0-9a-fA-F]{40}$/.test(document.payer))) ||
    document.success !== true ||
    typeof document.transaction !== "string" ||
    document.transaction.trim().length === 0 ||
    document.transaction.length > 512 ||
    document.network !== X402_NETWORK
  ) {
    throw new WardenError("Invalid x402 settlement receipt");
  }
}

function sameX402Requirement(
  left: X402PaymentRequirement,
  right: X402PaymentRequirement,
): boolean {
  return (
    left.scheme === right.scheme &&
    left.network === right.network &&
    left.asset === right.asset &&
    left.amount === right.amount &&
    left.payTo === right.payTo &&
    left.maxTimeoutSeconds === right.maxTimeoutSeconds &&
    left.extra.name === right.extra.name &&
    left.extra.version === right.extra.version
  );
}

function sameX402Challenge(left: X402Challenge, right: X402Challenge): boolean {
  return (
    left.x402Version === right.x402Version &&
    left.resourceUrl === right.resourceUrl &&
    sameX402Requirement(left.requirement, right.requirement)
  );
}

async function readPaidScanResponse(
  response: Response,
  timedOut: () => boolean,
  timeoutError: (cause: unknown) => WardenError,
): Promise<ScanResponse> {
  let data: unknown;
  try {
    data = await response.json();
  } catch (error) {
    if (timedOut()) {
      throw timeoutError(error);
    }
    if (error instanceof SyntaxError) {
      throw new WardenError("Invalid Warden response: expected JSON", error);
    }
    throw new WardenError(errorMessage(error), error);
  }
  validateScanResponse(data);
  return data;
}

function scanResultFromResponse(data: ScanResponse): ScanResult {
  return new ScanResult({
    verdict: data.verdict,
    riskLevel: data.risk_level,
    threatClasses: data.threat_classes,
    sanitizedPayload: data.sanitized_payload,
    recommendation: data.recommendation,
    latencyMs: data.latency_ms,
    raw: data,
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function validateScanResponse(value: unknown): asserts value is ScanResponse {
  if (!isRecord(value)) {
    throw invalidResponse("expected an object");
  }
  if (!isOneOf(value.verdict, ["ALLOW", "SANITIZE", "BLOCK"])) {
    throw invalidResponse("verdict");
  }
  if (
    !isOneOf(value.risk_level, ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
  ) {
    throw invalidResponse("risk_level");
  }
  if (!isStringArray(value.threat_classes)) {
    throw invalidResponse("threat_classes");
  }
  if (
    !Array.isArray(value.detections) ||
    !value.detections.every(isDetection)
  ) {
    throw invalidResponse("detections");
  }
  if (typeof value.sanitized_payload !== "string") {
    throw invalidResponse("sanitized_payload");
  }
  if (typeof value.recommendation !== "string") {
    throw invalidResponse("recommendation");
  }
  if (!isStringRecord(value.checks)) {
    throw invalidResponse("checks");
  }
  if (
    typeof value.latency_ms !== "number" ||
    !Number.isFinite(value.latency_ms)
  ) {
    throw invalidResponse("latency_ms");
  }
}

function validateFeedbackSubmission(
  value: unknown,
): asserts value is FeedbackSubmission {
  if (!isRecord(value)) {
    throw new WardenError("Feedback submission must be an object");
  }
  if (value.consentToRetain !== true || value.redactionConfirmed !== true) {
    throw new WardenError(
      "Feedback requires explicit boolean true for retention consent and redaction confirmation",
    );
  }
  if (
    !isOneOf(value.outcome, [
      "missed_attack",
      "false_positive",
      "correct_detection",
    ])
  ) {
    throw new WardenError("Feedback outcome is invalid");
  }
  if (!isOneOf(value.observedVerdict, ["ALLOW", "SANITIZE", "BLOCK"])) {
    throw new WardenError("Feedback observedVerdict is invalid");
  }
  if (
    !isOneOf(value.threatClass, [
      "PROMPT_INJECTION",
      "ROLE_OVERRIDE",
      "WEB3_INJECTION",
      "HIDDEN_UNICODE",
      "ENCODING_TRICK",
      "STATISTICAL_ANOMALY",
      "CORPUS_MATCH",
      "DRAIN_ADDRESS",
      "TOOL_HIJACK",
      "SECRET_EXFIL",
      "MALICIOUS_LINK",
    ])
  ) {
    throw new WardenError("Feedback threatClass is invalid");
  }
  if (
    typeof value.redactedReproducer !== "string" ||
    value.redactedReproducer.trim().length === 0
  ) {
    throw new WardenError("Feedback redactedReproducer must not be blank");
  }
  if (!hasValidUnicodeScalars(value.redactedReproducer)) {
    throw new WardenError(
      "Feedback redactedReproducer must contain valid unicode scalar text",
    );
  }
  if (Array.from(value.redactedReproducer).length > 4_000) {
    throw new WardenError(
      "Feedback redactedReproducer must not exceed 4000 characters",
    );
  }
  if (value.outcome === "missed_attack" && value.observedVerdict !== "ALLOW") {
    throw new WardenError(
      "Feedback missed_attack requires an observed ALLOW verdict",
    );
  }
  if (value.outcome !== "missed_attack" && value.observedVerdict === "ALLOW") {
    throw new WardenError(
      `Feedback ${value.outcome} requires a non-ALLOW observed verdict`,
    );
  }
}

function validateFeedbackResponse(
  value: unknown,
): asserts value is FeedbackResponse {
  if (!isRecord(value)) {
    throw new WardenError(
      "Invalid Warden feedback response: expected an object",
    );
  }
  const fields = Object.keys(value).sort();
  if (
    fields.length !== 3 ||
    fields[0] !== "feedback_id" ||
    fields[1] !== "retained_until" ||
    fields[2] !== "status"
  ) {
    throw new WardenError("Invalid Warden feedback response: fields");
  }
  if (
    typeof value.feedback_id !== "string" ||
    !/^[0-9a-f]{32}$/.test(value.feedback_id)
  ) {
    throw new WardenError("Invalid Warden feedback response: feedback_id");
  }
  if (!isOneOf(value.status, ["pending", "duplicate"])) {
    throw new WardenError("Invalid Warden feedback response: status");
  }
  if (
    typeof value.retained_until !== "string" ||
    !isStrictUtcTimestamp(value.retained_until)
  ) {
    throw new WardenError("Invalid Warden feedback response: retained_until");
  }
}

function hasValidUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isStrictUtcTimestamp(value: string): boolean {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?Z$/.exec(
      value,
    );
  if (match === null) {
    return false;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  const [, year, month, day, hour, minute, second] = match;
  return (
    parsed.getUTCFullYear() === Number(year) &&
    parsed.getUTCMonth() + 1 === Number(month) &&
    parsed.getUTCDate() === Number(day) &&
    parsed.getUTCHours() === Number(hour) &&
    parsed.getUTCMinutes() === Number(minute) &&
    parsed.getUTCSeconds() === Number(second)
  );
}

function invalidResponse(field: string): WardenError {
  return new WardenError(`Invalid Warden response: ${field}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    isRecord(value) &&
    Object.values(value).every((item) => typeof item === "string")
  );
}

function isDetection(value: unknown): value is Detection {
  return (
    isRecord(value) &&
    typeof value.class === "string" &&
    typeof value.match === "string" &&
    typeof value.confidence === "number" &&
    Number.isFinite(value.confidence) &&
    value.confidence >= 0 &&
    value.confidence <= 1 &&
    typeof value.source === "string"
  );
}

function isOneOf<const T extends string>(
  value: unknown,
  allowed: readonly T[],
): value is T {
  return typeof value === "string" && allowed.includes(value as T);
}
