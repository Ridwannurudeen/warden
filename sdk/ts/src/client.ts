const DEFAULT_BASE_URL = "https://warden.gudman.xyz";

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
}

export interface ScanOptions {
  expectedAddresses?: readonly string[];
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

  constructor(options: WardenClientOptions = {}) {
    const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    const timeoutMs = options.timeoutMs ?? 8_000;

    if (baseUrl.length === 0) {
      throw new TypeError("baseUrl must not be empty");
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive number");
    }

    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = timeoutMs;
    this.failOpen = options.failOpen ?? true;
  }

  async scan(payload: string, options: ScanOptions = {}): Promise<ScanResult> {
    const body: {
      payload: string;
      depth: "fast";
      context?: { expected_addresses: readonly string[] };
    } = { payload, depth: "fast" };

    if (options.expectedAddresses && options.expectedAddresses.length > 0) {
      body.context = { expected_addresses: options.expectedAddresses };
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

      return new ScanResult({
        verdict: data.verdict,
        riskLevel: data.risk_level,
        threatClasses: data.threat_classes,
        sanitizedPayload: data.sanitized_payload,
        recommendation: data.recommendation,
        latencyMs: data.latency_ms,
        raw: data,
      });
    } finally {
      clearTimeout(timeout);
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
