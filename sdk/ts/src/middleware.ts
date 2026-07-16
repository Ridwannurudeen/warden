import { ScanResult, WardenClient } from "./client.js";

export interface WardenRequest {
  method?: string;
  body?: unknown;
}

export interface WardenResponse {
  status(code: number): WardenResponse;
  json(body: unknown): unknown;
}

export type WardenNext = (error?: unknown) => void;

type Awaitable<T> = T | Promise<T>;

export interface WardenGuardOptions {
  client?: WardenClient;
  extract?: (request: WardenRequest) => Awaitable<string | null | undefined>;
  onBlock?: (
    result: ScanResult,
    request: WardenRequest,
  ) => Awaitable<unknown>;
}

export type WardenMiddleware = (
  request: WardenRequest,
  response: WardenResponse,
  next: WardenNext,
) => Promise<void>;

export function wardenGuard(options: WardenGuardOptions = {}): WardenMiddleware {
  const client = options.client ?? new WardenClient();
  const extract = options.extract ?? extractPayload;
  const usesDefaultExtract = options.extract === undefined;

  return async (request, response, next) => {
    const method = (request.method ?? "").toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      next();
      return;
    }

    let result: ScanResult;
    try {
      const payload = await extract(request);
      if (payload === null || payload === undefined || payload.length === 0) {
        next();
        return;
      }

      result = await client.scan(payload);
      let mustBlock = result.blocked;
      if (result.sanitized) {
        if (!usesDefaultExtract) {
          mustBlock = true;
        } else if (typeof request.body === "string") {
          request.body = result.sanitizedPayload;
        } else if (isPayloadBody(request.body)) {
          request.body = {
            ...request.body,
            payload: result.sanitizedPayload,
          };
        } else {
          mustBlock = true;
        }
      }
      if (!mustBlock) {
        next();
        return;
      }

      const detail = options.onBlock
        ? await options.onBlock(result, request)
        : result.raw;
      response.status(400).json({
        error: "payload blocked by Warden",
        verdict: detail,
      });
    } catch (error) {
      next(error);
    }
  };
}

function extractPayload(request: WardenRequest): string | null {
  if (typeof request.body === "string") {
    return request.body;
  }
  if (isPayloadBody(request.body)) {
    return request.body.payload;
  }
  return null;
}

function isPayloadBody(
  body: unknown,
): body is Record<string, unknown> & { payload: string } {
  return (
    typeof body === "object" &&
    body !== null &&
    "payload" in body &&
    typeof body.payload === "string"
  );
}
