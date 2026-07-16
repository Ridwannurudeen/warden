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
      if (!result.blocked) {
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
  if (
    typeof request.body === "object" &&
    request.body !== null &&
    "payload" in request.body &&
    typeof request.body.payload === "string"
  ) {
    return request.body.payload;
  }
  return null;
}

