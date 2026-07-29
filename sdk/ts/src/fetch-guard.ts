import { ScanResult, WardenClient } from "./client.js";

/**
 * Web-standard fetch guard — scan an untrusted request body before the route
 * handler runs.
 *
 * The Express-style `wardenGuard` needs `(request, response, next)` and a body
 * parser. Next.js route handlers, Hono, Cloudflare Workers, Deno and Bun have
 * none of those: a handler there is `(request: Request) => Response`. This wraps
 * that shape instead, so the same check works where agent services are actually
 * deployed.
 *
 *     import { guardFetch } from "@gudman/warden-guard";
 *
 *     export const POST = guardFetch(async (request) => {
 *       const { payload } = await request.json();
 *       return Response.json({ echo: payload });
 *     });
 *
 * The handler receives a request whose body is the original text on ALLOW and
 * the sanitized text on SANITIZE, and is not called at all on BLOCK.
 */

type Awaitable<T> = T | Promise<T>;

/** A web-standard fetch handler. */
export type FetchHandler<Args extends unknown[] = unknown[]> = (
  request: Request,
  ...args: Args
) => Awaitable<Response>;

export interface WardenFetchGuardOptions {
  client?: WardenClient;
  /**
   * Choose the untrusted string. Receives the body text already read from a
   * clone, so it never has to touch the stream itself.
   */
  extract?: (
    body: string,
    request: Request,
  ) => Awaitable<string | null | undefined>;
  /**
   * Called when a request is refused. Return a `Response` to answer the caller
   * directly; return anything else and it becomes the `verdict` field of
   * Warden's own 400.
   */
  onBlock?: (
    result: ScanResult,
    request: Request,
  ) => Awaitable<Response | unknown>;
}

/** How the scanned string sits inside the body, and therefore how a sanitized one can be written back. */
type BodyShape =
  | { kind: "json-payload"; scan: string; envelope: Record<string, unknown> }
  | { kind: "text"; scan: string }
  | { kind: "opaque"; scan: string };

export function guardFetch<Args extends unknown[]>(
  handler: FetchHandler<Args>,
  options: WardenFetchGuardOptions = {},
): FetchHandler<Args> {
  const client = options.client ?? new WardenClient();
  const usesDefaultExtract = options.extract === undefined;

  return async (request: Request, ...args: Args): Promise<Response> => {
    const method = request.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      return handler(request, ...args);
    }

    // Read a clone so the original body stays unread: an ALLOW then forwards the
    // caller's own request object untouched, keeping its signal and stream intact.
    const body = await request.clone().text();
    if (body.length === 0) {
      return handler(request, ...args);
    }

    const shape = describeBody(body);
    const payload = usesDefaultExtract
      ? shape.scan
      : await options.extract!(body, request);
    if (payload === null || payload === undefined || payload.length === 0) {
      return handler(request, ...args);
    }

    const result = await client.scan(payload);

    if (result.sanitized) {
      const safeBody = usesDefaultExtract ? rewrite(shape, result) : null;
      // A custom extractor pulled the string out of a shape only the caller
      // understands, so there is no safe way to put the sanitized value back.
      // Refuse rather than hand the handler the original poisoned body.
      if (safeBody === null) {
        return await blockResponse(result, request, options);
      }
      return handler(withBody(request, safeBody), ...args);
    }

    if (result.blocked) {
      return await blockResponse(result, request, options);
    }

    return handler(request, ...args);
  };
}

function describeBody(body: string): BodyShape {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    // Not JSON, so the body is the string. A sanitized version can replace it whole.
    return { kind: "text", scan: body };
  }

  if (
    typeof parsed === "object" &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    typeof (parsed as Record<string, unknown>).payload === "string"
  ) {
    const envelope = parsed as Record<string, unknown>;
    return {
      kind: "json-payload",
      scan: envelope.payload as string,
      envelope,
    };
  }

  // JSON of some other shape. Scanning the whole document still catches an
  // attack, but a sanitized rewrite of the raw text would not reliably be valid
  // JSON, so this shape cannot be repaired — only allowed or refused.
  return { kind: "opaque", scan: body };
}

function rewrite(shape: BodyShape, result: ScanResult): string | null {
  const safe = result.sanitizedPayload;
  if (safe === null) {
    return null;
  }
  if (shape.kind === "json-payload") {
    return JSON.stringify({ ...shape.envelope, payload: safe });
  }
  if (shape.kind === "text") {
    return safe;
  }
  return null;
}

function withBody(request: Request, body: string): Request {
  // The original Content-Length describes the text we are replacing; drop it and
  // let the runtime recompute one for the body actually being sent.
  const headers = new Headers(request.headers);
  headers.delete("content-length");
  return new Request(request, { body, headers });
}

async function blockResponse(
  result: ScanResult,
  request: Request,
  options: WardenFetchGuardOptions,
): Promise<Response> {
  if (options.onBlock === undefined) {
    return jsonError(result.raw);
  }
  const handled = await options.onBlock(result, request);
  return handled instanceof Response ? handled : jsonError(handled);
}

function jsonError(verdict: unknown): Response {
  return new Response(
    JSON.stringify({ error: "payload blocked by Warden", verdict }),
    { status: 400, headers: { "content-type": "application/json" } },
  );
}
