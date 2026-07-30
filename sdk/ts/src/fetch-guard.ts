import { ScanResult, WardenClient } from "./client.js";

const DEFAULT_MAX_RESPONSE_BYTES = 1_000_000;
const RESPONSE_JSON_FIELDS = [
  "payload",
  "result",
  "output",
  "tool_result",
] as const;

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
   * Scan handler responses before returning them to the agent. Disabled by
   * default for backward compatibility. Enabling it is fail-closed: a supplied
   * client must use `failOpen: false`.
   */
  guardResponses?: boolean;
  /** Maximum guarded response size in bytes. */
  maxResponseBytes?: number;
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

type ResponseBodyShape =
  | {
      kind: "json-field";
      scan: string;
      envelope: Record<string, unknown>;
      field: (typeof RESPONSE_JSON_FIELDS)[number];
    }
  | { kind: "json-string"; scan: string }
  | { kind: "text"; scan: string }
  | { kind: "opaque-json"; scan: string };

class ResponseGuardFailure extends Error {}

export function guardFetch<Args extends unknown[]>(
  handler: FetchHandler<Args>,
  options: WardenFetchGuardOptions = {},
): FetchHandler<Args> {
  if (
    options.guardResponses !== undefined &&
    typeof options.guardResponses !== "boolean"
  ) {
    throw new TypeError("guardResponses must be a boolean");
  }
  const guardResponses = options.guardResponses === true;
  const maxResponseBytes =
    options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) {
    throw new TypeError("maxResponseBytes must be a positive safe integer");
  }
  if (
    guardResponses &&
    options.client !== undefined &&
    options.client.failOpen
  ) {
    throw new TypeError(
      "guardResponses requires a WardenClient with failOpen: false",
    );
  }
  const client =
    options.client ??
    new WardenClient({ failOpen: guardResponses ? false : true });
  const usesDefaultExtract = options.extract === undefined;

  return async (request: Request, ...args: Args): Promise<Response> => {
    const method = request.method.toUpperCase();
    const invokeHandler = async (forwarded: Request): Promise<Response> => {
      const response = await handler(forwarded, ...args);
      if (!guardResponses || method === "HEAD") {
        return response;
      }
      return guardHandlerResponse(response, client, maxResponseBytes);
    };

    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      return invokeHandler(request);
    }

    // Read a clone so the original body stays unread: an ALLOW then forwards the
    // caller's own request object untouched, keeping its signal and stream intact.
    const body = await request.clone().text();
    if (body.length === 0) {
      return invokeHandler(request);
    }

    const shape = describeBody(body);
    const payload = usesDefaultExtract
      ? shape.scan
      : await options.extract!(body, request);
    if (payload === null || payload === undefined || payload.length === 0) {
      return invokeHandler(request);
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
      return invokeHandler(withBody(request, safeBody));
    }

    if (result.blocked) {
      return await blockResponse(result, request, options);
    }

    return invokeHandler(request);
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

async function guardHandlerResponse(
  response: Response,
  client: WardenClient,
  maxResponseBytes: number,
): Promise<Response> {
  let bytes: Uint8Array;
  let shape: ResponseBodyShape;
  try {
    bytes = await readResponseBytes(response, maxResponseBytes);
    if (bytes.byteLength === 0) {
      return response;
    }
    shape = describeResponseBody(response, bytes);
  } catch (error) {
    const reason =
      error instanceof ResponseGuardFailure
        ? error.message
        : "response could not be inspected";
    return responseGuardError(reason);
  }

  let result: ScanResult;
  try {
    result = await client.scan(shape.scan);
  } catch {
    return responseGuardError("response scanner unavailable");
  }

  if (result.allowed) {
    return response;
  }
  if (result.blocked) {
    return responseGuardError("response blocked by Warden");
  }

  const safeBody = rewriteResponse(shape, result);
  if (safeBody === null) {
    return responseGuardError("response could not be safely rewritten");
  }
  return withResponseBody(response, safeBody);
}

async function readResponseBytes(
  response: Response,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^[0-9]+$/.test(declaredLength)) {
      throw new ResponseGuardFailure("response content-length is malformed");
    }
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength)) {
      throw new ResponseGuardFailure("response content-length is malformed");
    }
    if (parsedLength > maxResponseBytes) {
      throw new ResponseGuardFailure("response body is too large");
    }
  }

  let clone: Response;
  try {
    clone = response.clone();
  } catch {
    throw new ResponseGuardFailure("response body is not readable");
  }
  if (clone.body === null) {
    return new Uint8Array();
  }

  const reader = clone.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxResponseBytes) {
        // A cloned response uses a tee'd stream. Awaiting cancellation of one
        // branch can wait for the untouched original branch indefinitely.
        void reader.cancel();
        throw new ResponseGuardFailure("response body is too large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ResponseGuardFailure) {
      throw error;
    }
    throw new ResponseGuardFailure("response body is not readable");
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

function describeResponseBody(
  response: Response,
  bytes: Uint8Array,
): ResponseBodyShape {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ResponseGuardFailure("response body must be UTF-8");
  }

  if (!isJsonContentType(response.headers.get("content-type"))) {
    return { kind: "text", scan: text };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ResponseGuardFailure("response body contains malformed JSON");
  }
  if (typeof parsed === "string") {
    return { kind: "json-string", scan: parsed };
  }
  if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
    const envelope = parsed as Record<string, unknown>;
    const fields = RESPONSE_JSON_FIELDS.filter(
      (field) => typeof envelope[field] === "string",
    );
    if (fields.length === 1) {
      const field = fields[0];
      if (field !== undefined) {
        return {
          kind: "json-field",
          scan: envelope[field] as string,
          envelope,
          field,
        };
      }
    }
  }
  return { kind: "opaque-json", scan: text };
}

function isJsonContentType(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  const mediaType = value.split(";", 1)[0]?.trim().toLowerCase();
  return (
    mediaType === "application/json" || (mediaType?.endsWith("+json") ?? false)
  );
}

function rewriteResponse(
  shape: ResponseBodyShape,
  result: ScanResult,
): string | null {
  const safe = result.sanitizedPayload;
  if (safe === null) {
    return null;
  }
  if (shape.kind === "json-field") {
    return JSON.stringify({ ...shape.envelope, [shape.field]: safe });
  }
  if (shape.kind === "json-string") {
    return JSON.stringify(safe);
  }
  if (shape.kind === "text") {
    return safe;
  }
  return null;
}

function withResponseBody(response: Response, body: string): Response {
  const headers = new Headers(response.headers);
  for (const header of [
    "content-encoding",
    "content-length",
    "content-md5",
    "digest",
    "etag",
  ]) {
    headers.delete(header);
  }
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function responseGuardError(reason: string): Response {
  return new Response(JSON.stringify({ error: reason }), {
    status: 502,
    headers: { "content-type": "application/json" },
  });
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
