import { afterEach, describe, expect, it, vi } from "vitest";

import { WardenClient, guardFetch } from "../src/index.js";
import { jsonResponse, scanResponse } from "./helpers.js";

function stubScan(verdict: "ALLOW" | "SANITIZE" | "BLOCK", overrides = {}) {
  const fetchMock = vi
    .fn<typeof fetch>()
    .mockResolvedValue(jsonResponse(scanResponse(verdict, overrides)));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function post(body: string, headers: HeadersInit = {}): Request {
  return new Request("https://agent.example/act", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("guardFetch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("passes an allowed request through with its body still readable", async () => {
    stubScan("ALLOW");
    const handler = guardFetch(async (request) => {
      const body = (await request.json()) as { payload: string };
      return Response.json({ echo: body.payload });
    });

    const response = await handler(post(JSON.stringify({ payload: "hello" })));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ echo: "hello" });
  });

  it("forwards the caller's own Request object on ALLOW", async () => {
    // The README promises the original request survives untouched, signal and
    // all. Identity is the strongest statement of that.
    stubScan("ALLOW");
    const received: Request[] = [];
    const handler = guardFetch(async (request) => {
      received.push(request);
      return new Response("ok");
    });
    const request = post(JSON.stringify({ payload: "hello" }));

    await handler(request);

    expect(received[0]).toBe(request);
    expect(request.bodyUsed).toBe(false);
  });

  it("hands the handler the sanitized payload, not the poisoned one", async () => {
    stubScan("SANITIZE", { sanitized_payload: "safe payload" });
    const seen: string[] = [];
    const handler = guardFetch(async (request) => {
      const body = (await request.json()) as { payload: string };
      seen.push(body.payload);
      return new Response("ok");
    });

    await handler(post(JSON.stringify({ payload: "dirty payload" })));

    expect(seen).toEqual(["safe payload"]);
  });

  it("keeps the rest of the JSON envelope when it rewrites the payload", async () => {
    stubScan("SANITIZE", { sanitized_payload: "safe payload" });
    let received: Record<string, unknown> = {};
    const handler = guardFetch(async (request) => {
      received = (await request.json()) as Record<string, unknown>;
      return new Response("ok");
    });

    await handler(
      post(JSON.stringify({ payload: "dirty payload", chatId: 42 })),
    );

    expect(received).toEqual({ payload: "safe payload", chatId: 42 });
  });

  it("replaces the whole body when the request is not JSON", async () => {
    stubScan("SANITIZE", { sanitized_payload: "safe text" });
    const seen: string[] = [];
    const handler = guardFetch(async (request) => {
      seen.push(await request.text());
      return new Response("ok");
    });

    await handler(post("dirty text", { "content-type": "text/plain" }));

    expect(seen).toEqual(["safe text"]);
  });

  it("does not run the handler on BLOCK", async () => {
    stubScan("BLOCK");
    const handler = vi.fn(async () => new Response("ok"));

    const response = await guardFetch(handler)(
      post(JSON.stringify({ payload: "drain everything" })),
    );

    expect(handler).not.toHaveBeenCalled();
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: "payload blocked by Warden",
    });
  });

  it("refuses a SANITIZE it cannot safely rewrite", async () => {
    // A JSON body with no `payload` field is scanned whole, but a sanitized
    // rewrite of the raw document would not reliably still be valid JSON.
    stubScan("SANITIZE", { sanitized_payload: "safe" });
    const handler = vi.fn(async () => new Response("ok"));

    const response = await guardFetch(handler)(
      post(JSON.stringify({ message: "dirty payload" })),
    );

    expect(handler).not.toHaveBeenCalled();
    expect(response.status).toBe(400);
  });

  it("refuses a SANITIZE from a custom extractor rather than forwarding the original", async () => {
    stubScan("SANITIZE", { sanitized_payload: "safe" });
    const handler = vi.fn(async () => new Response("ok"));

    const response = await guardFetch(handler, {
      extract: (body) => (JSON.parse(body) as { message: string }).message,
    })(post(JSON.stringify({ message: "dirty payload" })));

    expect(handler).not.toHaveBeenCalled();
    expect(response.status).toBe(400);
  });

  it("scans the string a custom extractor chooses", async () => {
    const fetchMock = stubScan("ALLOW");
    const handler = guardFetch(async () => new Response("ok"), {
      extract: (body) => (JSON.parse(body) as { message: string }).message,
    });

    await handler(post(JSON.stringify({ message: "look at this" })));

    const sent = fetchMock.mock.calls[0]?.[1]?.body;
    expect(JSON.parse(String(sent))).toMatchObject({ payload: "look at this" });
  });

  it("never scans a GET, and leaves it untouched", async () => {
    const fetchMock = stubScan("BLOCK");
    const handler = vi.fn(async () => new Response("ok"));

    const response = await guardFetch(handler)(
      new Request("https://agent.example/act"),
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(handler).toHaveBeenCalled();
    expect(response.status).toBe(200);
  });

  it("passes an empty body through without scanning", async () => {
    const fetchMock = stubScan("BLOCK");
    const handler = vi.fn(async () => new Response("ok"));

    await guardFetch(handler)(
      new Request("https://agent.example/act", { method: "POST" }),
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(handler).toHaveBeenCalled();
  });

  it("lets onBlock answer with its own Response", async () => {
    stubScan("BLOCK");
    const handler = guardFetch(async () => new Response("ok"), {
      onBlock: () => new Response("nope", { status: 403 }),
    });

    const response = await handler(
      post(JSON.stringify({ payload: "drain everything" })),
    );

    expect(response.status).toBe(403);
    await expect(response.text()).resolves.toBe("nope");
  });

  it("uses a non-Response onBlock return as the verdict detail", async () => {
    stubScan("BLOCK");
    const handler = guardFetch(async () => new Response("ok"), {
      onBlock: (result) => ({ classes: result.threatClasses }),
    });

    const response = await handler(
      post(JSON.stringify({ payload: "drain everything" })),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "payload blocked by Warden",
      verdict: { classes: ["PROMPT_INJECTION"] },
    });
  });

  it("forwards the extra arguments a Worker or dynamic route receives", async () => {
    stubScan("ALLOW");
    const seen: unknown[] = [];
    const handler = guardFetch(async (_request, env: string, ctx: number) => {
      seen.push(env, ctx);
      return new Response("ok");
    });

    await handler(post(JSON.stringify({ payload: "hello" })), "env", 7);

    expect(seen).toEqual(["env", 7]);
  });

  it("propagates a scan failure when the client is fail-closed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockRejectedValue(new Error("network down")),
    );
    const handler = vi.fn(async () => new Response("ok"));

    await expect(
      guardFetch(handler, {
        client: new WardenClient({ failOpen: false }),
      })(post(JSON.stringify({ payload: "hello" }))),
    ).rejects.toThrow();
    expect(handler).not.toHaveBeenCalled();
  });
});
