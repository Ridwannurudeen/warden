import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  WardenClient,
  WardenError,
  type WardenRequest,
  type WardenResponse,
  wardenGuard,
} from "../src/index.js";
import { jsonResponse, scanResponse } from "./helpers.js";

class TestResponse implements WardenResponse {
  statusCode: number | undefined;
  body: unknown;

  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  json(body: unknown): this {
    this.body = body;
    return this;
  }
}

describe("wardenGuard", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it.each(["GET", "HEAD", "OPTIONS"])("skips %s requests", async (method) => {
    const next = vi.fn();

    await wardenGuard()(
      { method, body: { payload: "evil" } },
      new TestResponse(),
      next,
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });

  it("extracts body.payload and returns a 400 JSON response for BLOCK", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("BLOCK")));
    const request = { method: "POST", body: { payload: "evil" } };
    const response = new TestResponse();
    const next = vi.fn();

    await wardenGuard()(request, response, next);

    expect(response.statusCode).toBe(400);
    expect(response.body).toEqual({
      error: "payload blocked by Warden",
      verdict: scanResponse("BLOCK"),
    });
    expect(next).not.toHaveBeenCalled();
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toMatchObject({
      payload: "evil",
    });
  });

  it("accepts a string body and passes ALLOW through", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("ALLOW")));
    const next = vi.fn();

    await wardenGuard()(
      { method: "POST", body: "hello" },
      new TestResponse(),
      next,
    );

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });

  it("passes requests without an extractable payload through", async () => {
    const next = vi.fn();

    await wardenGuard()(
      { method: "POST", body: { message: "not configured" } },
      new TestResponse(),
      next,
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledOnce();
  });

  it("does not rewrite the request body for SANITIZE", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("SANITIZE")));
    const request = { method: "POST", body: { payload: "dirty" } };
    const originalBody = request.body;
    const next = vi.fn();

    await wardenGuard()(request, new TestResponse(), next);

    expect(request.body).toBe(originalBody);
    expect(request.body.payload).toBe("dirty");
    expect(next).toHaveBeenCalledOnce();
  });

  it("supports custom extraction and block detail", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("BLOCK")));
    const request: WardenRequest = {
      method: "POST",
      body: { message: "evil" },
    };
    const response = new TestResponse();

    await wardenGuard({
      extract: (currentRequest) => {
        const body = currentRequest.body as { message: string };
        return body.message;
      },
      onBlock: (result) => ({ threatClasses: result.threatClasses }),
    })(request, response, vi.fn());

    expect(response.statusCode).toBe(400);
    expect(response.body).toEqual({
      error: "payload blocked by Warden",
      verdict: { threatClasses: ["PROMPT_INJECTION"] },
    });
  });

  it("passes fail-closed client errors to next", async () => {
    fetchMock.mockRejectedValue(new TypeError("network down"));
    const response = new TestResponse();
    const next = vi.fn();

    await wardenGuard({ client: new WardenClient({ failOpen: false }) })(
      { method: "POST", body: { payload: "hello" } },
      response,
      next,
    );

    expect(response.statusCode).toBeUndefined();
    expect(next).toHaveBeenCalledOnce();
    expect(next.mock.calls[0]?.[0]).toBeInstanceOf(WardenError);
  });
});
