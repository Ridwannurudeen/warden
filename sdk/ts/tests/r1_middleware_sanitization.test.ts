import { afterEach, describe, expect, it, vi } from "vitest";

import {
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

describe("R1 middleware sanitization", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("delivers the sanitized payload to downstream object-body handlers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse(
          scanResponse("SANITIZE", { sanitized_payload: "safe payload" }),
        ),
      ),
    );
    const request = { method: "POST", body: { payload: "dirty payload" } };
    const delivered: string[] = [];

    await wardenGuard()(request, new TestResponse(), () => {
      delivered.push(request.body.payload);
    });

    expect(delivered).toEqual(["safe payload"]);
  });

  it("blocks SANITIZE from a custom extractor without a safe rewrite", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        jsonResponse(
          scanResponse("SANITIZE", { sanitized_payload: "safe payload" }),
        ),
      ),
    );
    const request: WardenRequest = {
      method: "POST",
      body: { message: "dirty payload" },
    };
    const response = new TestResponse();
    const next = vi.fn();

    await wardenGuard({
      extract: (currentRequest) => {
        const body = currentRequest.body as { message: string };
        return body.message;
      },
    })(request, response, next);

    expect(response.statusCode).toBe(400);
    expect(next).not.toHaveBeenCalled();
  });
});
