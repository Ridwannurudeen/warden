import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FeedbackSubmission,
  WardenBlocked,
  WardenClient,
  WardenError,
  type ScanOptions,
  type WardenClientOptions,
} from "../src/index.js";
import { jsonResponse, scanResponse } from "./helpers.js";

describe("WardenClient", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("uses the documented client defaults", () => {
    const client = new WardenClient();

    expect(client.baseUrl).toBe("https://warden.gudman.xyz");
    expect("paid" in client).toBe(false);
    expect(client.timeoutMs).toBe(8_000);
    expect(client.failOpen).toBe(true);
  });

  it("always uses the fast-only free scan contract", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse()));
    const client = new WardenClient({ baseUrl: "https://warden.test/" });
    const legacyOptions = {
      expectedAddresses: ["0xabc"],
      depth: "thorough",
    } as unknown as ScanOptions;

    await client.scan("hello", legacyOptions);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [input, init] = fetchMock.mock.calls[0]!;
    expect(input).toBe("https://warden.test/api/demo/scan");
    expect(init).toMatchObject({
      method: "POST",
      headers: { "content-type": "application/json" },
    });
    expect(JSON.parse(String(init?.body))).toEqual({
      payload: "hello",
      depth: "fast",
      context: { expected_addresses: ["0xabc"] },
    });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("does not expose an inoperable paid-path switch", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse()));
    const legacyOptions = {
      baseUrl: "https://warden.test",
      paid: true,
    } as unknown as WardenClientOptions;
    const client = new WardenClient(legacyOptions);

    await client.scan("hello");

    const [input, init] = fetchMock.mock.calls[0]!;
    expect(input).toBe("https://warden.test/api/demo/scan");
    expect("paid" in client).toBe(false);
    expect(JSON.parse(String(init?.body))).toEqual({
      payload: "hello",
      depth: "fast",
    });
  });

  it("maps ALLOW and its convenience getters", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("ALLOW")));

    const result = await new WardenClient().scan("hello");

    expect(result.verdict).toBe("ALLOW");
    expect(result.riskLevel).toBe("NONE");
    expect(result.allowed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.sanitized).toBe(false);
    expect(result.safePayload).toBeNull();
  });

  it("maps SANITIZE and exposes the safe payload", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(scanResponse("SANITIZE", { sanitized_payload: "clean" })),
    );

    const result = await new WardenClient().scan("dirty");

    expect(result.sanitized).toBe(true);
    expect(result.safePayload).toBe("clean");
    expect(result.threatClasses).toEqual(["PROMPT_INJECTION"]);
    expect(result.latencyMs).toBe(1.25);
  });

  it("maps BLOCK and never exposes a safe payload", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("BLOCK")));

    const result = await new WardenClient().scan("evil");

    expect(result.blocked).toBe(true);
    expect(result.allowed).toBe(false);
    expect(result.safePayload).toBeNull();
    expect(result.recommendation).toBe("Review the payload.");
  });

  it("guard returns the original payload for ALLOW", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("ALLOW")));

    await expect(new WardenClient().guard("hello")).resolves.toBe("hello");
  });

  it("guard returns sanitized text for SANITIZE", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(scanResponse("SANITIZE", { sanitized_payload: "clean" })),
    );

    await expect(new WardenClient().guard("dirty")).resolves.toBe("clean");
  });

  it("guard throws WardenBlocked for BLOCK", async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanResponse("BLOCK")));

    const guarded = new WardenClient().guard("evil");
    await expect(guarded).rejects.toBeInstanceOf(WardenBlocked);
    await expect(guarded).rejects.toMatchObject({
      result: expect.objectContaining({ verdict: "BLOCK" }),
    });
  });

  it("fails open on a network error by default", async () => {
    fetchMock.mockRejectedValue(new TypeError("network down"));
    const client = new WardenClient();

    const result = await client.scan("hello");

    expect(client.failOpen).toBe(true);
    expect(result.allowed).toBe(true);
    expect(result.raw).toEqual({ error: "network down" });
  });

  it("fails open when the response body stream terminates after headers", async () => {
    const response = jsonResponse(scanResponse());
    Object.defineProperty(response, "json", {
      value: () => Promise.reject(new TypeError("body stream terminated")),
    });
    fetchMock.mockResolvedValue(response);

    const result = await new WardenClient().scan("hello");

    expect(result.allowed).toBe(true);
    expect(result.raw).toEqual({ error: "body stream terminated" });
  });

  it("fails closed when the response body stream terminates after headers", async () => {
    const response = jsonResponse(scanResponse());
    Object.defineProperty(response, "json", {
      value: () => Promise.reject(new TypeError("body stream terminated")),
    });
    fetchMock.mockResolvedValue(response);

    await expect(
      new WardenClient({ failOpen: false }).scan("hello"),
    ).rejects.toMatchObject({
      name: "WardenError",
      message: "body stream terminated",
    });
  });

  it("throws when malformed JSON is returned with a success status", async () => {
    const response = jsonResponse(scanResponse());
    Object.defineProperty(response, "json", {
      value: () => Promise.reject(new SyntaxError("unexpected token")),
    });
    fetchMock.mockResolvedValue(response);

    await expect(new WardenClient().scan("hello")).rejects.toMatchObject({
      name: "WardenError",
      message: "Invalid Warden response: expected JSON",
    });
  });

  it("fails open on a non-success HTTP response by default", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ detail: "unavailable" }, 503));

    const result = await new WardenClient().scan("hello");

    expect(result.allowed).toBe(true);
    expect(result.raw.error).toContain("503");
  });

  it("fails open when the request times out by default", async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => reject(new DOMException("aborted", "AbortError")),
            { once: true },
          );
        }),
    );
    const pending = new WardenClient({ timeoutMs: 25 }).scan("hello");

    await vi.advanceTimersByTimeAsync(25);
    const result = await pending;

    expect(result.allowed).toBe(true);
    expect(result.raw).toEqual({
      error: "Warden request timed out after 25ms",
    });
  });

  it.each([
    {
      failOpen: true,
      expected: {
        result: {
          verdict: "ALLOW",
          raw: { error: "Warden request timed out after 25ms" },
        },
      },
    },
    {
      failOpen: false,
      expected: {
        error: expect.objectContaining({
          name: "WardenError",
          message: "Warden request timed out after 25ms",
        }),
      },
    },
  ])(
    "keeps the timeout active while reading the response body (failOpen=$failOpen)",
    async ({ failOpen, expected }) => {
      vi.useFakeTimers();
      let requestSignal: AbortSignal | undefined;
      let rejectBody: (reason: unknown) => void = () => undefined;
      fetchMock.mockImplementation((_input, init) => {
        requestSignal = init?.signal ?? undefined;
        const response = jsonResponse(scanResponse());
        Object.defineProperty(response, "json", {
          value: () =>
            new Promise<unknown>((_resolve, reject) => {
              rejectBody = reject;
              requestSignal?.addEventListener(
                "abort",
                () => reject(new DOMException("aborted", "AbortError")),
                { once: true },
              );
            }),
        });
        return Promise.resolve(response);
      });
      const pending = new WardenClient({ failOpen, timeoutMs: 25 }).scan(
        "hello",
      );
      const outcomePromise = pending.then(
        (result) => ({ result }),
        (error: unknown) => ({ error }),
      );

      await vi.advanceTimersByTimeAsync(25);
      const aborted = requestSignal?.aborted;
      rejectBody(new DOMException("aborted", "AbortError"));
      const outcome = await outcomePromise;

      expect(aborted).toBe(true);
      expect(outcome).toMatchObject(expected);
    },
  );

  it("throws WardenError on transport failure when failOpen is false", async () => {
    fetchMock.mockRejectedValue(new TypeError("network down"));

    await expect(
      new WardenClient({ failOpen: false }).scan("hello"),
    ).rejects.toBeInstanceOf(WardenError);
  });

  it("throws WardenError on HTTP failure when failOpen is false", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ detail: "unavailable" }, 503));

    await expect(
      new WardenClient({ failOpen: false }).scan("hello"),
    ).rejects.toMatchObject({
      name: "WardenError",
      message: expect.stringContaining("503"),
    });
  });

  it("rejects malformed success responses even in fail-open mode", async () => {
    const { checks: _checks, ...malformed } = scanResponse();
    fetchMock.mockResolvedValue(jsonResponse(malformed));

    await expect(new WardenClient().scan("hello")).rejects.toMatchObject({
      name: "WardenError",
      message: expect.stringContaining("checks"),
    });
  });

  const feedbackSubmission: FeedbackSubmission = {
    outcome: "missed_attack",
    observedVerdict: "ALLOW",
    threatClass: "PROMPT_INJECTION",
    redactedReproducer: "Human-reviewed reproducer with secrets removed.",
    consentToRetain: true,
    redactionConfirmed: true,
  };

  const feedbackResponse = {
    feedback_id: "0123456789abcdef0123456789abcdef",
    status: "pending",
    retained_until: "2026-10-16T12:00:00Z",
  };

  it("submits feedback only through the explicit dedicated contract", async () => {
    fetchMock.mockResolvedValue(jsonResponse(feedbackResponse, 202));

    const result = await new WardenClient({
      baseUrl: "https://warden.test/",
    }).submitFeedback(feedbackSubmission);

    expect(result).toEqual({
      feedbackId: "0123456789abcdef0123456789abcdef",
      status: "pending",
      retainedUntil: "2026-10-16T12:00:00Z",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [input, init] = fetchMock.mock.calls[0]!;
    expect(input).toBe("https://warden.test/api/feedback");
    expect(init).toMatchObject({
      method: "POST",
      headers: { "content-type": "application/json" },
    });
    expect(JSON.parse(String(init?.body))).toEqual({
      outcome: "missed_attack",
      observed_verdict: "ALLOW",
      threat_class: "PROMPT_INJECTION",
      redacted_reproducer: "Human-reviewed reproducer with secrets removed.",
      consent_to_retain: true,
      redaction_confirmed: true,
    });
  });

  it.each([
    { consentToRetain: false },
    { consentToRetain: 1 },
    { redactionConfirmed: false },
    { redactionConfirmed: 1 },
  ])(
    "requires literal consent before feedback reaches the network",
    async (change) => {
      const invalid = {
        ...feedbackSubmission,
        ...change,
      } as unknown as FeedbackSubmission;

      await expect(
        new WardenClient().submitFeedback(invalid),
      ).rejects.toMatchObject({
        name: "WardenError",
        message: expect.stringContaining("explicit boolean true"),
      });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("never applies scan fail-open behavior to feedback submission", async () => {
    fetchMock.mockRejectedValue(new TypeError("feedback unavailable"));

    await expect(
      new WardenClient({ failOpen: true }).submitFeedback(feedbackSubmission),
    ).rejects.toMatchObject({
      name: "WardenError",
      message: expect.stringContaining("feedback submission failed"),
    });
  });

  it.each([
    { ...feedbackResponse, feedback_id: "not-an-id" },
    { ...feedbackResponse, unexpected: "field" },
    { ...feedbackResponse, retained_until: "not-a-timestamp" },
    { ...feedbackResponse, retained_until: "2026-02-31T12:00:00Z" },
  ])("rejects malformed feedback receipts", async (body) => {
    fetchMock.mockResolvedValue(jsonResponse(body, 202));

    await expect(
      new WardenClient({ failOpen: true }).submitFeedback(feedbackSubmission),
    ).rejects.toBeInstanceOf(WardenError);
  });

  it.each([
    { outcome: "unknown" },
    { observedVerdict: "MAYBE" },
    { threatClass: "UNKNOWN" },
    { redactedReproducer: "x".repeat(4001) },
    { redactedReproducer: "\ud800" },
  ])(
    "rejects feedback outside the backend contract before fetch",
    async (change) => {
      const invalid = {
        ...feedbackSubmission,
        ...change,
      } as unknown as FeedbackSubmission;

      await expect(
        new WardenClient().submitFeedback(invalid),
      ).rejects.toBeInstanceOf(WardenError);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    { outcome: "missed_attack", observedVerdict: "SANITIZE" },
    { outcome: "missed_attack", observedVerdict: "BLOCK" },
    { outcome: "false_positive", observedVerdict: "ALLOW" },
    { outcome: "correct_detection", observedVerdict: "ALLOW" },
  ])(
    "rejects contradictory $outcome/$observedVerdict feedback before fetch",
    async (change) => {
      const invalid = {
        ...feedbackSubmission,
        ...change,
      } as unknown as FeedbackSubmission;

      await expect(
        new WardenClient().submitFeedback(invalid),
      ).rejects.toMatchObject({
        name: "WardenError",
        message: expect.stringContaining("requires"),
      });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    { outcome: "missed_attack", observedVerdict: "ALLOW" },
    { outcome: "false_positive", observedVerdict: "BLOCK" },
    { outcome: "correct_detection", observedVerdict: "SANITIZE" },
  ] as const)(
    "accepts valid $outcome/$observedVerdict feedback with 4000 Unicode scalars",
    async ({ outcome, observedVerdict }) => {
      fetchMock.mockResolvedValue(jsonResponse(feedbackResponse, 202));
      const submission = {
        ...feedbackSubmission,
        outcome,
        observedVerdict,
        redactedReproducer: "😀".repeat(4000),
      } satisfies FeedbackSubmission;

      await expect(
        new WardenClient().submitFeedback(submission),
      ).resolves.toMatchObject({ status: "pending" });
    },
  );
});
