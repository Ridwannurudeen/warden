import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type ScanOptions,
  type X402Challenge,
  WardenClient,
  WardenError,
} from "../src/index.js";
import { jsonResponse, scanResponse } from "./helpers.js";

const resourceUrl = "https://warden.gudman.xyz/scan";
const payTo = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51";
const now = 1_700_000_000;

function encode(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function requirement(
  changes: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    scheme: "exact",
    network: "eip155:196",
    asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
    amount: "100000",
    payTo,
    maxTimeoutSeconds: 300,
    extra: { name: "USD₮0", version: "1" },
    ...changes,
  };
}

function challenge(changes: Readonly<Record<string, unknown>> = {}): string {
  return encode({
    x402Version: 2,
    error: "Payment required",
    resource: {
      url: resourceUrl,
      description: "Warden payload security scan",
      mimeType: "application/json",
    },
    accepts: [requirement()],
    ...changes,
  });
}

function paymentHeader(
  current: X402Challenge,
  changes: {
    accepted?: Readonly<Record<string, unknown>>;
    authorization?: Readonly<Record<string, unknown>>;
    resourceUrl?: string;
  } = {},
): string {
  return encode({
    x402Version: 2,
    payload: {
      authorization: {
        from: "0x1111111111111111111111111111111111111111",
        to: current.requirement.payTo,
        value: current.requirement.amount,
        validAfter: String(now - 600),
        validBefore: String(now + 300),
        nonce: `0x${"22".repeat(32)}`,
        ...changes.authorization,
      },
      signature: `0x${"33".repeat(65)}`,
    },
    accepted: { ...current.requirement, ...changes.accepted },
    resource: { url: changes.resourceUrl ?? current.resourceUrl },
  });
}

function settlementHeader(
  changes: Readonly<Record<string, unknown>> = {},
): string {
  return encode({
    success: true,
    payer: "0x1111111111111111111111111111111111111111",
    transaction: `0x${"44".repeat(32)}`,
    network: "eip155:196",
    ...changes,
  });
}

describe("opt-in x402 replay", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(Date, "now").mockReturnValue(now * 1_000);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("passes validated terms to the injected handler and replays exactly once", async () => {
    const callbacks: X402Challenge[] = [];
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(scanResponse(), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    const result = await new WardenClient({
      paymentHandler: async (current) => {
        callbacks.push(current);
        return paymentHeader(current);
      },
    }).scan("untrusted", {
      expectedAddresses: ["0xabc"],
      depth: "thorough",
    });

    expect(result.allowed).toBe(true);
    expect(callbacks).toHaveLength(1);
    expect(callbacks[0]).toEqual({
      x402Version: 2,
      resourceUrl,
      requirement: requirement(),
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl, firstInit] = fetchMock.mock.calls[0]!;
    const [secondUrl, secondInit] = fetchMock.mock.calls[1]!;
    expect(firstUrl).toBe(resourceUrl);
    expect(secondUrl).toBe(resourceUrl);
    expect(firstInit?.body).toBe(secondInit?.body);
    expect(firstInit?.redirect).toBe("error");
    expect(secondInit?.redirect).toBe("error");
    expect(firstInit?.headers).toEqual({ "content-type": "application/json" });
    expect(secondInit?.headers).toEqual({
      "content-type": "application/json",
      "PAYMENT-SIGNATURE": paymentHeader(callbacks[0]!),
    });
    expect(JSON.parse(String(secondInit?.body))).toEqual({
      payload: "untrusted",
      depth: "thorough",
      context: { expected_addresses: ["0xabc"] },
    });
  });

  it("rejects an invalid paid depth before crossing any boundary", async () => {
    const invalid = { depth: "deepest" } as unknown as ScanOptions;

    await expect(
      new WardenClient({ paymentHandler: paymentHeader }).scan(
        "untrusted",
        invalid,
      ),
    ).rejects.toThrow("depth must be");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    { header: undefined },
    { header: "not-base64" },
    { header: challenge({ x402Version: 1 }) },
    {
      header: challenge({
        resource: { url: "https://attacker.invalid/scan" },
      }),
    },
    {
      header: encode({
        x402Version: 2,
        resource: { url: resourceUrl },
        accepts: [requirement({ amount: "1" })],
      }),
    },
  ])("rejects a malformed or noncanonical challenge", async ({ header }) => {
    const paymentHandler = vi.fn(() => "unused");
    fetchMock.mockResolvedValue(
      new Response(null, {
        status: 402,
        headers: header ? { "PAYMENT-REQUIRED": header } : {},
      }),
    );

    await expect(
      new WardenClient({ failOpen: true, paymentHandler }).scan("untrusted"),
    ).rejects.toBeInstanceOf(WardenError);
    expect(paymentHandler).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each(["", "not-base64", encode([])])(
    "rejects malformed callback output without replay",
    async (header) => {
      fetchMock.mockResolvedValue(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      );

      await expect(
        new WardenClient({
          paymentHandler: () => header,
        }).scan("untrusted"),
      ).rejects.toMatchObject({
        name: "WardenError",
        message: expect.stringContaining("payment handler"),
      });
      expect(fetchMock).toHaveBeenCalledOnce();
    },
  );

  it("fails closed when the caller-owned handler rejects", async () => {
    fetchMock.mockResolvedValue(
      new Response(null, {
        status: 402,
        headers: { "PAYMENT-REQUIRED": challenge() },
      }),
    );

    await expect(
      new WardenClient({
        failOpen: true,
        paymentHandler: async () => {
          throw new Error("wallet rejected request");
        },
      }).scan("untrusted"),
    ).rejects.toMatchObject({
      name: "WardenError",
      message: expect.stringContaining("payment handler failed"),
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    (current: X402Challenge) =>
      paymentHeader(current, { accepted: { amount: "1" } }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        authorization: {
          to: "0x2222222222222222222222222222222222222222",
        },
      }),
    (current: X402Challenge) =>
      paymentHeader(current, { authorization: { value: "1" } }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        authorization: { validBefore: "9".repeat(79) },
      }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        authorization: { validBefore: String(now + 5) },
      }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        authorization: { validAfter: String(now + 1) },
      }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        authorization: { validBefore: String(now + 306) },
      }),
    (current: X402Challenge) =>
      paymentHeader(current, {
        resourceUrl: "https://attacker.invalid/scan",
      }),
  ])(
    "binds the returned payment header to the validated challenge",
    async (paymentHandler) => {
      fetchMock.mockResolvedValue(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      );

      await expect(
        new WardenClient({
          failOpen: true,
          paymentHandler,
        }).scan("untrusted"),
      ).rejects.toThrow("payment handler");
      expect(fetchMock).toHaveBeenCalledOnce();
    },
  );

  it.each([
    { second: challenge(), message: "one paid replay" },
    {
      second: encode({
        x402Version: 2,
        resource: { url: resourceUrl },
        accepts: [requirement({ amount: "1" })],
      }),
      message: "changed",
    },
    { second: "not-base64", message: "changed" },
  ])(
    "never invokes the handler twice after a second 402",
    async ({ second, message }) => {
      const paymentHandler = vi.fn(paymentHeader);
      fetchMock
        .mockResolvedValueOnce(
          new Response(null, {
            status: 402,
            headers: { "PAYMENT-REQUIRED": challenge() },
          }),
        )
        .mockResolvedValueOnce(
          new Response(null, {
            status: 402,
            headers: { "PAYMENT-REQUIRED": second },
          }),
        );

      await expect(
        new WardenClient({ failOpen: true, paymentHandler }).scan("untrusted"),
      ).rejects.toThrow(message);
      expect(paymentHandler).toHaveBeenCalledOnce();
      expect(fetchMock).toHaveBeenCalledTimes(2);
    },
  );

  it.each([
    {
      response: new Response(null, {
        status: 302,
        headers: { location: "https://attacker.invalid/capture" },
      }),
      message: "redirect",
    },
    {
      response: jsonResponse(scanResponse()),
      message: "PAYMENT-RESPONSE",
    },
    {
      response: jsonResponse(scanResponse(), 200, {
        "PAYMENT-RESPONSE": "not-base64",
      }),
      message: "PAYMENT-RESPONSE",
    },
    {
      response: jsonResponse(scanResponse(), 200, {
        "PAYMENT-RESPONSE": settlementHeader({ success: false }),
      }),
      message: "settlement",
    },
    {
      response: jsonResponse(scanResponse(), 200, {
        "PAYMENT-RESPONSE": settlementHeader({ network: "eip155:1" }),
      }),
      message: "settlement",
    },
  ])(
    "fails closed on a redirected or unverified replay",
    async ({ response, message }) => {
      fetchMock
        .mockResolvedValueOnce(
          new Response(null, {
            status: 402,
            headers: { "PAYMENT-REQUIRED": challenge() },
          }),
        )
        .mockResolvedValueOnce(response);

      await expect(
        new WardenClient({
          failOpen: true,
          paymentHandler: paymentHeader,
        }).scan("untrusted"),
      ).rejects.toThrow(message);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    },
  );

  it("rejects a malformed scan result after verified settlement", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ verdict: "MAYBE" }, 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    await expect(
      new WardenClient({
        failOpen: true,
        paymentHandler: paymentHeader,
      }).scan("untrusted"),
    ).rejects.toThrow("verdict");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
