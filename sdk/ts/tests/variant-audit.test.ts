import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { WardenClient, WardenError } from "../src/index.js";
import { jsonResponse } from "./helpers.js";

const resourceUrl = "https://warden.gudman.xyz/variant-audit";
const payTo = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51";
const now = 1_700_000_000;
const reportId = "a".repeat(64);

function encode(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function requirement(): Record<string, unknown> {
  return {
    scheme: "exact",
    network: "eip155:196",
    asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
    amount: "100000",
    payTo,
    maxTimeoutSeconds: 300,
    extra: { name: "USD₮0", version: "1" },
  };
}

function challenge(): string {
  return encode({
    x402Version: 2,
    error: "Payment required",
    resource: {
      url: resourceUrl,
      description: "Warden adversarial variant audit",
      mimeType: "application/json",
    },
    accepts: [requirement()],
  });
}

function paymentHeader(current: {
  requirement: Record<string, unknown>;
  resourceUrl: string;
}): string {
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
      },
      signature: `0x${"33".repeat(65)}`,
    },
    accepted: current.requirement,
    resource: { url: current.resourceUrl },
  });
}

function settlementHeader(): string {
  return encode({
    success: true,
    payer: "0x1111111111111111111111111111111111111111",
    transaction: `0x${"44".repeat(32)}`,
    network: "eip155:196",
  });
}

function classEntry(
  changes: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    threat_class: "DRAIN_ADDRESS",
    total: 4,
    detected: 4,
    missed: 0,
    inconclusive: 0,
    conclusive: 4,
    detection_rate: 100,
    grade: "A",
    ...changes,
  };
}

function auditResponse(
  changes: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: 2,
    target_host: "agent.example",
    corpus_fingerprint: `sha256:${"0".repeat(64)}`,
    generator: "warden-adversarial-variants/4",
    caps: {
      depth: "standard",
      max_variants_per_class: 25,
      max_total_variants: 150,
      probe_timeout_seconds: 5,
      total_timeout_seconds: 180,
      max_response_bytes: 100000,
    },
    per_class: [classEntry()],
    totals: {
      ...classEntry(),
      threat_classes: 1,
      variants_sent: 4,
    },
    consent_verified: true,
    limitations: ["Point-in-time evidence."],
    delta: null,
    report_id: reportId,
    issuer: "warden",
    issued_at: now,
    issuer_sig: "sig:AAAA",
    ...changes,
  };
}

describe("variantAudit", () => {
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

  function payingClient(): WardenClient {
    return new WardenClient({
      paymentHandler: (current) => paymentHeader(current),
    });
  }

  it("pays the variant-audit route and returns the signed report", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(auditResponse(), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    const report = await payingClient().variantAudit(
      "https://agent.example/scan",
    );

    expect(report.report_id).toBe(reportId);
    expect(report.totals.grade).toBe("A");
    expect(report.consent_verified).toBe(true);
    // The paid request goes to /variant-audit, not /scan.
    expect(fetchMock.mock.calls[0]?.[0]).toBe(resourceUrl);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("sends only the options the caller set", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(auditResponse(), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    await payingClient().variantAudit("https://agent.example/scan", {
      threatClasses: ["DRAIN_ADDRESS"],
      maxVariantsPerClass: 4,
      since: reportId,
      depth: "deep",
    });

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      target_url: "https://agent.example/scan",
      threat_classes: ["DRAIN_ADDRESS"],
      max_variants_per_class: 4,
      since: reportId,
      depth: "deep",
    });
  });

  it("omits unset options entirely so the server applies its own defaults", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(auditResponse(), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    await payingClient().variantAudit("https://agent.example/scan");

    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      target_url: "https://agent.example/scan",
    });
  });

  it("refuses to run without a payment handler", async () => {
    await expect(
      new WardenClient().variantAudit("https://agent.example/scan"),
    ).rejects.toThrow(WardenError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["", TypeError],
    [undefined as unknown as string, TypeError],
  ])("rejects a missing target url (%s)", async (targetUrl, expected) => {
    await expect(payingClient().variantAudit(targetUrl)).rejects.toThrow(
      expected,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [{ depth: "unlimited" as never }],
    [{ maxVariantsPerClass: 0 }],
    [{ maxVariantsPerClass: 1.5 }],
    [{ since: "not-a-report-id" }],
    [{ threatClasses: [1] as never }],
  ])(
    "rejects a malformed option before spending anything (%o)",
    async (options) => {
      await expect(
        payingClient().variantAudit("https://agent.example/scan", options),
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["missing counts", { per_class: [{ threat_class: "T", grade: "A", detection_rate: null }] }],
    ["negative counts", { per_class: [classEntry({ detected: -1, missed: 5 })] }],
    ["counts that do not add up", { per_class: [classEntry({ total: 99 })] }],
    ["out-of-range rate", { per_class: [classEntry({ detection_rate: 101 })] }],
    ["empty limitation", { limitations: [""] }],
    ["negative issued_at", { issued_at: -1 }],
  ])("rejects a report with %s", async (_label, changes) => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(auditResponse(changes), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    await expect(
      payingClient().variantAudit("https://agent.example/scan"),
    ).rejects.toThrow(WardenError);
  });

  it.each([[[]], [[""]]])(
    "refuses an empty or blank threatClasses before paying (%j)",
    async (threatClasses) => {
      await expect(
        payingClient().variantAudit("https://agent.example/scan", {
          threatClasses: threatClasses as string[],
        }),
      ).rejects.toThrow(TypeError);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["consent_verified", { consent_verified: false }],
    ["report_id", { report_id: "nope" }],
    ["totals", { totals: { threat_classes: 1 } }],
    ["limitations", { limitations: [] }],
    ["grade", { per_class: [classEntry({ grade: "S" })] }],
  ])("rejects a response with an invalid %s", async (_field, changes) => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(auditResponse(changes), 200, {
          "PAYMENT-RESPONSE": settlementHeader(),
        }),
      );

    await expect(
      payingClient().variantAudit("https://agent.example/scan"),
    ).rejects.toThrow(WardenError);
  });

  it("accepts a class with no conclusive probe and no rate", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(null, {
          status: 402,
          headers: { "PAYMENT-REQUIRED": challenge() },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          auditResponse({
            per_class: [
              classEntry({
                detected: 0,
                conclusive: 0,
                inconclusive: 4,
                detection_rate: null,
                grade: "INCONCLUSIVE",
              }),
            ],
          }),
          200,
          { "PAYMENT-RESPONSE": settlementHeader() },
        ),
      );

    const report = await payingClient().variantAudit(
      "https://agent.example/scan",
    );

    expect(report.per_class[0]?.detection_rate).toBeNull();
    expect(report.per_class[0]?.grade).toBe("INCONCLUSIVE");
  });
});
