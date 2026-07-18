export type TestVerdict = "ALLOW" | "SANITIZE" | "BLOCK";

export function scanResponse(
  verdict: TestVerdict = "ALLOW",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    verdict,
    risk_level: verdict === "ALLOW" ? "NONE" : "HIGH",
    threat_classes: verdict === "ALLOW" ? [] : ["PROMPT_INJECTION"],
    detections:
      verdict === "ALLOW"
        ? []
        : [
            {
              class: "PROMPT_INJECTION",
              match: "ignore previous instructions",
              confidence: 0.99,
              source: "pattern",
            },
          ],
    sanitized_payload: verdict === "SANITIZE" ? "clean payload" : "",
    recommendation:
      verdict === "ALLOW" ? "Payload is safe." : "Review the payload.",
    checks: { injection: verdict === "ALLOW" ? "pass" : "fail" },
    latency_ms: 1.25,
    ...overrides,
  };
}

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: HeadersInit = {},
): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json");
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  });
}
