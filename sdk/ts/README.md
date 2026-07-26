# @gudman/warden-guard

Fetch-based Warden payload scanning for TypeScript and JavaScript, with an Express-style middleware that has no Express runtime dependency.

The default free endpoint is rate-limited, best-effort telemetry. `failOpen` therefore defaults to `true`: network, timeout, and HTTP failures return an `ALLOW` result whose `raw.error` explains the failure. Set `failOpen: false` when a Warden outage must stop processing.

`latencyMs` is reported by the hosted scanner. End-to-end call latency also includes network round-trip time.

## Install

```bash
npm install @gudman/warden-guard
```

The emitted runtime is zero-dependency and supports Node 18+.

### Build from source

Building and testing this checkout requires Node 20.19+ because the locked Vite/Vitest
development toolchain has a higher engine floor.

```bash
cd sdk/ts
npm ci
npm test
npm run build
```

## Client

```ts
import { WardenClient, WardenBlocked } from "@gudman/warden-guard";

const warden = new WardenClient();
const result = await warden.scan(userPayload, {
  expectedAddresses: ["0x1234..."],
});

if (result.blocked) {
  console.error(result.threatClasses);
}

try {
  const safePayload = await warden.guard(userPayload);
  await runAgent(safePayload);
} catch (error) {
  if (error instanceof WardenBlocked) {
    console.error(error.result.raw);
  }
}
```

`scan()` uses the fast-only `https://warden.gudman.xyz/api/demo/scan` route. Set `baseUrl` for another Warden host. The default timeout is 8 seconds.

The default client does not construct or settle x402 payments. An explicit
caller-owned `paymentHandler` is the only way to select the paid `/scan` flow; there
is no boolean switch that can silently authorize spending.

`guard()` returns the original payload for `ALLOW`, returns the scanner's sanitized text for `SANITIZE`, and throws `WardenBlocked` for `BLOCK`.

## Opt-in x402 pay and replay

The SDK never receives a wallet key and never signs autonomously. Inject an encoded
`PAYMENT-SIGNATURE` only after an external wallet has created it for the challenge:

```ts
import { WardenClient, type X402PaymentHandler } from "@gudman/warden-guard";

const paymentSignature = process.env.PAYMENT_SIGNATURE;
if (!paymentSignature) throw new Error("PAYMENT_SIGNATURE is required");

const paymentHandler: X402PaymentHandler = (challenge) => {
  // The external wallet created paymentSignature for this exact challenge.
  // The SDK validates the binding before transmitting it.
  void challenge;
  return paymentSignature;
};

const warden = new WardenClient({
  failOpen: false,
  paymentHandler,
});
const result = await warden.scan(untrustedText, { depth: "thorough" });
```

The handler receives a frozen `X402Challenge` only after the SDK validates Warden's
exact x402 v2 route, recipient, X Layer network, USDT asset, `100000` atomic amount,
300-second timeout, and `USD₮0`/`1` EIP-712 domain. A handler may return a string or
`Promise<string>`.

The SDK binds the returned base64 x402 v2 EIP-3009 header to those terms, serializes
the body once, reuses the exact endpoint and body, sets Fetch `redirect: "error"`,
and sends `PAYMENT-SIGNATURE` on exactly one replay. It requires at least six seconds
remaining for replay and rejects authorizations beyond the current 300-second
challenge window, allowing only five seconds of clock skew. It rejects callback
failure, malformed headers, challenge drift, a second 402, redirects, non-200 replay
responses, malformed scan results, and missing, false, or wrong-network
`PAYMENT-RESPONSE` receipts. These failures never use `failOpen`.

Without `paymentHandler`, the existing free `/api/demo/scan` behavior is unchanged.
The free path remains fast-only; `depth: "thorough"` is available only to the
injected paid flow.
The SDK does not generate a wallet, store a private key, create a signature, or make
a live payment without explicit caller injection.

## Explicit feedback

`scan()` and `guard()` never submit feedback. After a person has removed
secrets and identifying details from a reproducer, use the separate opt-in
method:

```ts
const receipt = await warden.submitFeedback({
  outcome: "missed_attack",
  observedVerdict: "ALLOW",
  threatClass: "PROMPT_INJECTION",
  redactedReproducer: "Human-reviewed reproducer with secrets removed.",
  consentToRetain: true,
  redactionConfirmed: true,
});
```

`FeedbackSubmission` is a discriminated union: `missed_attack` accepts only
an observed `ALLOW`, while `false_positive` and `correct_detection` accept
only `SANITIZE` or `BLOCK`. Runtime checks enforce the same relationship,
the backend enums, valid Unicode scalar text, and the 4,000-character limit.

Both consent fields have the literal TypeScript type `true` and are checked
again at runtime. Feedback transport, HTTP, and response-validation failures
always throw `WardenError`, even when scan telemetry uses `failOpen: true`.
The response contains only the feedback ID, queue status, and retention
deadline.

## Express-style middleware

```ts
import express from "express";
import { WardenClient, wardenGuard } from "@gudman/warden-guard";

const app = express();
app.use(express.json());
app.use(
  wardenGuard({
    client: new WardenClient({ failOpen: false }),
  }),
);
```

The middleware skips `GET`, `HEAD`, and `OPTIONS`. By default it scans a string request body or `request.body.payload`. A `BLOCK` returns HTTP 400 JSON, `ALLOW` passes the body through, and `SANITIZE` replaces the string body or `request.body.payload` before calling `next()`. A custom extractor cannot identify where its text belongs in the original body, so `SANITIZE` blocks; use `guard()` directly and forward its returned safe text for custom body shapes.

Custom extraction and block detail are supported without importing Express types:

```ts
app.use(
  wardenGuard({
    extract: (request) =>
      typeof request.body === "object" &&
      request.body !== null &&
      "message" in request.body &&
      typeof request.body.message === "string"
        ? request.body.message
        : null,
    onBlock: (result) => ({ threats: result.threatClasses }),
  }),
);
```
