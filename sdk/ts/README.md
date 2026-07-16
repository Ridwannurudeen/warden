# @warden/guard

Fetch-based Warden payload scanning for TypeScript and JavaScript, with an Express-style middleware that has no Express runtime dependency.

The default free endpoint is rate-limited, best-effort telemetry. `failOpen` therefore defaults to `true`: network, timeout, and HTTP failures return an `ALLOW` result whose `raw.error` explains the failure. Set `failOpen: false` when a Warden outage must stop processing.

`latencyMs` is reported by the hosted scanner. End-to-end call latency also includes network round-trip time.

## Build from source

The emitted zero-dependency runtime supports Node 18+. Building and testing this checkout requires Node
20.19+ because the locked Vite/Vitest development toolchain has a higher engine floor.

```bash
cd sdk/ts
npm ci
npm test
npm run build
```

Install the built source package from a checkout:

```bash
npm install /path/to/warden/sdk/ts
```

## Client

```ts
import { WardenClient, WardenBlocked } from "@warden/guard";

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

This package does not construct or settle x402 payments. Use a separate payment-aware integration when calling the paid `/scan` route; a boolean client option cannot authorize a payment.

`guard()` returns the original payload for `ALLOW`, returns the scanner's sanitized text for `SANITIZE`, and throws `WardenBlocked` for `BLOCK`.

## Express-style middleware

```ts
import express from "express";
import { WardenClient, wardenGuard } from "@warden/guard";

const app = express();
app.use(express.json());
app.use(
  wardenGuard({
    client: new WardenClient({ failOpen: false }),
  }),
);
```

The middleware skips `GET`, `HEAD`, and `OPTIONS`. By default it scans a string request body or `request.body.payload`. A `BLOCK` returns HTTP 400 JSON; `ALLOW` and `SANITIZE` call `next()` without rewriting the request body. Use `guard()` directly when downstream code must receive sanitized text.

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
