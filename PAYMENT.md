# x402 Payment Layer

Warden keeps payment enforcement at the HTTP boundary. The scan engine, auditor, and MCP tools stay payment-agnostic so tests and local development can run without wallet state.

## Current Implementation

- Package: `okxweb3-app-x402[fastapi,evm]==0.1.0`.
- Module path: the package provides the `x402` imports used by `warden/api.py`.
- Activation: middleware is installed only when `OKX_API_KEY` is present in the environment.
- Required production env: `WARDEN_REQUIRE_PAYWALL=1`, `OKX_API_KEY`,
  `OKX_SECRET_KEY`, `OKX_PASSPHRASE`, and `PAY_TO_ADDRESS`.
- Facilitator origin: the installed package's trusted default,
  `https://web3.okx.com`. `OKX_BASE_URL` may be omitted or set to that exact
  value; plaintext, paths, credentials, ports, and alternate facilitator
  origins are rejected. Signed facilitator requests do not follow redirects.
- Rail contract: x402 v2 `exact`, OKX facilitator, X Layer mainnet
  (`eip155:196`), X Layer USDT
  (`0x779ded0c9e1022225f8e0630b35a9b54be713736`, 6 decimals), and
  `100000` atomic units (`0.1 USDT`). `warden/payment.py` passes the
  atomic amount and asset explicitly; it does not rely on dollar-price or
  default-token inference.
- EIP-712 domain: the token's signed authorization metadata is pinned to
  `{"name":"USD₮0","version":"1"}`. `USDT` remains the user-facing market
  symbol; it is not the token contract's EIP-712 domain name. The installed
  x402 package's `USDT` default is therefore overridden explicitly.
- Unsupported `WARDEN_PAYMENT_*` overrides fail at startup instead of silently
  switching scheme, facilitator, network, asset, amount, symbol, or decimals.
  Coinbase, Base, Solana, AP2, metered, and `upto` rails are not implemented.
- `WARDEN_REQUIRE_PAYWALL` accepts only documented boolean values. Production
  sets `WARDEN_REQUIRE_PAYWALL=1` in the systemd unit so missing payment
  credentials or a misspelled boolean stops startup rather than exposing paid
  routes for free.
- Security configuration:
  - `WARDEN_RATE_LIMIT_PER_MIN` (default `60`; set to `0` to disable rate-limiting)
  - `WARDEN_RATE_LIMIT_DB` (production: `/opt/warden/data/rate-limit.db`; shared
    fixed-window counters and verified-payer grants fail closed if unavailable)
  - `WARDEN_DEMO_RATE_LIMIT_PER_MIN` (default `20`; independent limit for `/api/demo/*`)
  - `WARDEN_REQUIRE_CONSENT` (`true`/`false`)
  - `WARDEN_BADGE_SECRET` (required in production; the public development default is forgeable)
- Local/tests: when `OKX_API_KEY` is absent, `/scan` and `/audit` are free and the test suite runs without payment mocks.

## Corrected source terms

The tested source contract on this branch is:

| Route | Price | Network | Token | Pay to |
|---|---:|---|---|---|
| `POST /scan` | `0.1 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |
| `POST /audit` | `0.1 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |
| `POST /harden` | `0.1 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |
| `POST /variant-audit` | `0.1 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |

Each route has a `GET` twin on the same terms, for OKX's auto-replay. One
`build_payment_option` call feeds all four, so there is exactly one price on the
rail; a new route can never introduce a second price point.

Deployed and reprobed on 2026-07-25. The earlier note here said these corrections
were undeployed and that the live `/scan` challenge still published the stale
`{"name":"USDT","version":"1"}` domain, observed on 2026-07-18. That is no longer
the case. All four routes now answer `402` with amount `100000` and the pinned
`{"name":"USD₮0","version":"1"}` domain, and OKX's own `agent x402-check` reports
`valid: true`, `amountHuman: 0.1`, `amountMinimal: "100000"`, `decimals: 6` for
each. The OKX listing advertises `0.1` on all four services as of the same date,
so the advertised price and the challenge agree.

`GET /health` and `/api/demo/*` stay free. The playground uses only those routes. The `/hire` page makes an unpaid `GET` request to `/scan` or `/audit` to read the current 402 terms, then guides an agent operator through the paid, reviewable task flow; browser code does not sign or submit the paid service call.

## Verification

Read-only checks:

```bash
python -m pytest -q
python -m ruff check .
python - <<'PY'
import importlib.metadata as metadata
print(metadata.version("okxweb3-app-x402"))
PY
```

Use Python `subprocess` on Windows when passing JSON to `onchainos`; PowerShell can strip JSON quoting:

```python
import subprocess

subprocess.run(
    [
        "onchainos",
        "agent",
        "x402-check",
        "--endpoint",
        "https://warden.gudman.xyz/scan",
        "--body",
        '{"payload":"hi"}',
    ],
    check=True,
)
```

## Demo Boundary

The corrected source payment gate is covered by local contract tests; live
verification remains pending deployment and reprobe. The browser playground
uses the free, fast-only `/api/demo/scan` route, while production `/scan` and
`/audit` remain paid. A fully settled paid demo is not complete until the user
funds a buyer wallet with USDT and gas on X Layer and explicitly approves a
paid replay. Use `demo/run_demo.py --mode local` for the no-funds recording
path.
