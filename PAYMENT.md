# x402 Payment Layer

Warden keeps payment enforcement at the HTTP boundary. The scan engine, auditor, and MCP tools stay payment-agnostic so tests and local development can run without wallet state.

## Current Implementation

- Package: `okxweb3-app-x402[fastapi,evm]==0.1.0`.
- Module path: the package provides the `x402` imports used by `warden/api.py`.
- Activation: middleware is installed only when `OKX_API_KEY` is present in the environment.
- Required production env when active: `OKX_API_KEY`, `OKX_SECRET_KEY`, `OKX_PASSPHRASE`, `PAY_TO_ADDRESS`, and optional `OKX_BASE_URL`.
- Security hardening env (optional):
  - `WARDEN_RATE_LIMIT_PER_MIN` (default `60`; set to `0` to disable rate-limiting)
  - `WARDEN_REQUIRE_CONSENT` (`true`/`false`)
  - `WARDEN_BADGE_SECRET` (HMAC secret for signed badge records)
- Local/tests: when `OKX_API_KEY` is absent, `/scan` and `/audit` are free and the 39-test baseline runs without payment mocks.

## Production Terms

Live unpaid probes currently return x402 v2 `exact` challenges:

| Route | Price | Network | Token | Pay to |
|---|---:|---|---|---|
| `POST /scan` | `0.01 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |
| `POST /audit` | `15 USDT` | `eip155:196` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` |

`GET /health` stays free for uptime checks. The static landing page must not call paywalled routes from browser code.

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

The live payment gate is verified. A fully settled paid demo is not complete until the user funds a buyer wallet with USDT and gas on X Layer and explicitly approves a paid replay. Use `demo/run_demo.py --mode local` for the no-funds recording path.
