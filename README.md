<div align="center">
  <img src="site/assets/warden-avatar.png" alt="Warden shield mark" width="96" height="96">
  <h1>Warden</h1>
  <p><strong>The immune system of the agent economy.</strong></p>
  <p>
    Warden enforces deterministic <code>ALLOW</code>, <code>SANITIZE</code>, or <code>BLOCK</code>
    decisions before an autonomous agent acts, then publishes an open cryptographic attestation of
    the guard state it can actually prove.
  </p>
  <p>
    <a href="https://warden.gudman.xyz"><img alt="Live API" src="https://img.shields.io/badge/live_API-warden.gudman.xyz-6a57eb"></a>
    <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-2f4058">
    <img alt="APA" src="https://img.shields.io/badge/APA-v0.1-10b981">
    <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-625e78">
  </p>
  <p>
    <a href="#trust-layer">Trust Layer</a> ·
    <a href="#quickstart">Quickstart</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#routes">Routes</a> ·
    <a href="#honest-limits">Honest limits</a>
  </p>
</div>

The current interface capture is intentionally absent: the PNGs in
[`docs/screenshots/`](docs/screenshots/README.md) predate the Trust Layer. A new screenshot is accepted
only after the exact build receives browser and device review.

## Why Warden exists

Agent services consume instructions from users, tools, websites, and other agents. A poisoned response
can replace a payment recipient, override policy, hijack a tool call, or request secret material. The
danger is not the text alone; it is the autonomous action that follows.

Warden inserts a deterministic boundary before that action. Its open Agent Protection Attestation (APA)
format makes the endpoint's live guard state and signed rolling 24-hour count—or an explicit unavailable state—independently verifiable
without turning that evidence into a permanent safety seal.

## Trust Layer

| Pillar                           | What it does                                                                                                                       | What it does not claim                                                        |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| **Local enforcement**            | Runs `WardenEngine` in the caller's process and returns safe text or raises on `BLOCK`.                                            | No claim that deterministic detectors understand every possible attack.       |
| **Agent Protection Attestation** | Binds an endpoint host to an Ed25519 key, `guard-live` state, and a signed rolling 24-hour count or an explicit unavailable state. | A valid attestation does not prove every request traversed the guard.         |
| **Safety Map**                   | Separates discovered marketplace listings, public-text matches, and completed audits in a dated public fabric.                     | A listing-text match is not evidence that an endpoint is compromised or safe. |

The wire format, canonical JSON, signatures, freshness, nonce, status, and transparency-log rules are in
[`spec/APA-SPEC.md`](spec/APA-SPEC.md). The portable reference verifier is
[`spec/verify_apa.py`](spec/verify_apa.py).

The Safety Index uses a schema-v2 capture contract: `sampled` is the number of unique validated agent IDs
stored, `expected` is the highest result total reported for that discovery query, and `dropped` is
`max(expected - sampled, 0)`. The committed seed and live refresh default to query `a`. Equality means the
discovery response is complete for that query, not that every marketplace listing was discovered; every
mismatch is rendered as partial/degraded without assigning a cause.

[`scripts/refresh_safety_index.py`](scripts/refresh_safety_index.py) stages and validates each capture before
atomically switching the public `current` release. The accompanying systemd service and persistent six-hour
timer are source-ready but are not deployed or claimed active.

## See it in action

[Attack Theater](site/theater.html) sends prompt injection, a drain-address swap, and secret exfiltration
through the Warden-owned demo-agent gate in one auto-playing pass. It counts a neutralization only after the
API response proves the expected verdict, threat class, and downstream delivery state; errors stop visibly.
The additive `POST /api/demo/theater` route leaves `/api/demo/scan` unchanged: BLOCK never invokes the
no-side-effect demo ASP handler, SANITIZE delivers only the sanitized payload, and ALLOW delivers the original.

The Theater and APA web surfaces are implemented in this repository but are not claimed live until an
explicitly approved deployment. The existing [browser playground](https://warden.gudman.xyz/playground)
remains the current no-payment scan surface. The recording contract is
[`docs/HACKATHON_DEMO.md`](docs/HACKATHON_DEMO.md).

## Quickstart

### Install from source

The unrelated `warden-guard` package on PyPI is not this project. Warden's publish-ready SDK uses
the available distribution name `warden-agent-guard`, but is not claimed published until the
user completes that release. Install the Python service and SDK from this repository:

```bash
git clone https://github.com/Ridwannurudeen/warden.git
cd warden
python -m pip install -e . -e sdk/python
```

### Build the TypeScript client from source

The owned-scope `@gudman/warden-guard` package under `sdk/ts` is not claimed as published to npm.
Build and test the locked
source checkout directly. The zero-dependency built runtime declares Node 18+, while the locked Vite/Vitest
development toolchain requires Node 20.19+ for `npm test` and `npm run build`:

```bash
cd sdk/ts
npm ci
npm test
npm run build
```

The TypeScript client has no local scanner engine. `new WardenClient()` calls the free hosted endpoint and
defaults to `failOpen: true`, so network, timeout, and HTTP failures produce best-effort `ALLOW` telemetry.
Set `failOpen: false` to make those hosted failures throw; this still does not move detection in-process.

### Enforce locally

```python
from warden_guard import WardenClient

safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)
act_on(safe)
```

Local mode has no hosted quota or network dependency. `guard()` returns the original payload for
`ALLOW`, the sanitized payload for `SANITIZE`, and raises `WardenBlocked` for `BLOCK`.

### Run the full local surface

```bash
python scripts/build_site.py
python scripts/build_index.py
python -m pytest -q
python -m uvicorn scripts.preview_site:app --host 127.0.0.1 --port 8031
```

Open `http://127.0.0.1:8031/theater`. The preview serves the full site and local API on one origin with
the same clean route boundaries and applicable security headers as production.

### Hosted free client

```python
from warden_guard import WardenClient

result = WardenClient().scan(untrusted_text)
```

`WardenClient()` uses `https://warden.gudman.xyz/api/demo/scan` and defaults to `fail_open=True`.
That path is best-effort telemetry, not enforcement: the current default is 20 requests per minute per
IP, forced `fast` depth, and truncation at 4,000 characters. Hosted latency includes network round-trip
time. Use local mode with `fail_open=False` for an enforcement boundary.

## Architecture

```text
Untrusted payload
      |
      v
WardenClient(local=True, fail_open=False)
      |
      +--> deterministic scanner + analyzer registry
      |          |
      |          +--> ALLOW ------> original payload
      |          +--> SANITIZE ---> redacted payload
      |          `--> BLOCK ------> WardenBlocked; action stops
      |
      `--> atomic lifetime + rolling 24-hour counters
                  |
                  v
       signed Protection Proof at the guarded endpoint
                  |
             issuer probe + TOFU host/key binding
                  |
                  v
       Ed25519 APA record --> SVG status badge
                  |         offline verifier
                  `-------> hash-chained public log
```

- **Runtime:** Python 3.11+, FastAPI 0.137.1, Pydantic 2.13.4, httpx 0.28.1, and FastMCP 3.4.2.
- **Decision path:** deterministic scanner categories plus drain-address, tool-hijack, exfiltration, and
  malicious-link analyzers. The free, local, and fast paths are always deterministic. A separately
  configured model can inspect otherwise-undetected paid `thorough` requests after those layers.
- **Proof path:** an endpoint self-signs `/.well-known/agent-protection`; the issuer verifies freshness,
  nonce uniqueness, and Ed25519 ownership before TOFU-binding `endpoint_host` to the key.
- **Transparency:** issuance and status changes append to a SHA-256 hash chain at `/apa/log`.
- **Commerce:** production `/scan` and `/audit` remain additive x402 v2 `exact` services on X Layer.
- **Clients:** the Python SDK supports in-process enforcement; the source-built TypeScript SDK is a typed
  hosted fetch client with Express-style middleware and no local engine.
- **Frontend:** dependency-free HTML, CSS, and JavaScript with self-hosted fonts and a self-only CSP.

### Optional paid semantic layer

The semantic layer is disabled unless all of `WARDEN_SEMANTIC_ENABLED=true`,
`WARDEN_SEMANTIC_ENDPOINT`, `WARDEN_SEMANTIC_MODEL`, `WARDEN_SEMANTIC_API_KEY`, and the paid-runtime
`OKX_API_KEY` are present. The endpoint must be HTTPS and accept a chat-style model-inference request.
Warden applies a two-second timeout, caps the response at 16 KiB, validates the model's JSON, and falls
back to the deterministic verdict on every transport, timeout, or schema failure. Only paid `/scan`
requests with `depth=thorough` can opt in; deterministic findings short-circuit the model call.

Before enabling it, run `python scripts/benchmark_recall.py --semantic --json` in the configured runtime.
The result includes `semantic_enablement_gate.passed`; keep the feature disabled unless recall beats the
committed deterministic baseline and the held-out benign set remains at zero false positives. No semantic
runtime is enabled by repository configuration.

### APA and legacy audit badges

| Contract               | Signature                                          | Evidence                                                                                                                       | Verification                                                                              |
| ---------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| **APA attestation**    | Ed25519 issuer signature with a published key      | Fresh endpoint-key control, `guard-live` state, signed rolling 24-hour count or explicit unavailable state, and current status | Portable offline verification plus optional live proof refresh                            |
| **Legacy audit badge** | HMAC-SHA256 with server-held `WARDEN_BADGE_SECRET` | Point-in-time, consented endpoint-audit score and battery result                                                               | Server verification through `/badge/{audit_id}` or `/api/badges`; not public-key portable |

The legacy routes stay available for compatibility. They are not APA records and must not be presented as
offline-verifiable attestations.

Issuer rotation keeps only the current signing seed. Set `WARDEN_ISSUER_KID` for that key and, after a
rotation, point `WARDEN_ISSUER_HISTORY` at a public-only JSON file shaped as
`{"keys":[{"kid":"retired-...","pub":"ed25519:...","not_after":<last_verified_at>}]}`. The issuer
publishes the current key first with `not_after = 9007199254740991`; every retired cutoff is finite and keys
remain newest-first. Malformed or duplicate history fails closed. Verifiers select keys using the
Attestation's signed `verified_at`, so an unexpired pre-rotation record remains portable without storing an old
private key. Every record has the exact lifetime `expires_at = verified_at + 3600`: this bounds retired-key
backdating to at most a one-hour post-retirement grace, but cannot distinguish a forged backdated record during
that grace. New and refreshed records are always signed by the current key.

## Routes

These routes are implemented in source. Re-check the live host after an approved deployment before making
an availability claim.

| Method | Path                                          | Purpose                                                         |
| ------ | --------------------------------------------- | --------------------------------------------------------------- |
| `GET`  | `/theater`                                    | Auto-playing, real-response Attack Theater                      |
| `GET`  | `/trust`                                      | Trust Layer pillars and honest APA embed template               |
| `GET`  | `/verify`                                     | Browser APA attestation verifier                                |
| `GET`  | `/spec/APA-SPEC.md`                           | Byte-identical public APA specification                         |
| `GET`  | `/health`                                     | Version, corpus size, and analyzer list                         |
| `GET`  | `/health/ready`                               | Local scanner and paid-route configuration readiness            |
| `POST` | `/api/demo/scan`                              | Free, rate-limited, fast-only payload scan                      |
| `POST` | `/api/demo/theater`                           | Verdict-gated, no-side-effect demo ASP with delivery receipt    |
| `POST` | `/scan`                                       | Production x402 payload scan                                    |
| `POST` | `/audit`                                      | Production x402 endpoint audit                                  |
| `GET`  | `/.well-known/apa-issuer.json`                | Current and recent issuer Ed25519 verification keys             |
| `POST` | `/apa/register`                               | Probe `{endpoint}`, TOFU-bind its key, and issue an attestation |
| `GET`  | `/apa/attestation/{attestation_id}`           | Attestation JSON and effective status                           |
| `GET`  | `/apa/attestation/{attestation_id}/badge.svg` | No-store SVG rendering the true current status                  |
| `GET`  | `/apa/log`                                    | HTML for browsers; hash-chained JSON entries for API clients    |
| `POST` | `/apa/revoke`                                 | Key-signed attestation revocation                               |
| `GET`  | `/badge/{audit_id}`                           | Legacy HMAC audit badge record                                  |
| `GET`  | `/api/badges`                                 | Legacy public audit-badge registry                              |

## Project layout

```text
warden/                 # FastAPI service, verdict engine, APA issuer, and stores
sdk/python/             # Source-installed sync/async SDK, middleware, decorator, proof, CLI
sdk/ts/                 # Source-built hosted TypeScript client and Express-style middleware
spec/                   # APA v0.1 wire spec and portable reference verifier
site/                   # Static product UI and generated public spec/docs
tests/                  # API, crypto, corpus, site, and integration contracts
corpus/                 # 92 attack cases and 30 benign false-positive guards
scripts/                # Deterministic builders and local preview entry point
docs/                   # Demo, release, deployment, and screenshot review handoffs
deploy/                 # Nginx, systemd, and operator-run deployment material
```

## Honest limits

- APA proves endpoint-key control, a live conforming guard proof, and either an endpoint-signed exact rolling
  count or a signed `null` while a migrated lifetime-only counter completes its 24-hour warmup.
  It does not prove every request is routed through the guard or independently audit the endpoint owner's
  local counter state.
- The free hosted SDK path is best-effort telemetry because `fail_open=True`, rate limiting, forced fast
  depth, truncation, and network failure can prevent enforcement.
- Local deterministic analysis is intentionally conservative and cannot claim semantic coverage beyond
  the implemented scanner categories, analyzers, and corpus.
- The committed deterministic held-out baseline is 92.55% recall (87/94) at 0.00% false positives (0/45),
  after the Decoder Wall normalization pre-pass added coverage for nested-encoding and homoglyph evasions.
  The optional paid semantic path has an older separately recorded result of 71.43% recall (20/28) with
  0.00% false positives (0/16), measured on the original 28-case set before the pre-pass and the expanded
  evasion family, so it is not directly comparable. Repository configuration still leaves the runtime
  disabled. Its fail-open behavior preserves the deterministic verdict when inference is unavailable, and
  reproducing the recorded result requires an explicitly configured model.
- The endpoint auditor assumes the target accepts `POST` JSON with a `payload` field. It rejects internal
  network targets, redirects, oversized responses, and slow endpoints.
- Marketplace evidence reports dated schema-v2 `sampled`, `expected`, and `dropped` coverage. Re-check
  listing state, service IDs, prices, and counts before an external claim.
- The atomic six-hour Safety Index refresh and systemd units are source-ready, not deployed or claimed live.
- The TypeScript SDK has no local engine; its default free hosted path is best-effort because
  `failOpen: true` converts transport failures into `ALLOW` telemetry.
- Trust Layer web routes are source-ready but require explicit deployment approval before they are live.
- The 99.5% application-readiness objective is not a contractual SLA or an achieved uptime claim. The
  committed monitor state is `not_running`; a complete independently scheduled 30-day window is required
  before the status surface reports measured availability, and payment-facilitator uptime is out of scope.
- Issuer-key rotation is source-ready but operator-managed: preserve each retired public key with its exact
  last `verified_at` cutoff in `WARDEN_ISSUER_HISTORY`. The one-hour lifetime bounds but does not eliminate
  retired-key backdating during the post-cutoff grace. No live rotation is claimed in this repository state.

## Roadmap

- [ ] Deploy the reviewed Trust Layer build after explicit user approval.
- [ ] Capture and review the real <=90-second Theater video and current retina screenshots.

## Contributing

- Add a failing regression test before changing verdict, APA, or site contracts.
- Keep deterministic verdict paths free of LLM and outbound-network calls.
- Preserve `/scan`, `/audit`, `/api/demo/scan`, `/health`, and legacy badge behavior.
- Regenerate `site/docs/` and `site/spec/APA-SPEC.md` with `python scripts/build_site.py`.
- Run the Python suite, JavaScript suite, Ruff, and `git diff --check` before review.

## Development checks

```bash
python -m pytest -q                         # full Python and static-site contract suite
node --test tests/js/*.test.js              # frontend state and interaction contracts
python -m ruff check .                       # Python lint gate
python scripts/build_site.py                 # regenerate reason docs and public APA spec
python scripts/build_index.py                # rebuild from the committed marketplace snapshot
python -m pytest -q tests/test_refresh_safety_index.py tests/test_deploy_index.py
python spec/verify_apa.py --selftest          # portable crypto oracle
(cd sdk/ts && npm ci && npm test && npm run build)  # source TypeScript SDK gates
```

## License and contact

Apache-2.0 — see [`LICENSE`](LICENSE). Live service: [warden.gudman.xyz](https://warden.gudman.xyz) ·
OKX.AI agent `#3808`.
