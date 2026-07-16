# Codex — START HERE (Warden Trust Layer hand-off)

You are building the **Warden Trust Layer**. This file is the entry point. Read it, then follow the read order.

## Mission (one paragraph)
Warden is repositioned as **"the immune system of the agent economy"** — an open, cryptographically-verifiable
**Agent Protection Attestation (APA)** standard that any agent marketplace can adopt, designed first for
OKX.AI and source-ready but not yet deployed there. The goal is the hackathon **Creative Genius ($10k)** track (novel, category-defining, *watchable*
infrastructure — judges often don't run code) + the post-hackathon **OKX Super Nova grant**. Win by
*out-inventing*, not out-selling. Lead every surface with the metaphor + the demo + the open standard.

## Read order (do this first)
1. **`CODEX-TRUST-LAYER-BUILD.md`** — the authoritative spec. Read in this order inside it:
   - the **"v2 — HARDENING"** block at the top (it SUPERSEDES the base §0–§9 on any conflict),
   - **§0 BUILD STATUS** (what's already built — do NOT rebuild it),
   - **§H CANONICAL CONTRACTS** (the single source of truth for endpoints, record shape, register model),
   - **§1 GUARDRAILS** and **§2 WHAT ALREADY EXISTS**.
2. **`spec/APA-SPEC.md`** — the open standard you implement against (wire format, crypto, endpoints).
3. **`spec/verify_apa.py`** — the reference verifier + **your objective correctness gate**.
4. **`submission/COMPETITIVE-AUDIT.md`** — why this positioning wins (744-agent sweep).

## What's already built & verified — DO NOT REBUILD (P1 + P2)
48 tests green, ruff clean, verified end-to-end against the oracle:
- `sdk/python/**` — the `warden-guard` SDK (client with free `fail_open=True` + `local=True` in-process mode,
  async, middleware, decorator, lifetime + rolling counters, Ed25519 keygen, signed `/.well-known/agent-protection`
  heartbeat, `warden-guard verify` CLI).
- `warden/protection.py`, `warden/protection_store.py`, `warden/apa_url.py` — the Ed25519 issuer, TOFU
  registration, sqlite nonce store + hash-chained transparency log, SSRF-safe probe.
- `warden/api.py` `/apa/*` routes + `/.well-known/apa-issuer.json`; consent folded into the signed audit badge.
- `spec/APA-SPEC.md` + `spec/verify_apa.py`.

## What YOU build — P3 → P5 (in order; each phase green before the next)
- **P3 — the Creative-Genius centerpiece:** an auto-playing **"Attack Theater"** page (`site/theater.html`, see
  BUILD §E): a scripted malicious agent fires real injection→drain→secret-exfil attacks at a Warden-protected
  demo ASP; the viewer *watches* Warden neutralize each live (real BLOCK/SANITIZE feed, running "threats
  neutralized" counter, ms latency). Attack **our own** demo agent only. Plus the immune-system framing and a
  **Safety Map** hero visual (fabric, not node). This is the ≤90s video and the landing centerpiece.
- **P4 — human surfaces on the built server + reconcile tests:** `site/verify.html`+`verify.js` (paste a
  badge/endpoint → verify result, same algorithm as `spec/verify_apa.py`); `site/trust.html` (Trust Layer page:
  link the spec, one-line SDK snippet, `<img>` badge embed, link to the Safety Map); a rendered `GET /apa/log`
  view; `site/integrate.html` update (SDK first); README "Trust Layer" + quickstart. **Also reconcile the 4
  KNOWN failing site tests** (BUILD §0 KNOWN ISSUE) — fix the CSS if WCAG contrast genuinely fails; otherwise
  update the stale test contracts to the intentional redesign. Do not merely weaken tests.
- **P5 (optional/if time):** TypeScript SDK, live systemd-timer safety index.

## Non-negotiables (full detail in BUILD §1)
1. **Never destabilize the live listing `#3808`.** Everything additive; never run `agent update`; never change
   `/scan`,`/audit`,`/api/demo/scan`,`/health`,`/badge/*` behavior.
2. **Honesty is the product.** No claimable trust seal; the badge attests exactly what APA §preamble says.
3. **Design:** all site work uses the Luminous Trust system (`site/styles.css`, self-hosted `site/fonts/`).
4. **Tests + ruff must pass;** no stubs/TODOs; no secret (`0x`+64hex) literals.
5. **DO NOT deploy** (site → `/opt/warden-site`, service → `/opt/warden` via file copy is the reviewer's job).
6. **DO NOT commit `data/apa_issuer.key` or any `*.key`/`*.db`** — already gitignored; the prod issuer key is the
   `WARDEN_ISSUER_KEY` env var.

## How to run / verify locally
```
pip install -e sdk/python          # install the SDK
python -m pytest -q                # full suite (see KNOWN ISSUE: 4 site tests fail pre-P3)
python -m ruff check .             # lint
python spec/verify_apa.py --selftest   # crypto oracle must PASS
```
**Objective gate for anything touching crypto/attestations:** it must round-trip through `spec/verify_apa.py`
(`verify_attestation` accepts a genuine record; tampering `scans_24h`/fields fails).

## Review process
The reviewer (Claude, on the main model) reviews **each phase** against BUILD §8 + §H, re-runs the crypto oracle
independently, checks honesty/SSRF/no-listing-impact, and handles deploy. Ship one phase at a time, report the
file list + full `pytest`/`ruff` output + how you met the objective gate, and flag anything incomplete.
