> **HISTORICAL / SUPERSEDED IMPLEMENTATION BRIEF**
>
> This file is retained as project history, not current product truth. Consult `ROADMAP.md`, the
> completion addendum in `SECURITY-AUDIT-2026-07.md`, and `REDESIGN_REPORT.md`. Do not execute or
> deploy from this brief without fresh verification and explicit user approval.

# Codex Build Spec — Warden Trust Layer

**Author:** planning/review owner (Claude). **Builder:** Codex. **Reviewer:** Claude (against this spec).
**Repo:** `warden` (this repo). **Live service:** https://warden.gudman.xyz · Agent `#3808` on OKX.AI (X Layer).

---

## v2 — HARDENING (READ FIRST; supersedes any conflicting text below)

A 3-agent audit (standards prior-art + brutal red-team + Creative-Genius research) — with every red-team code
citation verified against the real source — reshaped this plan. **Where v2 conflicts with §0–§9, v2 wins.**
The §2 "what already exists" contracts remain valid. Net: same crypto core, but honest claims, protocol-shaped,
and led by a demo. Build v2's phasing (bottom of this block).

### 0. BUILD STATUS — P1 + P2 already built & independently verified; **Codex STARTS AT P3**
Phases **P1 (honesty + protocol core)** and **P2 (Python SDK)** are DONE and verified against the crypto oracle
(`spec/verify_apa.py`). **Do NOT rebuild them.** What already exists in the tree (48 tests green, ruff clean):
- `sdk/python/**` — full `warden-guard` SDK: client (free default `fail_open=True` + `local=True` in-process
  mode + `paid=True`), async, ASGI middleware, `@guard` decorator, lifetime + rolling **scan counters**,
  Ed25519 keygen, signed `/.well-known/agent-protection` heartbeat, `warden-guard verify` CLI. 36 tests.
- `warden/apa_url.py` (standalone SSRF validator), `warden/protection.py` (Ed25519 issuer: `probe_guard`,
  `issue_attestation`, `verify_attestation_record`, `render_badge_svg`, revoke, `issuer_public_key`),
  `warden/protection_store.py` (sqlite: TOFU host→pub with `key_changed`, nonce-replay, hash-chained
  transparency log). 12 tests.
- `warden/api.py` additive routes: `/.well-known/apa-issuer.json`, `POST /apa/register`, `GET
  /apa/attestation/{id}`, `.../badge.svg` (no-store), `GET /apa/log`, `POST /apa/revoke`. `consent_verified`
  folded into the signed audit badge (`warden/auditor.py`+`warden/badges.py`). `warden/models.py` request
  models. `pyproject.toml` adds `cryptography`.
- `spec/APA-SPEC.md` (the open standard) + `spec/verify_apa.py` (portable verifier; selftest passes).
- **Verified end-to-end (by the reviewer, against the oracle):** SDK heartbeat → server verifies it → issues an
  attestation → the reference verifier accepts it offline; **forging the scan count fails at every layer.**

**Codex builds P3 → P5** (per §G), on top of the above:
- **P3 (the Creative-Genius win):** the auto-playing **"Attack Theater"** demo (`site/theater.html`, §E) + the
  immune-system framing + the **Safety Map** hero.
- **P4 — human surfaces on the built server:** `site/verify.html`+`verify.js` (paste a badge/endpoint → verify
  result, using the same algorithm as `spec/verify_apa.py`), `site/trust.html` (Trust Layer page: spec link +
  one-line SDK snippet + `<img>` badge embed + link to the safety map), a rendered `GET /apa/log` view,
  `site/integrate.html` update (SDK first, then x402/MCP), README "Trust Layer" + quickstart. All must use the
  Luminous Trust design system (`site/styles.css`, self-hosted fonts).
- **P5 (optional):** TS SDK, live systemd-timer safety index.

**KNOWN ISSUE — reconcile in P4 (pre-existing; NOT from P1/P2):** 4 site-contract tests fail (`test_preview`,
`test_site` ×2, `test_site_javascript`) because this session's site redesign changed what they assert (the hero
widget replaced the static `DRAIN_ADDRESS` surface; the light-first theme removed the `:root[data-theme="light"]`
selector they grep; trimmed sections). Reconcile the tests to the *intentional* redesign — but **first verify the
current palette genuinely meets the WCAG contrast the test encodes**; fix the CSS if it doesn't, do not merely
weaken the test.

### A. Reframe (supersedes §0 framing)
- **"Warden — the immune system of the agent economy."** SDK = inoculation/antibodies; badge = vaccination
  certificate; safety index = live health map. Use immune-system / fabric / standard / attestation vocabulary;
  **avoid "scanner / scan / detect"** (reads as commodity). Make OKX the hero: *"Warden makes OKX.AI the first
  agent marketplace where every service can prove it's protected."*
- **Win path = Creative Genius via metaphor + a watchable demo + an open standard** (judges often don't run
  code). Best Product + Software Utility remain secondary/floor.

### B. CRITICAL honesty fixes (verified against code — non-negotiable)
1. **The badge must not overclaim (verified C1).** The Ed25519 heartbeat proves the guard is *served*, not that
   traffic is *routed through Warden*. So: (a) **rename the "guarded" tier to "Warden Guard Live" / "Warden-
   Integrated"** — never bare "Protected"; (b) the heartbeat MUST additionally attest a **signed rolling scan
   counter** `{scans_served, window_start}` signed by the ASP key, so the badge can honestly display *"N payloads
   screened in the last 24h"*. The endpoint signature prevents third-party alteration; it does not independently
   audit an endpoint owner's local state. The honest caveat goes **on the SVG and badge JSON**, not just the
   verify page.
2. **Key the badge to the VERIFIED ENDPOINT HOST only (verified C2).** `POST /protect/register` currently trusts
   an unverified `agent_id` → brand impersonation (register as CertiK #1965). Drop `agent_id` from the trust
   surface; the badge attests the **endpoint host that served a valid signature**, nothing else. If an agent_id
   is shown at all, label it "self-claimed, unverified."
3. **Consent must be in the signed audit badge (verified H2).** `auditor.audit()` calls `issue_badge()` and
   `consent_verified` is NOT in the signed payload (`badges.py` has no consent field). Add `consent_verified`
   into the signed badge; **refuse to issue (or mark `unconsented`)** when false. Do not call the current path
   "already honest."
4. **SDK "one-line protect" must be honest on adoption (verified C3).** Free path `/api/demo/scan` is **20/min
   per IP** and **truncates payloads at 4000 chars** (`api.py:48`, `models.py:10,52`); the SDK draft defaults
   `fail_open=False` → a 429 raises and takes the adopter's service down; payloads >4k scan blind. Therefore:
   - **Free tier default = `fail_open=True`** (best-effort) AND document loudly *"free = best-effort telemetry,
     not enforcement."* Enforcement requires either a **free API key with a real per-key quota** or the paid x402
     tier. Never market "protect any agent in one line" on the fail-closed demo endpoint.
   - **Add a local in-process mode** `WardenClient(local=True)` that imports `WardenEngine` and runs the verdict
     **in the caller's process** — this is the *only* path that is honestly sub-millisecond and not rate-limited;
     it's also what serious adopters want. This single addition fixes C3 + M3 at once.
   - Latency claims: *"sub-ms deterministic verdict **compute**; the hosted SDK adds network RTT."* Never claim
     end-to-end sub-ms for the hosted path.

### C. Make it a PROTOCOL, not a product (this is the "others copy it" + grant win)
1. **Ed25519-signed badge + published issuer key.** Sign badge records with a Warden **Ed25519 issuer key**
   (keep the internal HMAC if needed, but ADD a detached Ed25519 signature + published pubkey). Publish the
   pubkey at `/.well-known/warden-issuer.json` (did:web-aligned). Effect: **anyone verifies a badge offline
   without calling Warden.** This converts badge from product → protocol; without it nothing else is credibly a
   standard.
2. **Publish `spec/APA-SPEC.md`** (Agent Protection Attestation v0.1, Apache-2.0/CC-BY) — implementable by a
   non-Warden verifier: heartbeat document, canonicalization, Ed25519 signature, TTL/nonce rules, badge record,
   status semantics, verify algorithm. Generic discovery path **`/.well-known/agent-protection`** (alias
   `warden-protected`), with `spec_version` + a `protector`/`issuer` field so another firewall vendor can serve
   the same document. One sentence: *"any registry implementing this spec MAY issue attestations; `issuer`
   identifies it."*
3. **Hash-chained public transparency log.** Append every issuance/status-change to a hash-chained JSONL
   (`prev_hash`), published at `GET /log` (+ downloadable). Verification without trusting Warden's DB. (~30 lines
   on the existing JSONL store.)
4. **Portable verifier:** a standalone ~30-line script + a `warden-guard verify <url|badge>` CLI that validates a
   badge offline with the published issuer pubkey. Pitch: *"paste this into any marketplace — Solana, Base,
   Cronos — no Warden account needed."*

### D. Robustness fixes (verified H3–H6, M1–M5)
- **Re-probe timer** for protection heartbeats (mirror the index timer); store `last_probed_at`; **TTL ~1h**;
  the SVG serves **stored** status with `Cache-Control: no-store` (or ≤30s). **Never live-probe from the SVG
  route.**
- **Extract a standalone `validate_public_http_url(url) -> origin`** helper (refactor once; used by auditor +
  protection). The probe MUST use `follow_redirects=False`, a hard 2–3s timeout, and a response-size cap.
- **State the nginx header contract** as a deploy requirement (`proxy_set_header X-Real-IP $remote_addr`; app
  only reachable via nginx); add a **global concurrency cap** on outbound probes (independent of per-IP limits).
- **Nonce store = keyed (sqlite unique index), TTL-evicted** — not an O(n) unbounded JSONL scan; confirm
  single-worker uvicorn or make it process-safe.
- **`POST /protect/revoke`** (signed by the current key) + key rotation; state the key-theft limitation on the
  verify page.
- **Index snapshots:** atomic temp-file + rename; stamp `sampled/expected/dropped`; render "partial/degraded"
  honestly when they differ.

### E. The Creative-Genius centerpiece — "Attack Theater" (build this; it likely wins the prize)
A **self-running site page** (`site/theater.html`) + the ≤90s video: a scripted **malicious agent** fires REAL
attacks (prompt-injection → drain-address → secret-exfil) at a **Warden-protected demo ASP**, and the viewer
*watches* Warden intercept each live — a real BLOCK/SANITIZE feed, a running **"threats neutralized"** counter,
and compute latency in ms. Attacks target **our own demo agent** (no consent/ethics issue). Make it auto-play
(no `pip install` to see the magic). The **live Safety Map** is the hero visual (fabric, not node) — put the map,
not `/scan` JSON, on the landing hero.

### F. Scope cut (verified M4 — finish the right things)
**Demote to "if time remains":** the **TypeScript SDK (§3.2)** and the **live systemd-timer index (§5/§9.3)** —
ship a committed seed snapshot + the map instead; the 6h timer adds real infra risk for near-zero judging value.
Also **honest H1:** do NOT claim "infrastructure the marketplace runs on" as present-tense traction (zero
adopters on judging day). Say *"designed to be adopted; here is a working primitive + a reference ASP protected
end-to-end."* If even 1–2 real other-agent integrations happen before submission, that one fact beats all
network-effect language.

### G. v2 PHASING (build in this order; each green before the next)
1. **Honesty + protocol core:** Ed25519-signed badge + published issuer key; endpoint-host-only keying;
   signed scan-counter heartbeat; consent-in-badge; standalone URL validator; sqlite nonce store. + tests.
2. **Python SDK:** client/async/middleware/decorator/proof, **local in-process mode**, honest free-tier
   defaults, `warden-guard verify` CLI. + tests.
3. **Attack Theater demo + immune-system framing + Safety Map hero** (the Creative-Genius win).
4. **Open standard:** `spec/APA-SPEC.md` + transparency log (`GET /log`) + verify page/API.
5. **Optional/if time:** TS SDK, live index timer, extra polish.

### H. CANONICAL CONTRACTS (single source of truth — resolves every naming conflict in §3–§5)
`spec/APA-SPEC.md` **governs the on-the-wire format, field names, crypto, and endpoints.** Where §3–§5 below
disagree, **these win.** (§2 "what already exists" — engine, models, HMAC helper, SSRF validator — stays valid.)

**Canonical endpoints (use these exact paths; §4.2's `/protect/*` names are SUPERSEDED):**
- `GET  /.well-known/agent-protection`  — endpoint heartbeat / Protection Proof (alias `/.well-known/warden-protected`)
- `GET  /.well-known/apa-issuer.json`   — issuer's published Ed25519 verify key(s) (offline verification)
- `POST /apa/register  {endpoint}`      — issuer probes, reads `pub` from the proof, binds host→pub (TOFU), issues
- `GET  /apa/attestation/{attestation_id}`          — attestation JSON
- `GET  /apa/attestation/{attestation_id}/badge.svg`— embeddable SVG (true status; `Cache-Control: no-store`)
- `GET  /apa/log`                       — hash-chained transparency log (`prev_hash`)
- `POST /apa/revoke`                    — signed by the endpoint key; sets status `revoked`
- `GET  /verify`                        — human verify page (site)

**Canonical record = APA §5 attestation** `{spec_version, predicate_type, attestation_id, issuer, protector,
endpoint_host, pub, tier, status, scans_24h, verified_at, expires_at, issuer_sig}`, signed with the **Ed25519
issuer key**. **DROP** §4.2's `protection_id`, `agent_id`, and the bare HMAC `signature` field. `tier` is
**`guard-live`** (never "guarded"/"protected"). The reference verifier `spec/verify_apa.py` already consumes this
exact shape — match it.

**Canonical registration = TOFU (APA §4):** `POST /apa/register` takes **only `{endpoint}`**. The issuer fetches
the heartbeat, reads `pub` from it, verifies the endpoint self-signature + freshness + nonce, binds `host→pub`,
and flags `key-changed` on a later differing key. **No client-supplied `agent_id` or `public_key` is trusted.**
(§4.1/§4.2's "SDK registers the public key" and `{agent_id, endpoint, public_key}` are SUPERSEDED.)

**Canonical SDK defaults (supersede the `client.py` draft):** free tier default **`fail_open=True`** + loud
"best-effort, not enforcement" docs; add **`WardenClient(local=True)`** in-process mode (imports `WardenEngine`,
no network, honestly sub-ms, not rate-limited). The draft's `fail_open=False` default and hosted-only design are
superseded.

**Scan-counter mechanism (fills the §B1 gap — this is the linchpin of the honest badge):**
- The SDK MUST maintain a lifetime monotonic counter plus an exact rolling 24-hour count, updated atomically
  only after `scan()`/`guard()` returns a valid verdict (both hosted and local modes). Failed, fail-open, and
  malformed hosted responses do not count. State derives from `$WARDEN_GUARD_STATE` (default
  `~/.warden/state.json`, `0600`) and survives restarts. `proof.py` signs the rolling count as `scans_served` plus
  `window_start`; the issuer copies it into the attestation's `scans_24h`. Migrating a positive or unreadable
  lifetime-only state MUST persist a full 24-hour warmup and sign `null`, never `0`, until exact rolling coverage
  is available.
- The SDK exposes no API/config setter for either counter. Third-party tampering fails signature verification
  (proven by `verify_apa.py` selftest case [2]); endpoint-owner state integrity is outside this signature model.
- **Multi-process honesty:** if the ASP runs N workers, either coordinate one shared counter file (atomic
  increment via file lock) OR have each keypair report its own process's count; **document which**, and word the
  badge as "payloads this guard has signed", not "all traffic". Do not aggregate across keys.

---

## 0. Goal & why

Reposition Warden from "a security ASP" to **the trust / safety *layer* of OKX.AI** — infrastructure the whole
agent marketplace can run on. We are building a real product for the long term; the hackathon is a checkpoint.

**Award targeting (data-backed — see `submission/COMPETITIVE-AUDIT.md`, a live 744-agent sweep):**
- **PRIMARY → Creative Genius ($10k).** The marketplace is dominated by data APIs (1000+ sales) and yield bots we
  cannot out-*volume*; the security lane is crowded with single scanners (max 190 sales) and after-the-fact
  correctness checkers. **No competitor offers** a real-time in-loop payload firewall + a drop-in SDK + a
  **cryptographically-verifiable per-ASP "Protected by Warden" badge** + a live marketplace safety index. That
  combination is the most imaginative, category-defining idea in the field and it's execution we control — so we
  win by *out-inventing*, not out-selling. **Build to maximize the "novel, category-defining infrastructure"
  story.**
- **SECONDARY → Best Product ($10k):** completeness/UX/value (site + live demo + SDK + badge + index + open
  source + real feedback loop).
- **FLOOR → Software Utility ($2.5k).** **Not our track → Revenue Rocket** (raw-volume race).
- Plus the post-hackathon **Super Nova grant / OKX partnership** — which rewards exactly this: real, launched
  infrastructure that grows OKX's agent economy.

**Competitive moat the build must make obvious:** the verifiable per-ASP badge (§4) and the one-line SDK (§3) are
things *no other agent has* — they turn Warden from "a service in the marketplace" into "infrastructure the
marketplace runs on." Lead every surface (site, demo, README, submission) with that.

Three pillars (detailed in §3–§5). Build in order; each is independently shippable.

1. **`warden-guard` SDK** — one-line drop-in payload firewall for any agent service (network-effect core).
2. **"Protected by Warden" verifiable badge** — honest-by-design: the badge attests something *cryptographically
   real* (the guard is live), never a claimable sticker.
3. **Marketplace Safety Index** — a live public trust dashboard for OKX.AI listings.

---

## 1. NON-NEGOTIABLE GUARDRAILS (read before writing code)

1. **Do NOT destabilize the live listing `#3808`.** It is currently approved & eligible (`approvalDisplayStatus:
   4`). Everything here is **additive** — new packages, new API routes, new site pages. **Never** run `agent
   update`, change existing service prices/descriptions, or touch the listed agent's core config as part of this
   work. New API routes must not alter existing `/scan`, `/audit`, `/api/demo/scan`, `/health`, `/badge/*`
   behavior.
2. **Honesty is the product.** No claimable trust seals. A "Protected by Warden" badge MUST be backed by a
   verifiable check (see §4). Never fabricate metrics, reviews, or protection claims. If a claim can't be
   verified, don't make it.
3. **Match existing style exactly.** Python: FastAPI + Pydantic v2 models (`warden/models.py`), `httpx`, ruff-clean,
   type hints, the existing module layout. Follow patterns in `warden/api.py`, `warden/auditor.py`,
   `warden/badges.py`. Site: extend `site/styles.css` (Luminous Trust design system) + the existing page
   structure; **self-hosted fonts already in `site/fonts/`** (no external font requests). No new heavy deps
   without justification.
4. **Every function must work** — no stubs, no `TODO`, no placeholder implementations. Ship real, tested code.
5. **Security:** no hardcoded secrets; read from env (`WARDEN_BADGE_SECRET`, `WARDEN_API_KEY`, etc.). Validate all
   external input at boundaries. No secret (0x + 64 hex) literals in committed source — a repo hook blocks them
   (build key-like demo strings from split parts if needed).
6. **Tests required.** Every new module ships with pytest tests matching `tests/` conventions. `python -m pytest
   -q` and `python -m ruff check .` must pass before hand-back.
7. **Deploy is copy-based (not git-based).** Site → `/opt/warden-site/` (nginx root). Service → `/opt/warden/`
   (`warden.service`, uvicorn on 127.0.0.1:8031). **Codex does NOT deploy.** Codex builds + tests locally; the
   reviewer deploys and verifies live. Do not add deploy steps to the app.

---

## 2. WHAT ALREADY EXISTS — verified contracts to build ON (do not reinvent)

Read these files first; they are the source of truth for the contracts below.

### 2.1 Scan / verdict engine
- `warden/engine.py` → `WardenEngine.scan(payload: str, depth="fast", context: dict|None) -> Verdict`.
- `warden/models.py` → `ScanResponse`, `AuditResponse`, `ScanContext`, `Verdict`, `ReasonCode`. **Use these
  models; do not redefine shapes.**
- **Live free endpoint `POST /api/demo/scan`** (rate-limited, no payment) returns exactly:
  ```json
  {"verdict":"BLOCK|SANITIZE|ALLOW","risk_level":"NONE|LOW|MEDIUM|HIGH|CRITICAL",
   "threat_classes":["SECRET_EXFIL", ...],"detections":[{"class":..,"match":..,"confidence":..,"source":..}],
   "sanitized_payload":"...","recommendation":"...","checks":{...},"latency_ms":3.5}
  ```
  Verified verdicts: secret/private-key exfil → `BLOCK`; drain address → `SANITIZE`; "ignore previous
  instructions/restrictions" → `SANITIZE` (PROMPT_INJECTION); benign → `ALLOW`.
- **Paid endpoints:** `POST /scan` and `POST /audit` are x402-gated (0.5 USDT, X Layer, USD₮0). Do not change.

### 2.2 Badges (HMAC verification contract — reuse exactly)
- `warden/badges.py`:
  - `issue_badge(target_host, score, grade, blocked, total, issued_at) -> dict` — HMAC-SHA256 over
    `_canonical_json` of the payload (sorted keys, compact separators), secret from `WARDEN_BADGE_SECRET`
    (default `"warden-dev-key"`). Field set: `{audit_id, target_host, grade, score, blocked, total, issued_at,
    signature}`.
  - `verify_badge(badge: dict) -> bool` — recomputes HMAC over the record minus `signature`, `compare_digest`.
  - **New badge types in §4 MUST reuse `_canonical_json` + the same HMAC scheme** (add helpers, don't fork the
    crypto).
- `warden/badge_store.py`: `record_badge`, `get_badge(audit_id)`, `list_badges()` (JSONL store).
- Live routes: `GET /badge/{audit_id}` (JSON), site badge pages under `site/badges.html` / `site/badge.js`.

### 2.3 MCP surface (mirror these signatures in the SDK)
- `warden/mcp_server.py` (FastMCP): `scan_payload(payload, depth="fast", context=None)` and
  `audit_agent(target_url, sample_prompts=None)`.

### 2.4 Auditor & consent proof (reuse the pattern for §4 verification)
- `warden/auditor.py` → `AgentAuditor.audit(target_url, sample_prompts)`; already probes a target's
  `/.well-known/warden-consent` for `warden-audit-allowed` (see `_verify_target_consent`). The §4 "guard is live"
  proof uses the **same well-known probe pattern**.

### 2.5 Marketplace index (elevate for §5)
- `warden/marketplace/{catalog,fetch,index,render}.py` and `site/agents*.{html,js}` + `site/data/*.json` already
  scan/list OKX.AI agents by public-listing text. §5 builds on this.

### 2.6 Site design system (extend, don't replace)
- `site/styles.css` — "Luminous Trust": Fraunces serif display + Plus Jakarta Sans (self-hosted `site/fonts/`),
  electric-indigo accent, light default + dark variant, verdict colors mint/amber/rose, sticky glass nav, SVG
  icon system, interactive hero widget (`site/hero-scan.js`). New pages MUST use these tokens/components.

### 2.7 Reference draft already started
- `sdk/python/warden_guard/client.py` — a working first draft of the SDK client (`WardenClient`, `ScanResult`,
  `guard()`, `WardenBlocked`). **Adopt and complete it** per §3; treat it as the quality bar, not a throwaway.

---

## 3. PILLAR 1 — `warden-guard` SDK (drop-in payload firewall)

**Outcome:** any OKX.AI ASP adds Warden protection in one line. Ship a real, installable package.

### 3.1 Python package `sdk/python/`
```
sdk/python/
  pyproject.toml            # name "warden-guard"; deps: httpx, cryptography (Ed25519 proof); extra [server]: starlette
  README.md                 # the one-line pitch + copy-paste examples
  warden_guard/__init__.py  # exports: WardenClient, AsyncWardenClient, ScanResult, WardenBlocked, WardenGuard, guard
  warden_guard/client.py    # (draft exists) sync client — finish per below
  warden_guard/aio.py       # AsyncWardenClient (httpx.AsyncClient) — same API, async
  warden_guard/middleware.py# WardenGuard ASGI/Starlette/FastAPI middleware
  warden_guard/proof.py     # serves /.well-known/warden-protected signed heartbeat (see §4)
  warden_guard/decorator.py # @guard(...) to wrap any fn taking untrusted text
```
Requirements:
- **Client API** (already drafted): `WardenClient(base_url=..., paid=False, timeout=8.0, fail_open=False)`;
  `.scan(payload, *, expected_addresses=None, depth="fast") -> ScanResult`; `.guard(payload, **kw) -> str`
  (returns safe payload or raises `WardenBlocked`). `ScanResult` exposes `.blocked/.allowed/.sanitized/
  .safe_payload/.verdict/.threat_classes/.latency_ms/.raw`.
- **`fail_open` semantics:** default fail-*closed* (raise on transport error). `fail_open=True` returns ALLOW on
  outage so Warden never takes a caller offline — document the tradeoff.
- **Async client** (`aio.py`): identical surface with `await`.
- **Middleware** (`middleware.py`): `app.add_middleware(WardenGuard, client=WardenClient(), extract=..., on_block=...)`
  — reads configured request fields, scans, and short-circuits `BLOCK` with HTTP 400 + the verdict JSON; passes
  ALLOW/SANITIZE through (optionally replacing the field with `sanitized_payload`). Must be framework-agnostic
  (pure ASGI) with a FastAPI usage example.
- **Decorator** (`decorator.py`): `@guard(client, field="payload")` wraps a handler; raises/short-circuits on BLOCK.
- **Zero-config default:** `WardenClient()` points at the hosted free endpoint so adoption needs no key. Document
  the `paid=True` path (x402) for production volume.
- **Tests** (`sdk/python/tests/`): mock httpx; assert verdict mapping, `guard()` block/sanitize/allow behavior,
  `fail_open`, middleware short-circuit. Plus one opt-in live smoke test (skipped without network) hitting
  `/api/demo/scan` for the 4 canonical verdicts.

### 3.2 TypeScript package `sdk/ts/` (second; do after Python is green)
- `@warden/guard` — `scan(payload)` client (fetch-based, no deps) + an Express middleware + a `guard()` helper.
  Mirror the Python surface and the `ScanResult` shape. Vitest tests with mocked fetch.

### 3.3 Acceptance (Pillar 1)
- `pip install -e sdk/python` works; `from warden_guard import WardenClient` protects a payload in ≤3 lines.
- All 4 canonical verdicts map correctly against the live demo endpoint.
- Middleware blocks a BLOCK payload end-to-end in a minimal FastAPI app (test).
- `pytest -q` + `ruff check` green.

---

## 4. PILLAR 2 — "Protected by Warden" verifiable badge

**Outcome:** an ASP that actually runs Warden protection can display a badge that **anyone can verify** — and
that Warden itself can confirm by probing the endpoint. Honest network effect.

### 4.1 The honesty model (critical — build exactly this) — LOCKED: per-ASP Ed25519
The badge attests a **real, checkable** fact, chosen by tier:
- **Tier "audited":** issued only after a real `audit_agent` pass (reuse `issue_badge`; already honest). Badge
  states the grade + date + that it is point-in-time.
- **Tier "guarded":** issued when the endpoint **cryptographically proves the guard is live**, using a
  **per-ASP Ed25519 keypair** (asymmetric — the standard; no shared secret):
  - On first run, the SDK generates an **Ed25519 keypair** (`cryptography` lib), persists the private key
    locally with `0600` perms (`$WARDEN_GUARD_KEY` path, default `~/.warden/guard_key`), and registers the
    **public key** with Warden via `POST /protect/register {agent_id, endpoint, public_key}`.
  - The SDK's `proof.py` serves `GET /.well-known/warden-protected` returning
    `{agent_id, endpoint_host, ts, nonce, sig}` where
    `sig = Ed25519_sign(private_key, canonical(agent_id, endpoint_host, ts, nonce))`.
  - Warden's issuer probes that URL and **verifies `sig` against the registered public key** + checks freshness
    (`ts` within TTL) and replay (`nonce` unseen), then issues the **protection badge**. Two distinct signature
    layers, do not conflate: **ASP → heartbeat = Ed25519**; **Warden → badge record = HMAC** (reuse §2.2).
  - Honest meaning: "the ASP holding *this specific* registered key is serving a live Warden guard right now" —
    per-ASP, non-forgeable. State exactly this on the verify page; do not overclaim (it proves the guard is
    served, not that every call is routed through it).
- **Never** issue a "guarded" badge without a passing live signature probe. TTL 24h. Status: fresh valid probe →
  `active`; stale/absent heartbeat → `stale`; bad signature → `invalid`. The badge/SVG must always show the true
  status.

### 4.2 Server (extend `warden/`)
- New module `warden/protection.py`:
  - `issue_protection_badge(agent_id, endpoint, tier, verified_at) -> dict` (HMAC via `badges._canonical_json`
    scheme; fields `{protection_id, agent_id, endpoint_host, tier, status, verified_at, expires_at, signature}`).
  - `verify_protection_badge(badge) -> bool`.
  - `probe_guard(endpoint, public_key) -> bool` (httpx GET `/.well-known/warden-protected`, verify the **Ed25519**
    signature against `public_key` + freshness + nonce-replay; reuse the SSRF-safe URL validation from
    `auditor._validate_public_http_url`). Ed25519 via the `cryptography` package (add to deps).
- New store `warden/protection_store.py` (JSONL, mirror `badge_store.py`; stores the registered public key +
  seen nonces).
- New routes in `warden/api.py` (additive):
  - `POST /protect/register` `{agent_id, endpoint, public_key}` → stores the public key, probes the guard
    (verify Ed25519 sig + freshness), issues badge, returns record. Rate-limited.
  - `GET  /protect/{protection_id}` → JSON record + `verified: true/false`.
  - `GET  /protect/{protection_id}/badge.svg` → **embeddable SVG** ("Protected by Warden" · status color) with
    proper cache headers; renders even for `stale`/`revoked` (different color) — never lies.
  - `GET  /verify` (site page) — paste a badge/id → shows verify result.
- Tests: issue→verify roundtrip, tamper→fail, stale heartbeat→`stale`, SSRF host rejected, SVG renders.

### 4.3 Site
- `site/verify.html` + `site/verify.js` — human verify page (Luminous Trust styling).
- Embeddable snippet documented on the integrate/trust page: `<img src="https://warden.gudman.xyz/protect/<id>/badge.svg">`.

### 4.4 Acceptance (Pillar 2)
- Install SDK → run the demo ASP → `POST /protect/register` issues an **active** badge only while the heartbeat
  is served; kill the heartbeat → re-check → `stale`. Tamper the badge JSON → verify fails. SVG embeds and shows
  the true status. Honesty caveats (what the Ed25519 heartbeat proves / doesn't) written on the verify page.

---

## 5. PILLAR 3 — Marketplace Safety Index (live public dashboard)

**Outcome:** a genuine, honest, beautiful public "trust layer" view of OKX.AI listings — Warden's public good.

- Build on `warden/marketplace/*` + existing `site/agents*`. Deliver:
  - A refreshed **index dashboard page** (`site/index-safety.html` or elevate `/agents`) with: total agents
    scanned, per-agent public-listing-text signal, filters (category / signal / audited), and a clear, repeated
    **honesty banner** ("public-listing-text signal only — NOT an endpoint audit or a claim an agent is
    malicious"). Reuse the exact honesty framing already in `site/agents*`.
  - Link agents that hold a real `audit` badge or a `protect` badge to their verifiable record (ties Pillars 2 & 3).
  - **Genuinely live (LOCKED):** a refresh script (`scripts/refresh_safety_index.py`) re-scans the marketplace
    and writes a **timestamped snapshot** to `site/data/`, driven by a **systemd timer on the VPS**
    (`deploy/systemd/warden-index.service` + `warden-index.timer`, e.g. every 6h). The site reads the latest
    snapshot; each snapshot shows its `capturedAt`. **Log what was sampled/dropped** (no silent truncation). Ship
    one committed seed snapshot so the page renders before the first timer run.
- Tests: index build is deterministic from a fixture; honesty banner present; no agent labeled "malicious".

### 5.1 Acceptance (Pillar 3)
- Dashboard renders from committed data, is honest, filterable, links to verifiable badges, matches design system.

---

## 6. SITE / DOCS (tie it together)
- New **"Trust Layer" page** (`site/trust.html`) — the vision + the 3 pillars, with the one-line SDK snippet, the
  badge embed, and a link to the safety index. Luminous Trust styling; add to nav (Developers group) **without**
  breaking existing nav.
- Update `site/integrate.html` to feature the SDK first (one-line protect), then raw x402/MCP.
- README: add a "Trust Layer" section + SDK quickstart.

---

## 7. PHASING (ship each phase green before the next)
1. **P1:** Python SDK (client/async/middleware/decorator/proof) + tests. ← start here (draft exists).
2. **P2:** Protection badge server + store + routes + SVG + verify page + tests.
3. **P3:** TS SDK.
4. **P4:** Safety Index dashboard.
5. **P5:** Trust Layer site page + integrate/README updates.

Each phase: `pytest -q` + `ruff check .` green, no changes to existing endpoints' behavior, no repo-hook secret
violations.

---

## 8. REVIEW CHECKLIST (what Claude will verify per phase)
- [ ] Contracts match §2 exactly (models, badge HMAC scheme, endpoint shapes). No forked crypto.
- [ ] No change to `#3808` config or existing `/scan`,`/audit`,`/api/demo/scan`,`/health`,`/badge/*` behavior.
- [ ] Honesty: no claimable badge; "guarded" requires a live Ed25519 probe; SVG never shows a false status;
      heartbeat-proof caveats stated on the verify page.
- [ ] SDK: 4 canonical verdicts correct against live demo; `guard()` + middleware block/sanitize/allow correct;
      `fail_open` documented.
- [ ] Tests present + green; ruff clean; no stubs/TODOs; no secret literals.
- [ ] Site: uses Luminous Trust tokens/fonts; responsive; no console errors; nav intact.
- [ ] SSRF-safe URL validation reused for any endpoint that probes external URLs.
- [ ] Everything additive & deployable by file-copy without breaking the live listing.

---

## 9. LOCKED DECISIONS (final — build exactly these; no open questions)
1. **Badge proof = per-ASP Ed25519 keypair** (asymmetric, standard). SDK generates + persists the keypair,
   registers the public key, signs the heartbeat; Warden verifies against the registered public key + freshness +
   nonce-replay. No shared secret. (§4.1)
2. **SDK default = free / zero-config** hosted endpoint for frictionless adoption; **paid x402 is opt-in**
   (`paid=True`), documented as the production/high-volume tier. (§3.1)
3. **Safety Index = genuinely live** via a systemd timer on the VPS refreshing timestamped snapshots (~every 6h),
   with one committed seed snapshot. Not a static file. (§5)

These are the "best/standard, built once for the long term" choices — implement them as specified above.
