# Warden — Prioritized Fix Plan (emergency → low)

Merged from three Fable audits + two Codex audits, every item Claude-verified against live/source.
Ordered by severity + submission impact. Work top-down.

## HARD CONSTRAINTS (all tiers)
- Never change the frozen `/scan` `/audit` x402 contract (routes, methods, $0.5 prices, response envelopes).
  `test_paid_http_contract_remains_frozen` must stay green.
- Regression test per fix. Run the full suite (py/js/ts) + ruff; report real counts.
- No AI attribution (see the AI_USAGE.md USER DECISION at the bottom). No deploy — Codex commits on the
  branch, Claude audits + deploys.

---

## TIER 0 — EMERGENCY (already FIXED LIVE by Claude this session; make permanent in code)
- **[DONE] Live 403 on `/data/warden-services.json` + `/data/marketplace-summary.json`** → `/hire` +
  `/integrate` were broken. Cause: `build_index` wrote them mode-600; nginx (non-root) got permission-denied.
  Fixed via `chmod 644` live. **Make permanent (R3):** `build_index.py`/deploy must `chmod 644` generated data.
- **[DONE] APA issuer key world-readable** (`/opt/warden/data/apa_issuer.key` was 0644, `WARDEN_ISSUER_KEY`
  env unset → forgeable attestations). Fixed via `chmod 600` live. **Make permanent (R6):** deploy creates the
  key 600 / prefer `WARDEN_ISSUER_KEY` env; **ROTATE the key** (was readable) as a sequenced user-owned
  follow-up (rotation invalidates existing attestations).

## TIER 1 — CRITICAL (enforcement returns unsafe content; the "our security does nothing" bugs)
- **R1 — SANITIZE is cosmetic.** Both SDK middlewares (`sdk/python/warden_guard/middleware.py`,
  `sdk/ts/src/middleware.ts`) forward the ORIGINAL body on SANITIZE ("ALLOW and SANITIZE pass through …
  unchanged"); the engine sanitizer (`scanner.py:421`, `verdict.py:152`) can leave a dangerous remainder.
  → On SANITIZE, substitute `sanitized_payload` into the forwarded body, or BLOCK if it can't be safely
  rewritten; make the sanitizer remove ALL matched dangerous content or downgrade to BLOCK.
  **Accept:** integration test proves the app receives the sanitized value (or a block).
- **R7 — Secret-echo.** A `SECRET_EXFIL` detection returns the raw secret in `detections[].match` (verified
  live: seed words echoed); sanitizer left mnemonic words in. → Redact/hash `match` for secret-class
  detections before returning; remove all secret tokens in sanitize. **Accept:** no raw secret substring in
  the response.
- **R2 — Empty/oversized input fails open.** `payload=""` → ALLOW/NONE (`models.py:45`); oversized payloads
  are truncated before scanning (`models.py:27`) so an attack in the tail is never scanned but is forwarded.
  → Reject blank/whitespace-only payload (422); scan the full payload or reject oversize with 413 (never
  silently truncate-then-ALLOW). **Accept:** `{"payload":""}` → non-ALLOW/422; tail attack in a large payload
  is detected or rejected.

## TIER 2 — HIGH (release-blocking, trust, distribution)
- **S1 — Rate-limit bypass.** Any request with a junk `payment-signature`/`x-payment` header skips the limit
  on `/scan`+`/audit` (`api.py:276`). → Apply a SEPARATE generous limit to payment-carrying requests instead
  of an unlimited skip (preserve legit OKX paid replays). **Accept:** (cap+1)-th forged-header request → 429.
- **R4 — Distribution broken.** (a) root wheel omits `bip39_words.txt` (`exfiltration.py:10` reads at import)
  → clean `pip install` + `import warden.engine` fails; add `package-data`/MANIFEST + a CI clean-wheel-install
  gate. (b) `pip install warden-guard` = unrelated PyPI project; `@warden/guard` unpublished — publish real
  names or fix every install doc. (c) `paid=True` (`client.py:229`) doesn't settle x402 and `fail_open` turns
  402→ALLOW — implement real signing or stop claiming paid; `fail_open` must NEVER turn a 402 into ALLOW.
  (d) CI never tests clean install / SDK suites / TS packaging / APA self-test / settled x402 — add those.
- **R3 — Deploy parity.** `chmod 644` generated data in the deploy process (permanent 403 fix); reconcile the
  RED test `test_deploy_index.py::test_nginx_routes_only_live_index_artifacts_to_atomic_current_release` — it
  expects the blue-green `/current` layout but production is FLAT (chosen). Update the test to the flat conf.
  **Accept:** full pytest green (currently 1 failed).
- **R8 — systemd hardening.** `warden.service` `ReadWritePaths=/opt/warden` lets the service rewrite its own
  code/venv. → Narrow to `/opt/warden/{data,badges,gauntlet}` + logs only; fix the committed-unit
  `/opt/warden/current` vs flat mismatch.
- **C1 — Auditor false grades.** 402/429/timeout/3xx counted as "not blocked" → paywalled/unreachable targets
  grade F, and broad keywords ("risk"/"unsafe") count as a block — both signed into badges (`auditor.py:100`).
  → Add INCONCLUSIVE (never-processed statuses excluded from scoring; no badge when fully inconclusive);
  tighten the "blocked" heuristic. **Accept:** paywalled target → not-F/no-badge; normal target unchanged.
- **S3 — Transparency log unsigned + no seq.** Truncation OR full rewrite verifies `True` (`protection_store.py
  :462`). → Enforce contiguous strictly-increasing `seq`; issuer-sign a log head/checkpoint and verify it.
  **Accept:** truncated + rewritten chains fail; honest chain passes.

## TIER 3 — MEDIUM
- **S2 — Unbounded APA growth.** Same-key re-registration mints a new attestation + log row each call
  (`protection_store.py:346`). → Reuse/refresh the existing active record; log only real state changes.
- **S7 — Gauntlet pending unbounded.** `_prune_records` keeps ALL pending/confirmed (`gauntlet_store.py`),
  each ~4-5KB, O(n) rewrite per POST. → Cap retained pending (or store only hashes).
- **R5 — False positives.** Benign `getBalance` tool call → BLOCK; legit invoice recipient redacted; security
  docs → SECRET_EXFIL (recheck 64-hex tx-hash). → Tighten each; add all as benign regression cases.
- **S4 — `/apa/log` un-rate-limited + full-serialize.** → Add read-scope rate limit + pagination.

## TIER 4 — LOW
- **S5 — x402 schema middleware crash guard** (`api.py:302`): on malformed challenge, pass original through
  (never 500).
- **S6 — Rate-limit `X-Real-IP` trust** (`ratelimit.py:18`): prefer peer IP or assert nginx sets it everywhere.
- **S8 — MCP tools skip caps** (`mcp_server.py`): truncate payload; validate `target_url`.
- **S9 — Badge default secret** (`badges.py:18`): require `WARDEN_BADGE_SECRET` independent of `OKX_API_KEY`.
  (Live impact NIL — VPS has a real secret.)

## HONESTY (do BEFORE submission — integrity)
- **O1** — correct the `scanner.py` docstring: no LLM runs (`ai_analyzer=None`); deterministic regex +
  heuristic + TF-IDF only. **O2** — recaption the demo/theater ("deterministic catches known patterns;
  semantic layer handles novel"); stop the theater relying on pre-supplied `expected_addresses` to fake a
  BLOCK; note classic injections SANITIZE (redact), not hard-BLOCK.

## DETECTION (recall — do the safe one; defer the risky one)
- **D3 [SAFE]** — add paraphrase/plain-English patterns (injection "set aside what you were told", drain verbs
  wire/route/forward/move, exfil verbs ship/smuggle/forward). MUST NOT add false positives (test benign
  paraphrases). **D4** — held-out recall benchmark (`scripts/benchmark_recall.py` + fresh non-corpus attacks);
  publish the honest number. **D1 [HIGH RISK, LAST]** — wire the semantic LLM layer, PAID/`thorough` tier only,
  gated behind deterministic layers, fail-open, env-keyed, provider-neutral copy; **leave disabled if it can't
  be made fail-open + fully tested.**

## PRODUCT / UX (separate track — user-owned, not Codex code)
Consolidate to one "Pre-Action Incident Console" journey (external output → consequential action → Warden
withholds/transforms it). Lead with real proof (15 sold / 4.8 / paid services / listing link); move Safety
Map, Gauntlet, APA, badges, auditor under Labs/Trust; fix number drift across surfaces; unify brand
(black/gold/red, drop purple/glass). Record ≤90s demo + browser/mobile QA.

## ⚠ USER DECISION — AI_USAGE.md
Codex says the hackathon REQUIRES an AI-usage disclosure (restore AI_USAGE.md); the user's standing rule
forbids AI attribution in the repo (why it was removed). Claude could NOT verify the OKX Build-X rules mandate
it. **User decides** — if mandated, restore a provider-neutral note; else keep removed. Do not restore on
assertion alone.

---
## HACKATHON CUT LINE — what ships before the deadline vs what defers
The clock may not allow everything. Cut in this order; defer the rest to PRODUCT-PLAN.md without guilt.

### MUST SHIP before submission (non-negotiable integrity floor — you cannot honestly submit a security
### product that returns unsafe output or overclaims)
- TIER 0 (already done live).
- **TIER 1** — R1 SANITIZE, R7 secret-echo, R2 empty/oversize. If the FULL fix can't all land, ship the
  minimum that stops unsafe output: SANITIZE→BLOCK when it can't fully clean, redact the secret-echo, reject
  empty payload.
- **O1 + O2** (honesty — don't overclaim the LLM/demo; a judge WILL test the demo).
- **R3** (green CI + permanent 403 fix).
- **R4 honesty subset** — fix install docs so they don't point at PyPI/npm packages you don't own, and stop
  documenting `paid=True` as settling payment (even if you don't publish the packages this cycle).
- The submission itself: ≤90s demo, X thread, form + browser/mobile QA (user-owned, approval-gated).

### SHIP IF TIME PERMITS (each materially strengthens the submission)
- S1 (rate-limit bypass), C1 (auditor false-grades), S3 (log signing), R8 (systemd), R4 full (packaging + CI).
- D3 (safe paraphrase patterns — cuts the obvious demo misses without an LLM).
- Cheap UX wins: lead-with-proof homepage, fix number-drift across surfaces.

### DEFER → PRODUCT-PLAN.md (post-hackathon; explicitly NOT expected before the deadline)
- TIER 3 + TIER 4 hardening (S2, S7, R5, S4, S5, S6, S8, S9).
- **D1 (semantic/LLM layer) + D4 (held-out benchmark)** — the real detection overhaul → PRODUCT-PLAN P1/P2.
  This is the thing that makes Best Product genuinely winnable; it is a *post-hackathon* build.
- The full **Pre-Action Incident Console** UX rebuild → PRODUCT-PLAN P3.
- **Near-real-time Safety Index auto-update** (the "reflect OKX enlistments live" feature) → PRODUCT-PLAN
  (already specced, with the VPS-CLI blocker + the not-literally-instant caveat).
- **APA key rotation**, full CI gates, transparency-log anchoring maturation → PRODUCT-PLAN P3.

## PARALLELIZATION — 3 disjoint lanes (for 3 Codex terminals)
**Do NOT run 3 Codex on the same working tree.** Each lane runs in its OWN git branch/worktree
(`git worktree add ../warden-laneA laneA` etc.). Claude integrates (merge A→B→C, full suite after each,
resolve residual, verify frozen contract + acceptance) — Codex terminals never merge or deploy.

- **Lane A — Detection, response-safety, honesty.** Owns `warden/scanner/*`, `warden/analyzers/*`,
  `warden/core/verdict.py`, `warden/engine.py`, `warden/models.py`, `warden/auditor.py`, `site/index.html`,
  `site/theater.html`, `site/theater.js`, `corpus/`, `benchmark/`. Items: R1(engine sanitizer), R2, R7, R5,
  C1, O1, O2, D3, D4.
- **Lane B — API / rate-limit / trust.** Owns `warden/api.py`, `warden/ratelimit.py`, `warden/protection.py`,
  `warden/protection_store.py`, `warden/gauntlet_store.py`, `warden/badges.py`, `warden/badge_store.py`,
  `warden/mcp_server.py`, `site/verify.js`, `site/log.js`. Items: S1, S2, S3, S4, S5, S6, S7, S8, S9.
- **Lane C — SDK / packaging / deploy / CI.** Owns `sdk/python/*`, `sdk/ts/*`, `pyproject.toml`, `MANIFEST.in`,
  `.github/workflows/ci.yml`, `deploy/*`, `scripts/build_index.py`, `scripts/refresh_safety_index.py`,
  `tests/test_deploy_index.py`. Items: R1(SDK middlewares), R4, R3, R8.

**Coordination rules (agree before starting):**
- `models.py` is Lane A's; B/C request fields (additive-only) — Claude resolves at merge. Frozen Scan/Audit
  field sets change for nobody.
- R1 contract: Lane A guarantees `sanitized_payload` is fully clean (or verdict=BLOCK); Lane C's SDK forwards
  that field on SANITIZE. Shared = the field, not code.
- Tests: each lane adds tests in NEW files named for its items (`tests/test_r1_*.py`, `tests/test_s1_*.py`,
  `tests/js/*`, `sdk/*/tests/*`) — never edit another lane's test file.
- Each lane runs its own subset + reports; Claude runs the FULL py/js/ts + ruff after each merge.

## Build order for Codex
TIER 0 (make permanent) → TIER 1 → O1/O2 → R3 → TIER 2 → D3 → TIER 3 → TIER 4 → D4 → D1 (guarded).
Stop at the cut line if the clock runs out — everything below it is tracked in PRODUCT-PLAN.md.
Frozen contract intact throughout; commit on branch; Claude audits + deploys.
