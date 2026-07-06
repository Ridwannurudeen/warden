# Warden — Phase 2 Build Brief for Codex (revenue-critical, additive-only)

**You (Codex) build every line. Claude audits each item.** This brief is self-contained. Follow it exactly. No Claude/Anthropic attribution anywhere in code or commits. No `Co-Authored-By`.

## Context you must not break (read first)

Warden is **LIVE** at `warden.gudman.xyz` and **registered as OKX Agent #3808, listing under review.** The registered A2MCP services point at `POST /scan` (0.01 USDT) and `POST /audit` (15 USDT). The hackathon target is the **Highest Revenue Award** ($10k) — scored on revenue + orders + on-chain reviews during the window. Hard cutoff: **Jul 17 00:00 UTC** (finish by Jul 16).

**HARD CONSTRAINTS — violating any voids the listing or the entry:**
1. **Do NOT change the request/response schema, path, method, status codes, or pricing of `POST /scan` or `POST /audit`.** They are frozen on-chain. Everything you add is *new* surface.
2. **Additive only.** New routes, new modules, new middleware layers that no-op unless explicitly enabled. Never edit the frozen route handlers' contract.
3. **Determinism is sacred.** Do not touch `warden/engine.py`, `warden/core/verdict.py`, the analyzers, or the corpus. `test_corpus.py` must stay green and unchanged.
4. **No new hard dependency in the payment/paywall path.** New deps go in an optional extra or are pure-stdlib where possible.
5. Every function complete and working — no TODO/stub/`pass`/`NotImplemented`. No `Any` at boundaries. Validate all external input.

Package layout is `warden/warden/` (imports `from warden.x import ...`), pytest from repo root, ruff clean, async throughout. Match existing style in `warden/api.py`, `warden/auditor.py`, `warden/models.py` (all already read — mirror them).

---

## Build order (each item ends at a ▸ Claude-audit gate; stop and report at each)

### Item 1 — Verifiable audit badge + public lookup (HIGHEST revenue leverage) ▸
**Why:** today `audit_agent` returns a plain string badge (`warden/auditor.py:81`) that anyone can fabricate. A **verifiable** badge is what makes entrants comfortable posting "Warden-audited" publicly → that post markets Warden → drives more paid audits + on-chain reviews (the exact revenue-award inputs). This is the single most revenue-relevant thing to build.

Build:
- **New module `warden/badges.py`:**
  - `issue_badge(target_url: str, score: float, grade: str, blocked: int, total: int, issued_at: str) -> dict` — returns `{audit_id, target_host, grade, score, blocked, total, issued_at, signature}`.
  - `audit_id` = deterministic short id: first 16 hex of `sha256(f"{target_host}|{issued_at}|{score}")` (stdlib `hashlib` — no `Date.now()`/`random`; caller passes `issued_at`).
  - `signature` = HMAC-SHA256 (stdlib `hmac`) over the canonical JSON of the badge fields (sorted keys, excluding `signature`), keyed by env `WARDEN_BADGE_SECRET`. If the secret is unset (local/test), sign with a fixed documented dev key `"warden-dev-key"` so tests are deterministic — document this clearly.
  - `verify_badge(badge: dict) -> bool` — recomputes and constant-time-compares (`hmac.compare_digest`).
  - A JSONL store `warden/badge_store.py` OR reuse a file at `corpus/`-sibling `badges/issued.jsonl` (create dir): append-only `record_badge(badge)` + `get_badge(audit_id) -> dict | None`. Pure stdlib, file-locked with a simple `threading.Lock` guarded append (single-worker VPS today; note the limitation in a comment).
- **Wire into `warden/auditor.py`:** after computing `score/grade/blocked_count`, call `issue_badge(...)` passing `date.today().isoformat()` as `issued_at` (keep the existing `date` import; the badge string stays for backward compat), record it, and add the structured badge object to the response.
- **Extend `AuditResponse` in `warden/models.py`:** ADD an optional field `badge_record: BadgeRecord | None = None` (new `BadgeRecord` model). **Do not remove or rename the existing `badge: str` field** — additive only, so the on-chain-visible schema still validates.
- **New route in `warden/api.py`:** `GET /badge/{audit_id}` → returns the stored badge + `{"verified": verify_badge(...)}`, or 404. This is a **new, free, read-only** route — does not touch the paid routes or their middleware.
- **New site page:** `site/badge.html` + a small `site/badge.js` that reads `?id=<audit_id>` from the query string, fetches `/badge/{id}`, and renders a verify card (✓ Verified / ✗ Invalid, host, grade, score, date). Match `site/styles.css`. Self-contained, no external resource requests (CSP rule — see existing `site/index.html`).

Tests (`tests/test_badges.py`): issue→verify round-trips; tamper any field → `verify_badge` False; `audit_id` stable for same inputs; store append+get; `GET /badge/{id}` returns verified true for a freshly issued badge and 404 for unknown.

▸ **Claude audits:** signature can't be forged without the secret; tamper detection; frozen `/audit` contract unchanged (old `badge` string still present); new route is free + read-only; site page makes zero external requests; tests green.

### Item 2 — Rate limiting (survive judge/attacker load) ▸
**Why:** `warden/api.py` has only a body-size middleware (`:102`). `/scan` pre-402 processing and free `GET /` `/health` `/badge` are unmetered — a judge load-test or a bad actor can exhaust the single VPS worker and take the listing offline (offline = ineligible).

Build:
- **New module `warden/ratelimit.py`:** a dependency-free in-process fixed-window limiter keyed by client IP (`request.client.host`, honoring `X-Forwarded-For` first hop since nginx fronts it — document trust boundary). Config via env: `WARDEN_RATE_LIMIT_PER_MIN` (default 60) and a separate higher bucket is unnecessary — one global per-IP window.
- **New middleware in `warden/api.py`** registered AFTER the size-limit middleware: on limit exceeded return `429` + `Retry-After`. **Exempt nothing by path** except keep it strictly separate from the x402 payment middleware ordering — payment middleware must still run for paid routes. Verify the paid-route 402 behavior is unchanged when under the limit.
- Make it **disable-able** (`WARDEN_RATE_LIMIT_PER_MIN=0` → off) so tests and the corpus/API tests don't flake.

Tests (`tests/test_ratelimit.py`): N requests under limit pass; N+1 → 429 with `Retry-After`; window resets; disabled mode never 429s; the existing `test_api.py` still green (set limit high or off in its fixtures).

▸ **Claude audits:** limiter can't be trivially bypassed (spoofed XFF note is acceptable + documented), 429 shape correct, paid-route 402 path intact, no interference with corpus determinism, tests green.

### Item 3 — audit_agent target-consent gate + ToS/privacy (legal safety) ▸
**Why:** `audit_agent` fires a 20-attack battery at an arbitrary `target_url` (`warden/auditor.py:AUDIT_BATTERY_SIZE`). SSRF is already guarded, but nothing proves the target consented → "pay 15 USDT to attack any endpoint." For the hackathon, entrants requesting their own audit consent implicitly, so **gate must be opt-in/soft for the window, hard-documented for mainstream.**

Build:
- **Consent check in `warden/auditor.py`** (new helper): before firing the battery, attempt `GET {origin}/.well-known/warden-consent` (short timeout, reuse the SSRF-validated connect path). If it returns 200 with body containing the token `warden-audit-allowed`, proceed normally. If absent: controlled by env `WARDEN_REQUIRE_CONSENT` (default `false` for the hackathon → proceed but set a response flag `consent_verified: false`; `true` → raise `ValueError` → existing 400 handler at `api.py:130`). **Additive response field only** — add `consent_verified: bool` to `AuditResponse` (default true when the file is present), never remove fields.
- **Static docs:** `site/terms.html` + `site/privacy.html` (linked from `site/index.html` footer) — plain, honest: `/scan` payloads are processed transiently and not retained beyond request handling; `audit_agent` requires you to own or have permission to test the target; no OKX endorsement claimed. Match site style, self-contained.

Tests (`tests/test_consent.py`): consent file present → proceeds, flag true; absent + require=false → proceeds, flag false; absent + require=true → 400. Mock the HTTP fetch; do not hit the network in tests.

▸ **Claude audits:** default-false preserves hackathon flow, hard mode works, no fields removed from `/audit`, SSRF path reused (not a second unguarded fetch), docs honest + no external requests, tests green.

---

## Cross-cutting acceptance (all items)
- `ruff check .` clean; `pytest -q` fully green including the untouched `test_corpus.py` (88 attacks / 30 benign, 0 false positives).
- No edits to: `warden/engine.py`, `warden/core/*`, `warden/analyzers/*`, `warden/scanner/*`, `corpus/*`, the frozen `/scan` and `/audit` request/response contracts, `deploy/warden.service`'s run command (you MAY add `EnvironmentFile` keys / new env vars, documented in `deploy/DEPLOY.md`).
- New env vars documented in `deploy/DEPLOY.md` and `PAYMENT.md` where payment-adjacent: `WARDEN_BADGE_SECRET`, `WARDEN_RATE_LIMIT_PER_MIN`, `WARDEN_REQUIRE_CONSENT`.
- Update `README.md` only to document the new `/badge/{id}` route, badge verification, rate limiting, and consent/ToS — keep the honest "Limitations" section accurate.
- Nothing deployed or registered by Codex — deploy + the on-chain listing are user-owned. Stop after each ▸ and report exactly what to audit.

## What is explicitly OUT of scope for this phase (do not build)
LLM layer 4, client SDKs, corpus growth pipeline, A2A escrow tier, monitoring/alerting stack, multi-worker/Redis-backed rate limiting, Coinbase/Solana/AP2 ports. Those are roadmap Q4-2026+ (see `ROADMAP.md`) — build them only when asked.
