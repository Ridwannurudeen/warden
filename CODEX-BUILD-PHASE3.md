> **HISTORICAL / SUPERSEDED IMPLEMENTATION BRIEF**
>
> This file is retained as project history, not current product truth. Consult `ROADMAP.md`, the
> completion addendum in `SECURITY-AUDIT-2026-07.md`, and `REDESIGN_REPORT.md`. Do not execute or
> deploy from this brief without fresh verification and explicit user approval.

# Warden — Phase 3 Codex Build Brief (eligibility hardening)

**Author:** Claude (audit synthesis, 2026-07-08). **Builder:** Codex. **Auditor:** Claude (each item ends at a ▸Claude-audit gate).

## Context you must respect
Warden is a **LIVE, listed** OKX.AI ASP (Agent #3808, `approvalDisplayStatus: 4 = Listed`). Two paid A2MCP services are attached on-chain and **FROZEN** — do NOT change any endpoint path, request/response schema, pricing, or the x402 config in `warden/api.py` lines 48–117. Breaking the live contract can void the hackathon entry.

This phase is **additive/surgical only**. Two fixes came out of a 3-agent audit. Both were verified by Claude against the code as written. Scope is exactly these two — nothing else. Do NOT touch the detection engine, add the LLM layer, add features, or flip the `WARDEN_REQUIRE_CONSENT` default (leaving it `false` is a deliberate hackathon decision so our free-audit outreach can scan entrant endpoints that have no consent file).

Env baseline (verified 2026-07-04): Python 3.12, pytest 9.0.3, fastapi 0.137.1. Current test count: **53 passing, ruff clean.** Both must stay green after each item.

---

## Item 1 — [HIGH] Fix the rate limiter (bypass + memory-DoS). Highest priority.

### The bug (verified in code)
`warden/ratelimit.py`:
- Line 22: `_client_ip` returns `forwarded_for.split(",")[0].strip()` — the **first** X-Forwarded-For value.
- `deploy/nginx-warden.conf` (lines 38–39, 47–48, 56–57, 65–66) sets `X-Real-IP $remote_addr` **and** `X-Forwarded-For $proxy_add_x_forwarded_for`. The latter *appends* the real client IP to whatever the client already sent, so **the first XFF element is fully attacker-controlled**.

Two consequences:
1. **Bypass:** a caller rotating `X-Forwarded-For: <random>` on every request gets a fresh bucket each time and never trips the 60/min limit.
2. **Unbounded-memory DoS:** `_STATE` (line 14) is a module-global dict that **never evicts**. Every distinct spoofed key becomes a permanent entry → memory growth → uvicorn worker OOM/crash. **A crash while judges are testing = listing offline = invalid entry.** This is the whole reason this item is HIGH.

### The fix
In `warden/ratelimit.py`:

1. **Trust the nginx-set `X-Real-IP` header, not client-forgeable XFF.** Rewrite `_client_ip` so it prefers `X-Real-IP` (nginx sets it to `$remote_addr`, which the client cannot forge through our proxy), then falls back to `request.client.host`, then `"unknown"`. Do **not** read `X-Forwarded-For` as the primary key anymore. (Rationale: every real request to the live service transits nginx, which always sets `X-Real-IP`. Direct-to-uvicorn is bound to `127.0.0.1:8031` only, so `request.client.host` is a safe fallback there.)

2. **Bound `_STATE`.** On each `check_rate_limit` call, while holding `_STATE_LOCK`, evict entries whose stored `window_id` (the tuple's first element) is older than the current window before inserting/updating. This makes `_STATE` size bounded by the number of *distinct real clients active in the current 60s window*, not by lifetime request variety. Keep the existing lock, window math, and the `limit_per_minute <= 0` disabled-path untouched.

Keep the public function signatures identical: `check_rate_limit(request, limit_per_minute) -> bool`, `retry_after_seconds() -> int`, `_reset_state()`. `api.py:141` calls `check_rate_limit(request, limit_per_minute)` — do not change that call site or `WARDEN_RATE_LIMIT_PER_MIN` (default 60, `api.py:23`).

### Tests (`tests/test_ratelimit.py`)
The existing helper `_request_with_client_ip` (lines 11–15) builds a request with **only** `x-forwarded-for`. Since we're switching the trust source, update it to set `x-real-ip` instead (that's what nginx sends). Keep every existing assertion — behavior must be identical for a well-formed single-client request. Then **add**:
- `test_xff_spoof_does_not_create_new_buckets`: a request with a fixed `x-real-ip` but a *rotating* `x-forwarded-for` on each call must still be counted as the **same** client (i.e. XFF is ignored). Confirms the bypass is closed.
- `test_state_evicts_stale_windows`: drive `check_rate_limit` across two different windows (monkeypatch `_time_now` like `test_check_rate_limit_window_resets_on_boundary` does) with distinct clients per window, then assert `len(ratelimit._STATE)` reflects only the current window's clients (stale entries evicted). Confirms the memory leak is fixed.

### ▸Claude-audit gate 1
- `_client_ip` no longer trusts XFF; keys on X-Real-IP with safe fallback.
- `_STATE` provably bounded (eviction verified by the new test, not just claimed).
- 53 prior tests + 2 new = 55 green, ruff clean.

---

## Item 2 — [LOW→MED] Harden the /audit SSRF IP blocklist

### The gap (verified in code)
`warden/auditor.py:238-246` `_is_blocked_ip` allow-lists specific flags (`is_private/is_loopback/is_link_local/is_multicast/is_reserved/is_unspecified`). It misses:
- **IPv4-mapped IPv6** (e.g. `::ffff:169.254.169.254`) — on some CPython versions the `is_*` flags evaluate on the v6 wrapper and don't catch the mapped v4 address, so a cloud metadata IP could slip through.
- **CGNAT `100.64.0.0/10`** and other non-global ranges.

`/audit` is a paid, public endpoint that fires ~20 attack payloads at a buyer-named URL, so its SSRF surface must be tight. The DNS-rebinding pin (`_build_consent_url` + `connect_url` reuse) is already correct — **do not touch that**; it was verified good.

### The fix
Rewrite `_is_blocked_ip` to:
1. First unwrap IPv4-mapped IPv6: if the address has a non-None `.ipv4_mapped`, evaluate the blocklist against that unwrapped IPv4 address instead.
2. Replace the flag allow-list with a **deny-unless-global** check: `return not ip.is_global`. `ipaddress`'s `is_global` already excludes private, loopback, link-local, CGNAT (`100.64/10`), reserved, multicast, and unspecified — this is strictly stronger and simpler than the current list.

Keep the method static, same signature `(_is_blocked_ip(ip) -> bool)`, same call sites.

### Tests (`tests/` — add to `test_consent.py` or a small `test_ssrf.py`, match existing style)
Add unit tests asserting `_is_blocked_ip` returns `True` for: `169.254.169.254`, `::ffff:169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `100.64.0.1`; and `False` for a normal public IP like `93.184.216.34` (example.com). If `_is_blocked_ip` isn't importable as-is, test it via the class (`SecurityAuditor._is_blocked_ip(ipaddress.ip_address(...))`) — verify the actual import path before writing.

### ▸Claude-audit gate 2
- `_is_blocked_ip` uses `not ip.is_global` after unwrapping ipv4_mapped.
- New SSRF unit tests green; the DNS-rebinding pin path is unchanged.
- Full suite green, ruff clean.

---

## Out of scope (do NOT build)
- Consent default flip (stays `false` for the hackathon outreach flow — roadmap item).
- Badge secret hardening — this is an **ops action, not code**: Claude/user will confirm `WARDEN_BADGE_SECRET` is set on the VPS `.env` (memory says it was set on 2026-07-06). Do not add a startup `raise` that could break local/test runs.
- Any detection-engine, LLM-layer, corpus, or feature work — audits agree it moves zero award needle and risks the live service.

## Deploy
Codex builds + tests locally only. **Do not deploy or restart the VPS service** — deploy is user/Claude-owned (additive restart of `warden.service` per `deploy/DEPLOY.md`, after Claude audits both gates).

## Definition of done
Both ▸Claude-audit gates pass, `55+` tests green, ruff clean, zero changes to frozen endpoints/schemas/pricing, working tree committed on a new branch (`phase3-hardening`) but **not** pushed/deployed.
