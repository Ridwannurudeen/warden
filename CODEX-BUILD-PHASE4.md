# Warden Phase 4 — Codex Build Brief

**Branch:** create `phase4-detection-recall` off `phase3-hardening` (which already has commit `d11e939` — rate-limiter key/eviction fix + SSRF `is_global` fix, 57/57 tests green, not yet deployed; leave that branch/commit alone).

**Constraints (same as Phase 2/3):**
- `#3808` listing is live on OKX.AI with a **frozen x402 contract**: `POST /scan` = 0.01 USDT, `POST /audit` = 15 USDT, both endpoints also answer `GET` with a 402 challenge (Phase-3 fix). **Do not change the route paths, price fields, or response envelope shape** (`ScanRequest`/`ScanResponse`/`AuditResponse` in `warden/models.py`) — only widen detection logic and add fields additively.
- Every item below ends at a ▸Claude-audit gate. Do not deploy or touch the VPS — that's ops-owned.
- Run `python -m pytest -q` and `ruff check .` before calling anything done. Current baseline on `phase3-hardening`: 57 tests, ruff clean.

---

## Item 1 — Detection-engine recall gaps

Verified against current code (not assumed):

**1a. `warden/analyzers/drain_address.py:10-12`** — `TRANSFER_INTENT_RE` is a 9-verb allowlist:
```python
r"(?i)\b(send|transfer|pay|deposit|withdraw|recipient|payment|funds|to address)\b"
```
Misses common redirect phrasing: "move the holdings to 0x…", "redirect proceeds to…", "payout wallet is…", "route funds to…". Add: `move`, `redirect`, `payout`, `route`, `wallet`, `receiving address`. Keep it a single regex (perf-sensitive, this analyzer runs on every `/scan` call) — just extend the alternation. Add regression cases to `tests/` (there's an existing test file for this analyzer — extend it, don't create a parallel one) covering each new verb with both a benign sentence (verb present, no address) and an attack sentence (verb + address) to confirm no over-triggering.

**1b. `warden/scanner/patterns.py:17-23`** — `role_override` category only matches 5 rigid phrasings ("you are now a…", "act as…", "pretend…", "your role is…", "developer mode enabled"). Reworded overrides slip through: "from now on, respond as…", "ignore all prior instructions and become…", "switch persona to…", "system override:". Add 3-4 more patterns to the same list, each with a corpus test case (`warden/scanner/patterns.py` also has `KNOWN_INJECTIONS` — add the new phrasings there too so Layer-3 TF-IDF similarity also benefits when `depth="thorough"` is requested).

**1c. `warden/scanner/patterns.py:24-25`** — `web3_specific` only catches `transfer|approve|swap ... all tokens/funds/balance`. Same redirect-verb gap as 1a. Extend the alternation with `move|redirect|route` to match.

**Do NOT touch:** `depth` default (`"fast"` in `warden/models.py:26` and `warden/engine.py:30`) or Layer 4 (`ai_analyzer=None` stub in `warden/engine.py:19`) — those are known, documented, out of scope for this pass (no LLM budget/infra for the hackathon window).

**Verification for this item:** after the pattern changes, re-run the existing attack/benign corpus test suite and report before/after pass counts. If you have time, write a short adversarial script (not committed, just for your own check) that paraphrases 10-15 known attacks and confirms recall improved — mention the delta in your handoff notes, don't invent a precise recall percentage without measuring it.

## Item 2 — Badge/consent polish

Verified against current code:

**2a. `site/badge.js:60-65`** — the summary line-list (`Audit ID`, `Target`, `Grade`, `Score`, `Blocked`, `Issued`) omits `consent_verified` even though `AuditResponse.consent_verified` (`warden/models.py:102`) is already in the payload and defaults `True`. For an audit badge whose whole point is trust, silently omitting whether target consent was checked undercuts credibility. Add a line: `line("Consent verified", badge.consent_verified ?? "unknown")` (confirm the actual key name badge records serialize under — check `warden/badges.py`/`warden/badge_store.py` for the exact field name before wiring it, don't guess).

**2b.** Check `warden/badges.py` for what fields actually get persisted into the signed badge record vs. what's only in the live `AuditResponse` — if `consent_verified` isn't part of the signed payload itself (only the live response), note that as a finding rather than silently patching around it; that's a design question (should consent status be part of what's cryptographically attested?) worth flagging back to me, not deciding unilaterally.

**Do NOT touch:** `WARDEN_REQUIRE_CONSENT` env default (`false` — deliberately kept off for hackathon outreach scanning per prior decision) or `WARDEN_BADGE_SECRET` (already rotated to a real 64-char secret on the VPS, do not regenerate/change signing logic).

---

## Out of scope (do not build)
- LLM Layer 4 wiring, TF-IDF default-on, rate-limiter/SSRF (already done, `d11e939`), A2A escrow, monitoring/ToS, anything touching `/scan` or `/audit` request/response shape beyond additive fields.

## Handoff format
Same as Phase 2/3: PR-style summary, list of files touched, test counts before/after, and any findings you flag rather than fix (e.g. the 2b consent-attestation question).
