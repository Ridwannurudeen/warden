# Post-hackathon build — prioritized by SCORE IMPACT (build now)

Goal: lift award readiness before the deadline. Ordered so the biggest, safest score-movers ship first.
Same flow as the audit plan: build on the current branch, commit as you go, **do NOT deploy** — Claude audits
each phase and deploys under the user's approval.

## HARD CONSTRAINTS (all phases)
- Frozen `/scan` `/audit` request+response field sets byte-identical (`test_paid_http_contract_remains_frozen`
  stays green). No AI/Claude/Codex attribution (AI_USAGE.md already exists and is approved — don't duplicate it).
- A regression/UI test per change. Run the full suite (py/js/ts) + ruff; report real counts.
- Self-contained site (no external resource requests). Keep light + dark, black/gold/red brand.
- No deploy, no ssh/VPS/wallet/on-chain/network-to-external. Claude deploys.

---

## PH1 — Pre-Action Incident Console + lead-with-proof homepage  [BIGGEST SCORE-MOVER, low risk: site only]
Directly lifts Best Product ("experience/completeness/value") and kills the toy/fragmented look. No engine risk.
- Build ONE consequential journey on the homepage: **external agent output → a consequential action
  (payment/tool/secret/link) → Warden detects+explains → the action is visibly withheld or safely transformed.**
  Use the real free `/api/demo/scan` + `/api/demo/theater` so it's live, not mocked.
- **Lead with real proof** above the fold: 15 sold, 4.8/5, external reviews, Agent #3808 + a direct
  "Use Warden on OKX" link to the listing, median latency. Not the abstract Safety Map.
- **Demote experimental surfaces** (Safety Map/index, Gauntlet, APA badges, endpoint auditor) under a
  `Labs` / `Trust` section — keep them reachable, off the primary journey.
- **Fix number drift** across every surface (prices, corpus counts, sales, test counts) — one source of truth.
- Unify brand: black/gold/red; drop the purple/glass card-heavy look where it conflicts.
- **Accept:** homepage tells the one journey with a live verdict; proof is above the fold; experimental
  surfaces moved to Labs; numbers consistent site-wide; light+dark; no external requests (test asserts it).

## PH2 — Real semantic detection layer  [Best-Product detection lift — GATED, higher risk]
The `HttpSemanticAnalyzer` scaffolding exists (`warden/scanner/semantic.py`) but is disabled. Make it real.
- Wire it to a real model, **PAID `thorough` tier only**, gated behind the deterministic layers (ambiguous
  cases only), **fail-open** (error/timeout/missing-key → deterministic verdict, never 500, hard timeout),
  env-keyed, provider-neutral copy. Free/demo path stays deterministic (assert no LLM call there).
- Re-run the held-out benchmark; **only leave it ENABLED in config if recall clearly improves over 64% AND
  it's fail-open + fully tested** — otherwise keep the flag off and report the number.
- Principled severity calibration pass (fix any remaining "detected-but-LOW" / "SANITIZE that doesn't clean").
- **Accept:** benchmark recall reported before/after; fast path unchanged (tested); LLM failure →
  deterministic fallback (tested); frozen contract intact.

## PH3 — Continuous eval + Gauntlet data flywheel  [Creative-Genius / integrity support]
Turns "trust us" into "measured, published." Supports the honest-security thesis.
- A harness (`scripts/benchmark_recall.py` matured) that re-runs the held-out benchmark and writes a
  dated recall/FP record; a small public page or docs section that shows the current number honestly.
- Confirmed Gauntlet bypasses (human-reviewed) feed new held-out cases + patterns (active-learning loop).
- **Accept:** harness runs + records; a public surface shows the measured recall with methodology; a test
  proves confirmed bypasses append to the benchmark set (not the training corpus).

## PH4 — Security/ops completeness  [polish]
- **APA key rotation:** the issuer key was world-readable before it was locked — rotate it via a proper
  re-issue sequence (new key → re-sign live attestations → publish), documented; prefer `WARDEN_ISSUER_KEY`
  env. (Deploy/rotation is Claude+user-owned; provide the script + runbook.)
- **Transparency-log external anchoring:** S3 signs a log head; add publishing/anchoring of that signed
  checkpoint (e.g. a committed/public checkpoint file the verifier can pin) so a full rewrite is detectable.
- **Full CI gates:** ensure CI runs clean-wheel-install + all SDK suites + TS packaging + APA self-test.

## PH5 — Productize  [bigger, lower deadline-impact]
Monitoring/health + SLA surface; framework adapters (LangChain, LlamaIndex, MCP already present); more
language SDK polish; a drop-in reverse-proxy middleware. Build if time remains after PH1-PH4.

## PH6 — DEFERRED / BLOCKED (do last or post-deadline)
- **Near-real-time Safety Index auto-update:** BLOCKED — the VPS `onchainos` CLI (2.2.8) can't fetch agents;
  needs an isolated newer CLI OR a direct OKX marketplace HTTP API rewrite of `warden/marketplace/fetch.py`.
  Also the audits say de-emphasize the Safety Index — LOW priority. Do the fetch-API rewrite only if PH1-PH5 done.
- **Phase 4 moat** (compounding threat-intel corpus, broader APA-standard adoption) — ongoing, not a task.

---
## Build order
PH1 (do first — biggest safe win) → PH2 (gated) → PH3 → PH4 → PH5 → PH6.
Commit per phase; Claude audits + deploys each before you start the next high-risk one.
