# Phase 5 Build Handoff — 2026-07-13

## Result

Phase 5 is implemented end to end on branch `phase5-web-platform`.

| Scope | Commit |
|---|---|
| Public demo API | `dae6ec8` |
| Marketplace security index | `17c2506` |
| Reviewable x402 hire flow | `ba266b8` |
| Public security Gauntlet | `ca93160` |
| Multi-page platform, badge registry, docs, status, and final hardening | `72a631d` |

No deployment, VPS change, marketplace write, paid call, on-chain write, social post, or submission was performed.

## Built

1. **Public demo API**
   - Added the rate-limited, fast-only `POST /api/demo/scan` route and curated examples.
   - Enforced a 4,000-character payload cap, 20-address context cap, and a limiter independent from the paid routes.
   - Kept the production `/scan` and `/audit` contracts and x402 boundary unchanged.

2. **Marketplace security index**
   - Added read-only CLI snapshot collection, deterministic public-text indexing, static generation, filters, and per-agent pages.
   - The committed snapshot contains 375 agents fetched at `2026-07-13T14:33:39Z`: 2 public-text pattern matches and 0 independent audits.
   - Generated `site/agents/` pages remain ignored and are rebuilt with `scripts/build_index.py`; the smaller 11-page reason-code documentation set is committed.
   - Future badge attachment requires an explicit reviewed `auditId` → `agentId` entry in `data/marketplace/badge-links-v1.json`, a valid badge signature, and a matching listed-service host. Hostname inference alone is not treated as ownership proof.

3. **Reviewable x402 hire flow**
   - Added six verified OnchainOS task commands for task creation, provider attachment, x402 payment, completion, and task-linked feedback.
   - Validates live 402 terms against the selected endpoint, X Layer network, USDT asset, and exact atomic amount.
   - Keeps signing in the operator's configured CLI wallet and locks completion/review until the operator confirms the verdict.
   - Rejects self-review identities, including equivalent IDs with leading zeroes.

4. **Public Gauntlet**
   - Added real fast-path attempts, aggregate stats, a concurrency-safe JSONL review queue, and a human-review-only candidate policy.
   - Only the first unique ALLOW candidate retains raw payload/context/intent/finder data. Detected attempts and duplicate candidates retain hashes and verdict metadata only.
   - Claim deduplication excludes ignored context and canonicalizes verdict-relevant address lists, preventing equivalent submissions from retaining raw data twice.
   - The funded pot remains a roadmap design; no wallet or automated payout logic was added.

5. **Multi-page web platform**
   - Added real routes for landing, playground, agents, Gauntlet, hire, badges, 11 reason-code docs, integrations, status, privacy, and terms.
   - Added light/dark themes, responsive navigation, mobile agent cards, keyboard focus states, local/system fonts, and no external auto-loaded resources.
   - Added a public badge registry plus single-badge verifier, shared generated-page shell, honest live reachability status, corpus fingerprint, dated marketplace facts, and payment-evidence boundaries.
   - Added strict self-only CSP and explicit nginx routing with no SPA fallback.
   - Updated README, payment documentation, demo script, X draft, and deploy runbook.

## Verification

- `python -m pytest -q` — **127 passed**; one non-failing Starlette `TestClient` deprecation warning from the installed dependency stack.
- `python -m ruff check .` — clean.
- `node --test tests/js/*.test.js` — **16 passed**.
- `npx --no-install prettier --check "site/*.js" "tests/js/*.js" site/styles.css` — clean.
- `python scripts/build_site.py` — generated the documentation index and 11 reason-code pages.
- `python scripts/build_index.py` — indexed 375 agents, 2 public-text matches, 0 independent audits.
- Static site tests verify the CSP/no-external-resource property, required routes, shared navigation, light/dark/mobile CSS, JavaScript syntax, dated metadata, and absence of stale service/listing copy.
- Regression tests verify the frozen `/scan` and `/audit` methods and request/response fields.
- Local `nginx` is not installed, so source-level route/CSP tests passed but `nginx -t` remains an approved-deploy step.
- Visual browser QA could not be run because no in-app browser was connected. Static layout, accessibility, responsive, and JavaScript checks passed; visual desktop/mobile review remains an operator step after a browser is available.

## Verified facts versus dated facts

- The 375-agent marketplace data, listing state, service IDs, and 402 terms are dated 2026-07-13 snapshots. The marketplace is volatile; later public claims must refresh them.
- Current snapshot service IDs are `31669` and `31670`. The brief's `18954` and `18955` references were stale.
- The corpus is 92 attacks plus 30 benign guards, 122 cases total. Earlier 88-case and test-count references were stale.
- The corpus build fingerprint is `sha256:6d5bff99dac7364761796ef6c6da214f0c3cac13e1d3171033c4fad0168be83a`.
- The repository contains no full transaction hash proving a specific Warden purchase. `/status` therefore links only to settlement-address activity and explicitly says it is not transaction-specific payment proof.
- Historical uptime is not measured. `/status` reports only whether `/health` answers the current browser.

## Deliberate deviations and limits

- Marketplace pages render local initials and provide an outbound avatar source link. They do not auto-load marketplace avatars, preserving the no-external-request requirement. A verified personalized OKX listing URL was not available in the snapshot, so pages link to OKX.AI with the agent ID to search rather than inventing a direct route.
- The optional injected-wallet direct-payment flow was not built. It cannot create the task required for buyer feedback, while the implemented task flow can.
- Gauntlet JSONL reads are intentionally simple and concurrency-safe for the current single-service scale. Reads become linear with retained attempts; move counters and dedup indexes to a bounded database before high-volume public traffic.
- No generated agent HTML was committed. Refresh and regeneration are required before deploy, and VPS-side regeneration is required to include runtime badge records without copying the production signing secret locally.

## Operator-owned next steps

1. Review this branch and the dated marketplace/badge-link inputs.
2. After explicit approval, follow `deploy/DEPLOY.md`, including marketplace refresh, VPS-side badge-aware generation, `nginx -t`, and public browser smoke tests.
3. Record the demo, replace the security-index URL placeholder after deploy, and obtain explicit approval before posting or submitting anything.
