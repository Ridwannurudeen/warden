# Warden — 12-Month Roadmap (Jul 2026 → Jul 2027)

Warden goes mainstream after the OKX.AI Genesis Hackathon as the **trust & payload-security layer for the agent economy** — starting on OKX.AI (Agent ID #3808, X Layer, x402 pay-per-call) and expanding to every x402-settled marketplace.

## Why this roadmap is shaped this way (verified platform alignment, Jul 2026)

- OKX.AI = two marketplaces (Agent + Task), settled in USDT/USDG over OKX's **Agent Payments Protocol (APP)** on X Layer; Warden's pay-per-call A2MCP model sits squarely in the "instant pay-per-call / standardized services" lane OKX describes. (okx.com/learn/okx-ai; The Block, Apr 29 2026)
- OKX **outsources trust to partners** (CertiK for security assessment, GenLayer for disputes) rather than owning it — an ASP that *is* security infrastructure fits the platform's model. There is **no published ASP payload-security standard yet**; Warden fills an unaddressed gap (not a stated OKX requirement — don't overclaim).
- OKX structurally rewards **staying live** (eligibility requires remaining listed), **on-chain reputation accrual** (one identity, every tx counts), and **real user value** over demos.
- APP is designed to be **chain-agnostic** (Base, Ethereum, Solana, Sui, Aptos, Optimism named); **x402** is now a Linux-Foundation-incubated standard with Coinbase Agent.market, Solana, and Google AP2 settling through it — Warden's portability targets.
- Verified from the official Build X hackathon page (user-provided Jul 5): **$100k pool** — Best Product / Best Business Creativity / Highest Revenue each 10k/6k/4k USDT; **Best Software Service Award 2,500 USDT × 3** (Warden's registered category is SOFTWARE_SERVICES — a fourth, less-contested shot); Social Media Popularity 1,000 × 10. **Highest Revenue is scored on "revenue, orders, and positive reviews during the campaign period"** → real paid calls + reviews before Jul 17 count directly. Winners also get OKX PR + collaboration. Evaluator economics confirmed: ≥100 OKB stake, ≥5 evaluators per dispute, majority splits 5% of bounty + slashed stakes. OKX.AI join page verbatim: "One person. One company. A million dollars a year — powered by your agents" (no BTC pledge exists).
- Still unverified (do not cite): revenue-share %, OKX.AI-specific grant funds.

---

## Funded Gauntlet honeypot - design only, funding decision required

The future spectacle is an isolated agent with a real, deliberately losable wallet balance: break
its decision loop and keep the capped pot. This is **not implemented or funded** in Phase 5. A novel
jailbreak may defeat the model rather than the deterministic firewall, so the full balance must be
treated as marketing spend that can be lost on the first attempt.

Before activation, the user must approve a fixed loss budget. The build then needs all of these
controls together:

- a dedicated agent identity, wallet, host, and model account with no access to Warden production;
- one non-refillable pot capped at the approved loss budget, with no treasury approvals or secrets;
- an explicit public ruleset defining a valid exploit, payout finality, finder credit, and exclusions;
- full prompt, tool-call, firewall-verdict, and transaction capture with sensitive fields redacted;
- a manual arming step, time-boxed campaign window, balance alarm, and immediate kill switch;
- independent review of every apparent bypass before publishing it or adding a credited regression;
- a detection fix and a failing-then-green corpus test shipped with each confirmed bypass.

No on-chain contract, funded wallet, LLM loop, or payout automation should be built until that loss
budget and operating rules are approved.

---

## Phase 0 — Hackathon close-out (Jul 2026)

- [ ] `git init` + push to public GitHub (makes README CI claims true; submission artifact)
- [ ] Add LICENSE (Apache-2.0)
- [ ] Record ≤90s demo video; post #OKXAI thread; submit Google Form (user-owned, approval-gated)
- [ ] Pass listing review; if rejected, same-day fix + re-activate (buffer to Jul 17)
- [ ] Rotate OKX Dev Portal API key post-event
- [ ] **Campaign-window revenue push (scores Highest Revenue + seeds reviews):** offer pre-review scans/audits to other #OKXAI entrants on X — every paid order from a distinct entrant wallet counts as revenue + orders + potential positive review during the judged period
- [ ] Target the category prize: Warden is listed under Software Services → explicitly pitch for **Best Software Service Award** in the X thread and form

## Phase 1 — Production trust floor (Q3 2026: Aug–Sep)

Goal: an ASP a stranger can safely pay. Reliability is what OKX's eligibility + reputation model rewards.

- **Rate limiting + abuse controls** on `/scan`, `/audit`, `/health` (pre-402 processing is currently unmetered)
- **Observability:** structured logging, error tracking, external uptime probe, multi-worker uvicorn; publish an uptime page
- **Terms of Service + privacy/retention policy** (scanned payloads may contain secrets — state zero-retention)
- **audit_agent consent gate:** target must prove ownership (well-known file or signed header) before the attack battery fires — closes the "pay 15 USDT to attack a third party" hole
- **Signed, verifiable badges:** audit reports get an ID + server signature + public lookup endpoint (`/badge/{id}`); marketplaces and buyers can verify "Warden-audited" claims
- **Corpus pipeline v1:** versioned detection rules; monthly ingestion of newly published injection taxonomies; regression CI stays zero-flake

## Phase 2 — Detection depth + integration surface (Q4 2026: Oct–Dec)

Goal: raise the ceiling above deterministic regex (paraphrase-resistant) and cut integration cost to near zero.

- **LLM layer 4** (opt-in `depth="thorough"`): LLM judge with canary tokens; hard rule preserved — LLM may escalate but never downgrade a deterministic BLOCK
- **Adversarial red-team loop:** quarterly internal attack sprints against Warden's own analyzers; bypasses become corpus entries
- **Client SDKs:** Python + TypeScript one-liners that handle x402 pay-and-replay; open-source MCP-proxy wrapper (transparent firewall mode) as the GitHub distribution play
- **Feedback flywheel:** opt-in reporting of real-world scan hits → anonymized corpus growth → published quarterly threat report (content marketing + credibility)
- **OKX reputation compounding:** volume pricing/subscription tier via APP pay-as-you-go modes; keep dispute rate at zero

## Phase 3 — Marketplace expansion (Q1 2027: Jan–Mar)

Goal: Warden wherever x402 settles. OKX first, never OKX-only.

- **Coinbase Agent.market listing** (x402 on Base — same payment standard, minimal port)
- **Solana x402 + Google AP2** endpoints (APP itself is chain-agnostic; follow OKX's named expansion chains)
- **A2A escrow audit tier on OKX.AI** (the deferred premium: negotiated deep audits with evaluator-backed sign-off; requires ~100 OKB stake — fund from Phase 1–2 revenue)
- **Pre-listing audit partnerships:** pitch marketplaces (OKX, Agent.market) on "Warden-audited" as an optional listing signal; publish an open **ASP Payload Security Standard** draft — become the reference the platforms lack
- **Evaluator alignment:** register as/partner with staked evaluators so audit reports carry weight in GenLayer-style dispute flows

## Phase 4 — The security layer, not a scanner (Q2 2027: Apr–Jun)

Goal: recurring revenue; "Cloudflare for agent commerce" positioning.

- **Warden Shield subscription:** continuous monitoring for listed ASPs — scheduled re-audits, drift alerts when an endpoint's defenses regress, badge auto-renewal
- **Runtime firewall SaaS:** hosted transparent proxy tier (agents route inbound content through Warden by config, not code)
- **Threat-intel API:** sell the compounding attack corpus as a feed (the moat: every scan makes the corpus better)
- **Grant/partnership push:** OKX PR channel (hackathon reward), x402 Foundation ecosystem, CertiK-adjacent positioning — Warden covers payload/prompt-injection, CertiK covers wallet/token; complementary, not competitive
- **OPC milestone tracking:** public revenue dashboard aligned with OKX's one-person-company narrative

---

## KPIs by quarter

| Quarter | North star | Targets |
|---|---|---|
| Q3 2026 | Trust floor | 99.5% uptime, ToS live, signed badges shipped, 0 disputes |
| Q4 2026 | Detection depth | LLM tier live, 2 SDKs, corpus 2× with 0 false positives |
| Q1 2027 | Distribution | 2+ non-OKX marketplaces, A2A tier live, standard draft published |
| Q2 2027 | Recurring revenue | ≥30% revenue from subscriptions, threat-intel feed launched |

## Standing constraints

- Deterministic core stays LLM-free and zero-flake — the corpus CI gate is permanent
- Never claim OKX requires audits (it doesn't, per available sources) — sell insurance against an *unpublished* review bar
- Deploys stay additive on shared infra until revenue justifies dedicated hosting
- Prices on-chain are frozen per listing; price changes go through `agent update`, never silent divergence
