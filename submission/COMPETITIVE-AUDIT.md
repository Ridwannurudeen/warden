# Warden — Competitive Audit (live marketplace sweep, 2026-07-15)

Source: full `onchainos agent search` sweep of the OKX.AI marketplace via Warden's own `marketplace/fetch.py`.
**744 agents** captured with real `soldCount` / `feedbackRate` / category. This is measured data, not memory.

## Market shape
| Category | Agents |
|---|---|
| SOFTWARE_SERVICES | 505 (68%) ← our category, most crowded |
| FINANCE | 103 |
| LIFESTYLE | 73 |
| ART_CREATION | 44 |
| WORLD_CUP | 15 |

**Traction is heavily concentrated and dominated by DATA/YIELD, not security:**
| Agent | Sold | Rate | What it is |
|---|---:|---:|---|
| CoinWM Open API #3118 | 1559 | 100 | market-data API |
| CoinAnk OpenAPI #2013 | 1480 | 100 | market-data API |
| Onchain Data Explorer #2023 | 944 | 92.9 | on-chain data |
| Newsliquid #2135 | 390 | 100 | news/data |
| Barker Yield Agent #2012 | 340 | 100 | yield |
| Otto AI #2118 | 220 | 100 | yield/idle-capital |
| **Agent Output Verifier #4451** | **190** | — | **verifies agent deliverables vs schema/claims** |
| **CertiK #1965** | **87** | 100 | **paid gateway to CertiK Token Scan / Skynet** |

**Warden #3808: sold 13, rate 4.75.** We are *not* going to out-*volume* the data APIs in the campaign window —
so **Revenue Rocket is not our track.**

## The security / trust lane (our lane) — crowded, fragmented, mostly zero-traction
| Agent | Sold | Job (verified from description) |
|---|---:|---|
| **Agent Output Verifier #4451** | 190 | Checks another agent's deliverable vs expected schema/claims/evidence → accept/remediate/reject. *Correctness verification, after the fact.* |
| **CertiK #1965** | 87 | Paid HTTP gateway to CertiK Token Scan / Skynet Score. *Token/contract risk. Brand.* |
| Onchain Shield #1718 | 16 | Wallet authorization-risk / counterparty scoring (consumer wallet). |
| QTrade Guard / MarginGuard / Degen Safety #3775 | 4–9 | Trade / margin / token risk. |
| SlowMist Agent Security #2155 | 3 | Free brand-trusted one-shot audits. |
| **Agent Trust Layer #4453** | 3 | Scores agent fit/trust/price for buyer/router agents. *Advisory trust-scoring, not protection.* |
| ~25 more (ShieldSuite, ContractGuard, RouteRiskFirewall, TxGuard, PreTradeGuard, AttestVerify, SecureAudit AI …) | 0 | Single-shot scanners; no traction. |

## The gap NOBODY fills (Warden's uncontested position)
Cross-referencing all of the above, **not one competitor is a deterministic, real-time, in-the-loop payload
firewall.** They are one of: (a) token/contract risk scanners, (b) after-the-fact deliverable/correctness
checkers, (c) advisory trust-scorers, (d) consumer wallet scanners. None screens an *untrusted payload at the
moment of action* with a sub-millisecond ALLOW/SANITIZE/BLOCK. That lane is **empty and it's ours.**

And critically: **not one of them offers**
1. a **drop-in SDK** so any of the other 743 agents can be protected in one line, or
2. a **cryptographically-verifiable "Protected by Warden" badge** (per-ASP Ed25519 attestation), or
3. a **live marketplace-wide safety index**.

## How we counter each real threat
- **vs Agent Output Verifier (190 sold):** they verify *correctness* of a deliverable *after* it's produced. We
  prevent *adversarial threats* (injection, drain, exfil, hijack) *before* the agent acts — deterministically,
  in-loop, sub-ms. Different, higher-stakes job, and we're *adoptable by every agent* via SDK, not called ad-hoc.
- **vs CertiK (brand, 87):** they scan tokens/contracts (a gateway to their existing product). We secure the
  agent's *runtime payloads* — a different, unserved layer — and we're **verifiable + open-source**, not a
  closed brand gateway.
- **vs Agent Trust Layer / SlowMist / scorers:** they *advise* ("this agent scores X"). We *prevent* and
  *cryptographically prove* protection. Active infrastructure, not an opinion.
- **vs the 25 zero-sold guard/shield agents:** each is one scanner. We are the **fabric** they could all plug
  into — the network effect none of them has.

## Award positioning (refined by the data)
- **PRIMARY → Creative Genius ($10k):** the field is data APIs, yield bots, and single scanners. The
  **verifiable trust *fabric* of the agent economy** — a per-ASP cryptographic "Protected by Warden" badge + a
  one-line SDK any agent adopts + a live marketplace safety index — is the most *imaginative, category-defining*
  idea in the marketplace, and it's execution we control. We can't out-traction the data APIs, but we can
  **out-invent the entire field.** This is our best 10k shot.
- **SECONDARY → Best Product ($10k):** highest completeness/UX/value — award-grade site, live interactive demo,
  SDK, verifiable badge, safety index, open source, real reviews + a real bug-fix feedback loop.
- **FLOOR → Software Utility (2.5k):** strong best-in-class Software Services entry.
- **Not our track → Revenue Rocket** (raw volume race we can't win in the window).

## The build that wins it
The **Warden Trust Layer** (spec: `CODEX-TRUST-LAYER-BUILD.md`) is exactly this counter: the SDK (network
effect), the verifiable per-ASP badge (the novel primitive no one else has), and the live safety index (the
public good). Build it, lead the submission on Creative Genius, and Warden becomes the one entry that is
*infrastructure the whole marketplace can run on* — not another service competing inside it.
