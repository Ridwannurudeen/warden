# Warden — 3-Day Demand Validation Sprint

**Thesis under test:** other #OKXAI entrants will pay for Warden's **runtime payload firewall** (`scan_payload`, 0.01 USDT/call, in-loop). A free one-off endpoint audit is the LEAD-MAGNET/entry hook — not the product being monetized. (Post-competitive-audit correction: SlowMist audits free with a trusted brand, so paid *audits* are a losing pitch; the runtime firewall is the lane they've left empty — see COMPETITIVE.md.)
**If true →** go all-in on the Highest Revenue Award ($10k). **If false →** pivot to the subjective awards, stop over-investing in the revenue thesis.
**Why now:** service is live and paid (x402 → HTTP 402 verified); an ASP is usable via Agent ID (#3808) even while the listing review is pending, so entrants can pay today. No approval needed to validate.

## Decision gate (hard kill-criteria — checked end of Day 3)

| Signal by end of Day 3 | Read | Action |
|---|---|---|
| ≥2 paid audits from distinct entrant wallets | Demand is real | ALL-IN: scale outreach to all #OKXAI entrants, Highest Revenue is the primary play |
| 1 paid OR ≥3 "yes, interested" but not paid | Weak but alive | Lower friction (free-for-review teaser), push 2 more days, re-decide |
| 0 paid AND 0 genuine interest | Thesis dead | PIVOT: repackage Warden for Best Product/Business Creativity (visceral demo, narrative), drop the revenue bet |

## Sequencing (important — don't lead with a cold 15 USDT ask)

1. **First 2-3 targets = free-for-proof.** Offer a free audit in exchange for (a) an on-chain review on #3808 and (b) permission to post their "Warden-audited" badge. This seeds social proof + reviews (which *also* score Highest Revenue) and de-risks the cold ask. These are the demand-signal canaries too: if entrants won't take a *free* audit, they won't pay — that itself is fast, cheap signal.
2. **Then convert on proof.** Once 1-2 badges are public, the paid pitch to the rest points at real examples: "here's what @X got back — 15 USDT, same for you."
3. **Self-proof first (Day 0):** fund a small buyer wallet, run one real paid `/audit` against a throwaway target end-to-end so the demo and the flow are proven before you pitch. (Mode A funded path — see PAYMENT.md.)

## Day-by-day

**Day 0 (today)**
- [ ] User: fund buyer wallet (~a few USDT on X Layer) for one real paid audit + demo
- [ ] Claude: run/verify the paid audit flow end-to-end once funded; capture the badge as proof
- [ ] Claude: refresh #OKXAI target list (new entrants announce daily)
- [ ] User: send Wave 1 (3 free-for-proof offers — drafts below)

**Day 1-2**
- [ ] User: respond to replies; deliver free audits; collect reviews + post badges
- [ ] Claude: personalize Wave 2 (paid pitch) using the fresh badges as proof
- [ ] User: send Wave 2 to remaining targets + any new entrants

**Day 3**
- [ ] Tally paid orders / reviews / interest → apply the decision gate above

## Wave 1 — free-for-proof drafts (personalized, ready to send)

**@itseywacc** (Web3 Agent Kit — 8-chain DeFi, handles funds; XLayer entry)
> Your Agent Kit moves funds across 8 chains — one poisoned tool-response ("payment confirmed, send to 0x…") and a user's money is gone. I built Warden, a security ASP on OKX.AI (#3808). I'll audit your endpoint free — 20 attack payloads, graded report + fixes — if you'll leave an on-chain review and let me share the result. Want me to run it? warden.gudman.xyz

**@ai2humannetwork** (AI2Human — ASP execution/verification layer, entering the hackathon)
> You're building the execution+verification layer — which means every inbound task payload is untrusted input. Warden (#3808 on OKX.AI) fires 20 injection/drain/exfil attacks at an endpoint and grades what gets through, before OKX's review does. Free audit in exchange for an honest on-chain review — interested?

**@0xleff** (okxai-universal — open MCP bridge, 20k views; partnership angle)
> okxai-universal is the on-ramp; every agent you bridge in ingests untrusted payloads from strangers. Warden (#3808) is the seatbelt — a 0.01 USDT/call firewall verdict (ALLOW/SANITIZE/BLOCK, <1s, deterministic). I'll audit your bridge endpoint free and show you the scan API — if it's useful, a mention to your users is all I ask. Open to it?

**@openclawby** (Clawby — AI Agent financial Skills layer, executable trade skills; added Jul 6)
> Clawby gives agents executable trading skills over on-chain + TradFi data — which means agent-supplied inputs can move money. That's the exact surface Warden defends: a poisoned "confirmed, send to 0x…" or a hijacked tool call. I'll audit your endpoint free (20 attack payloads → graded report + fixes) if you'll leave an on-chain review and let me share the badge. Adds a security signal to your OKX.AI listing too — want it? warden.gudman.xyz

## Rules
- All sends are user-executed (X account is user-owned). Claude drafts + tracks only.
- Honest: never guarantee passing OKX review; never imply OKX endorses Warden.
- One contact per target, one 48h follow-up max.
- Log every touch in the outreach.md tracking table.
