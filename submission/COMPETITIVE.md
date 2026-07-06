# Warden — Competitive Audit: SlowMist Agent Security (#2155)

Verified on-platform 2026-07-06 via `agent search` + `agent get-agents` + `service-list` + one benign black-box probe.

## The incumbent (real one)

**SlowMist Agent Security #2155** — Listed & eligible. Backed by SlowMist, a globally-known blockchain security firm.
- 6 services, **ALL priced 0 USDT (free)**. salesCount **2**. No rating yet (securityRate null).
- Category SOFTWARE_SERVICES (same as Warden). Wallet `0x35d8…51a8`, endpoints `okxai.slowmist.ai/v1/review/*`.
- Services: (1) skill/MCP install malware, (2) GitHub repo audit, (3) URL/doc prompt-injection+phishing, (4) on-chain AML, (5) product/API/SDK security review, (6) social scam detection.

**Registry Scan #2182 (8004scan)** — ERC-8004 registry index, NOT a security scanner. Not a competitor. Ignore.

## Black-box architecture read (what's verifiable, no source access)

- Endpoints are **gated through the OKX call path** — a raw POST to `/v1/review/url` returns HTTP 000 after ~24s (no answer to unauthenticated direct calls); root is 404. Same gating shape as Warden.
- A raw POST timed out at ~24s — but that was **our own curl timeout (-m 20), NOT a measurement of their latency.** We have **no evidence** about their processing speed. Do not claim a latency edge until Warden's own live latency is measured and theirs is observed through the real call path.
- Their product is **framed** as one-shot reviews ("submit a URL/repo/address → get a report"), not a runtime per-call firewall — this is a positioning/taxonomy read, verifiable from their service descriptions, and does not depend on the timeout.
- **We cannot audit their code/infra** — closed hosted API. Anything beyond surface behavior is speculation.

## Full competitor map (verified across 4 search queries, 2026-07-06)

- **Payload / prompt-injection lane (Warden's actual lane): SlowMist #2155 is the ONLY overlap.** Confirmed across every query.
- **Token-risk / rug-check lane (different product, NOT Warden competitors):** Degen Safety Desk #3775 (contract/wallet risk snapshots, **sold 4**), RugRadar Mini #2910 (honeypot/tax/liquidity check, **0.1 USDT paid**, sold 0). These matter only as evidence that (a) paid security-adjacent services do list and (b) #3775's 4 sales > SlowMist's 2 — some buyers pay for security-adjacent value.
- Search is not exhaustive (marketplace has no full-list API confirmed); more may exist. But the injection/firewall lane is demonstrably thin.

## The two findings that actually matter

1. **You cannot out-brand SlowMist.** In security, trust is the product. A general "we're a better security scanner than SlowMist" fight loses hands-down — their name beats an unknown every time. **Trying to beat SlowMist at being SlowMist is the trap.**
2. **SlowMist priced everything at $0 → they are NOT competing for the Highest Revenue Award.** salesCount 2 × 0 USDT = **$0 revenue.** The revenue lane — the one Warden targets — is wide open. SlowMist ceded it.

## The threat this creates (must be honest)

Free, brand-trusted SlowMist offers overlapping **audit/review** services (their #3 URL-injection ≈ Warden scan; their #5 product review ≈ Warden `audit_agent`). **Warden's paid `audit_agent` (15 USDT) competes against "free, from a famous firm."** That pitch is weak. Do not build the revenue thesis on paid audits — SlowMist undercuts it.

## Where Warden wins — a lane SlowMist has NOT taken

None of SlowMist's 6 services is a **runtime, per-payload firewall in the agent loop.** They do periodic, human-firm-style audits. That is a different job from what Warden's `scan_payload` actually is. Reframe Warden accordingly:

**Warden is not a security-audit ASP. It is a runtime firewall primitive — the thing an agent wires into its loop and calls on every untrusted payload.**

Differentiators Warden can win on, cleanly, without touching SlowMist's brand advantage:

| Axis | SlowMist | Warden (defensible edge) |
|---|---|---|
| Job | one-shot audit ("review this URL/repo") | runtime firewall (scan every inbound payload, in-loop) |
| Latency | unknown (their speed NOT measured) | **measured: verdict compute p50 0.13ms / max 1.12ms over 118 payloads; end-to-end HTTP p50 2.54ms local. VPS figure not yet measured.** No LLM in the verdict path. |
| Integration | submit content, await report | **drop-in per-call** (0.01 USDT), fits high-frequency loop use |
| Verifiability | opaque report | **HMAC-signed, publicly verifiable badge** (already built) |
| Pricing model | free (no SLA, no revenue) | micro-fee per call → real revenue, scales with volume |
| Determinism | LLM/analyst judgment | published corpus, zero-flake, reproducible verdict |

## Derived positioning & minimal infra changes (NOT a rebuild)

The build is done; this is repositioning + small additive sharpening, not a new system.

1. **Reposition the pitch** everywhere (site hero, X thread, outreach): "the runtime payload firewall for agent commerce — deterministic <1s verdict, per-call, in your loop." Stop leading with "pre-listing audit" (that's SlowMist's free turf).
2. **Lead the demo with the runtime scan** (drain-address BLOCK in <1s), not the audit. The audit becomes a free-for-proof lead-magnet (seeds reviews/badges), the **runtime `scan_payload` is the monetized product.**
3. **Lean on the two things SlowMist structurally lacks:** verifiable signed badge (built) + deterministic low-latency verdict. **Measured 2026-07-06:** verdict compute p50 0.13ms / max 1.12ms over the 118-payload corpus; end-to-end HTTP p50 2.54ms (local, rate-limit off). Sub-millisecond compute is real and citable; measure the VPS figure (`measure_latency.py` on `/opt/warden`) before quoting a production number. Do NOT claim Warden is "faster than SlowMist" — their latency is unmeasured; claim Warden's own verified number instead.
4. **Do NOT chase breadth** (GitHub/AML/social — SlowMist has 6 categories, we can't match and shouldn't try). Win depth in ONE lane: payload firewall.
5. **Highest Revenue is still winnable** precisely because SlowMist is free — but revenue comes from **runtime scan volume**, not paid audits. Adjust the demand sprint pitch accordingly.

## Honest bottom line

"Beat SlowMist hands down" as a general security firm — not achievable, and the wrong goal. **Out-position them in the runtime-firewall lane they've left empty, and win Highest Revenue in the paid lane they've abandoned** — that is achievable and does not require beating their brand. The infrastructure is already built for it; the change is positioning + demo emphasis + pricing focus, not a new architecture.
