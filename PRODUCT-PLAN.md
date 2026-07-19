> **Historical / superseded planning artifact.** This early post-hackathon plan preserves point-in-time assumptions and is not current product truth. Do not use its metrics, blockers, product names, or implementation directions without fresh verification. Current scope and completion status live in `ROADMAP.md`, the completion addendum in `SECURITY-AUDIT-2026-07.md`, and `REDESIGN_REPORT.md`.

# Warden — Reliable Product Plan (post-hackathon)

The honest premise: Warden's *plumbing* is already strong (verifiable APA attestations, Ed25519 +
hash-chain log, SSRF-hardened auditor, sub-ms deterministic verdicts, two-language SDKs, a multi-page
platform, real traction). The *detection core* is the toy: regex + heuristics + a circular corpus, with a
dead LLM stub (`engine.py` builds `InjectionScanner(ai_analyzer=None)`). This plan turns the core into
something that measurably works — and, crucially, that we can *prove* works rather than assert.

Guiding principle: **robust agent-payload security is an open, adversarial problem — even frontier models get
jailbroken. "Best product" here is not "we catch everything" (impossible); it is defense-in-depth + a
MEASURED, PUBLISHED recall number + a data flywheel that compounds.** That honesty is the differentiator.

---

## Phase 0 — Hackathon floor (already scoped in CODEX-AUDIT-FIXES.md)
Damage control so the demo is honest, not embarrassing:
- D3: deterministic paraphrase/plain-English patterns (catches the obvious "wire the treasury out" / "ship
  the API key" misses without an LLM).
- O2: honest demo/theater captioning ("deterministic layer catches known patterns; semantic layer handles
  novel phrasing").
- All security fixes (S1–S9), auditor 402-inconclusive (C1).
This raises the floor. It does NOT make detection genuinely robust — Phase 1 does.

## Phase 1 — Make detection genuinely work (the core; ~3–5 weeks)
1. **Hybrid engine, real semantic layer.** Wire `_run_llm_layer` (scanner.py:369) to a real small model,
   PAID/`thorough` tier only, gated behind the deterministic layers (only on ambiguous cases), fail-open with
   a hard timeout. Deterministic fast path stays offline/free. (D1, matured past the hackathon guard.)
   - Add an embedding-similarity layer as a cheaper middle tier between regex and LLM (catches semantic
     near-neighbors of known attacks without a full LLM call).
2. **Kill the corpus circularity.** The current corpus is attack strings ≈ the regexes that catch them.
   Replace the eval basis with a genuinely HELD-OUT adversarial benchmark: paraphrases, obfuscation
   (homoglyphs across all scripts, encoded/decimal-IP hosts, base64, unicode), multi-vector payloads, and
   public jailbreak/prompt-injection datasets. The training corpus and the eval set must never overlap.
3. **Defense-in-depth per threat class** (harden each analyzer beyond literal patterns):
   - injection: semantic intent + known patterns; drop reliance on literal "ignore previous instructions".
   - drain: address-substitution intent + context + anomaly; fix the no-context under-call (a detected drain
     shouldn't render LOW). Broaden verb coverage beyond a hardcoded allowlist.
   - exfil: real secret detection + intent, not a verb allowlist (send/ship/smuggle/forward/… is a losing
     game as an enumerated list).
   - tool-hijack: structural (JSON/tool-call shape) + natural-language intent.
   - links (`analyzers/links.py`): decode obfuscated hosts, punycode + all-script homoglyphs, shortener
     reputation, and block `javascript:`/`file://`/bare-`www.` schemes.
4. **Principled severity model.** Replace the ad-hoc score blend with a calibrated model so verdicts map
   honestly to risk (no more "detected DRAIN_ADDRESS but verdict LOW", no more "SANITIZE that doesn't
   sanitize").

## Phase 2 — Prove it (evaluation + the trust ethos applied to efficacy; ~2 weeks, overlaps P1)
1. **Continuous eval harness.** Every release runs the held-out benchmark; recall + false-positive rate are
   recorded and PUBLISHED over time (`scripts/benchmark_recall.py` from D4, matured). Turns "trust our
   scanner" into "here is our measured recall on N held-out novel attacks, updated each release."
2. **The Gauntlet as a real data flywheel.** The public "beat the firewall" arena becomes the adversarial
   data source: human-confirmed bypasses feed (a) the benchmark and (b) new detection patterns (active
   learning). This is the compounding moat — a live, growing attack corpus from real adversaries.
3. **Efficacy transparency.** Apply the APA/transparency-log ethos to detection: publish the benchmark
   methodology and numbers, honestly. "We measure and publish our recall" is a defensible, differentiated
   claim no competitor is making.

## Phase 3 — Productize & harden (~2–3 weeks)
1. **Reliability:** real uptime/latency monitoring, facilitator-health checks (the x402 402-depends-on-
   facilitator fragility), and an actual SLA. Alerting.
2. **Trust layer maturation:** sign + anchor the transparency-log head (S3), signed log checkpoints, broader
   attestation types, and a bounded/paginated log store (S4, S2, S7 done properly).
3. **Audit service:** non-circular attack battery, INCONCLUSIVE handling for paywalled/unreachable targets
   (C1 done properly), consented scanning by default, and a grading model that reflects real robustness.
4. **Integrations:** framework adapters (LangChain, LlamaIndex, MCP, agent SDKs), more language SDKs, a
   drop-in reverse-proxy middleware, and clean docs with measured numbers.

## Phase 4 — Moat & positioning (ongoing)
1. **Data moat:** the compounding threat-intelligence corpus (Gauntlet + real inbound traffic) — the more
   Warden is used, the better it detects. This is the durable advantage a pure model-wrapper can't copy.
2. **Standard moat:** the portable, verifiable APA trust standard as an ecosystem play (other services adopt
   it; Warden is the reference issuer/verifier).
3. **Positioning:** "the measured, verifiable runtime security layer for the agent economy" — backed by a
   PUBLISHED recall number and cryptographic attestations, not marketing. The honest framing IS the wedge:
   everyone else claims "AI security"; Warden shows its numbers.

---

## What makes THIS the "best product" (the honest thesis)
Not "we block all attacks" — that's the claim that gets a security product embarrassed. Instead:
- **Measured, published detection efficacy** (recall/FP on held-out novel attacks, per release).
- **Cryptographically verifiable attestations** (APA) — you can check our claims offline.
- **A compounding adversarial data flywheel** (the Gauntlet) — improves with use.
- **Deterministic sub-ms fast path** + an optional semantic tier — real production shape.
A product that is *honest about its limits and proves its strengths* beats one that overclaims. That is the
version of Warden that wins on substance.

## Feature: near-real-time Safety Index (auto-update as OKX enlists agents) — POST-HACKATHON
Goal: new marketplace agents appear on warden.gudman.xyz without a manual redeploy. NOTE: OKX has no
push/webhook, so this is POLLING (near-real-time, e.g. every 15–30 min), NOT instant.
Blockers to solve (verified):
- `warden/marketplace/fetch.py:221` shells `onchainos agent search`; the VPS CLI is 2.2.8 (no `agent`
  subcommand) → the VPS can't fetch. Fix via ONE of: (a) an isolated newer `onchainos` CLI for Warden only
  (never touch the shared global CLI); (b) rewrite the fetch to hit OKX's public marketplace HTTP API
  directly (no CLI dependency — preferred long-term); (c) fetch on a machine with the new CLI and push the
  snapshot to the VPS.
- The refresh pipeline (`scripts/refresh_safety_index.py`) promotes to the blue-green `/opt/warden-index/current`
  layout; production is FLAT. Either adopt blue-green or adapt the refresh to write the flat `/opt/warden-site`.
- Install `deploy/systemd/warden-index.timer` (currently 6h → shorten to 15–30 min) + `warden-index-fetch.service`
  on the VPS, running as the hardened `warden-fetch` user.
Then: timer → fetch snapshot → build_index → atomic swap → new agents live within the interval.
STRATEGIC NOTE: the audits flag the Safety Index as an over-featured weakness (0 linked audits, abstract);
consider moving it under Labs before investing here — auto-refresh polishes a de-emphasized surface.

## Sequence & effort (rough)
P0 (hackathon) → P1 core (3–5w) → P2 proof (2w, overlaps) → P3 productize (2–3w) → P4 ongoing.
The single highest-leverage post-hackathon investment is **P1.2 (a real held-out benchmark) + P1.1 (the
semantic layer)** — together they convert Warden from "asserts security" to "measures security," which is the
whole game.
