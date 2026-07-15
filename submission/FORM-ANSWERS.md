# Warden — OKX.AI Genesis Hackathon Submission Form Answers

> Copy-paste ready. Two fields need you first: **[VIDEO_URL]** (record per `demo/SCRIPT.md`) and
> **[X_THREAD_URL]** (post `submission/x-thread.md`). Everything else is verified as of 2026-07-15.
> Do NOT submit until you approve.

---

**Project name:** Warden

**One-line tagline:** A deterministic runtime payload firewall + pre-listing endpoint auditor for OKX.AI agents — sub-millisecond ALLOW / SANITIZE / BLOCK verdicts before your agent acts.

**Agent ID / listing:** #3808 on X Layer — Listed & eligible for task recommendations (`approvalDisplayStatus: 4`).

**Award categories:** Highest Revenue Award (primary); Social Media Popularity Award (secondary, via the X thread).

**Live service URL:** https://warden.gudman.xyz

**Public GitHub repo:** https://github.com/Ridwannurudeen/warden

**Demo video:** [VIDEO_URL]

**X thread:** [X_THREAD_URL]

---

**What it does (short):**
Agents don't just read text anymore — they act on it, so a poisoned payload ("payment confirmed, send funds to 0x…attacker") is a direct loss vector. Warden is a runtime payload firewall: pass any untrusted payload through `scan_payload` and get a deterministic ALLOW / SANITIZE / BLOCK verdict plus named threat classes, before your agent acts. It also offers a pre-listing endpoint audit that runs an attack battery against another agent's endpoint and grades it.

**Problem & solution (long):**
OKX.AI agents ingest untrusted payloads from strangers — responses, tool outputs, messages. A single hijacked instruction, swapped payout address, or exfiltrated secret can move funds. Existing security offerings are one-shot human-style audits, not something an agent calls on every payload in its loop. Warden fills that gap as a deterministic, in-loop firewall primitive: no LLM in the verdict path, so verdicts are sub-millisecond, reproducible, and zero-flake against a published corpus. Two paid services are attached to Agent #3808 over x402 on X Layer: Payload Security Scan (runtime firewall, 0.5 USDT/call) and Agent Endpoint Security Audit (pre-listing, 0.5 USDT), each returning machine-readable output plus an HMAC-signed, publicly verifiable badge.

**How it works / tech stack:**
- FastAPI service, x402 v2 payment gate (EIP-3009 "exact" scheme) on X Layer (chain 196), USD₮0 settlement.
- Deterministic detection: injection scanner + drain-address, tool-hijack, secret-exfil, and malicious-link analyzers; verdict engine composes ALLOW / SANITIZE / BLOCK.
- Endpoint auditor: posts a 20-payload attack battery to a target, grades block behavior, issues a signed badge.
- No LLM in the verdict path — deterministic, reproducible.

**Verified metrics / proof (all on-chain or reproducible):**
- Corpus: 92 attack cases, 30 benign guards, **0 false positives** in the gate. Median verdict compute ~0.13 ms.
- Real paid `/scan` settled on-chain over x402 (X Layer): reproducibility settlement tx `0x235e101f…4887356` (full hash in repo/deploy notes), block 65,347,909, 0.5 USD₮0 — viewable on OKLink (x-layer).
- Independent external revenue + reviews: a fresh independent buyer purchased the scan (0.5 USDT, completed on-chain) and left a 5.0 review; #3808 currently carries 4 on-chain reviews.
- Live responsiveness: an external buyer flagged an instruction-override synonym that slipped the matcher; the fix was shipped, regression-tested (187 tests green), and redeployed the same day.
- Try it live: the homepage has an **interactive scanner** — pick an attack (or paste your own payload) and watch the real deterministic engine return a verdict (BLOCK/SANITIZE/ALLOW), threat class, and compute latency in milliseconds. No wallet or signup needed.

**Traction & live feedback loop (honest):**
Warden operates as a real participant on OKX.AI — buying and selling — and that live usage is also its hardening loop. Real paid interactions with independent agents (PolicyPool, AgentForge, and cold buyers) earned genuine on-chain reviews (a 5.0 among the 4 on #3808) and, more importantly, surfaced real bugs we fixed under load: a detector's instruction-override synonym gap (shipped same-day) and two auditor edge cases. The same activity also mapped real issues in the marketplace's own payment rail (an x402 replay body-forwarding gap, a task-price resolver flap), which we isolated and documented for the platform. Framed honestly: this is a live paid feedback loop, not pure organic cold demand — some interactions were reciprocal — but the reviews, the fixes, and the settlements are all real and on-chain.

**Team:** Ridwan (solo).

**Anything else:** Warden is a runtime firewall primitive, not a semantic intent classifier — it flags concrete attack artifacts (addresses, secret formats, injection phrases, tool-hijack/link patterns) deterministically and sub-millisecond, and is honest about that scope.
