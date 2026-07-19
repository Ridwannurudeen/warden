> **Historical / superseded submission draft.** This file contains point-in-time metrics and copy; it is not current product truth. Do not submit, publish, post, or send it without explicit user approval and fresh verification against `ROADMAP.md`, the completion addendum in `SECURITY-AUDIT-2026-07.md`, and `REDESIGN_REPORT.md`.

# Warden — OKX.AI Genesis Hackathon Submission Form Answers

> Staged for review, not submission. Add **[VIDEO_URL]** and **[X_THREAD_URL]**, then verify the Trust Layer
> routes on production before copying these answers into the form. Follow `docs/HACKATHON_DEMO.md`. Do not
> submit without explicit user approval.

---

**Project name:** Warden

**One-line tagline:** The immune system of the agent economy — a watchable runtime defense and open Ed25519 trust standard for autonomous services.

**Agent ID / listing:** #3808 on X Layer — listed and eligible for task recommendations (`approvalDisplayStatus: 4`).

**Award categories:** Creative Genius (primary); Best Product (secondary); Software Utility (secondary).

**Live service URL:** https://warden.gudman.xyz

**Private repository (staged):** https://github.com/Ridwannurudeen/warden — Do not change visibility or
describe it as public without explicit user approval.

**Demo video:** [VIDEO_URL]

**X thread:** [X_THREAD_URL]

---

**What it does (short):**
Warden puts an immune response between untrusted input and an autonomous action. Its Attack Theater sends three live attacks through the real demo API and shows Warden neutralizing them before they reach a demo agent. Its open Agent Protection Attestation (APA) standard then lets any agent service publish an Ed25519-signed proof of a live guard, a rolling 24-hour screened-payload count or explicit unavailable state, and a verifiable issuer attestation.

**Problem & solution (long):**
Agent services ingest messages, tool output, links, and transaction instructions from strangers, then act. A poisoned payload can hijack a tool call, swap a payout address, or request a secret. A one-time audit cannot protect that live decision boundary.

Warden is the immune system at that boundary. The Python and TypeScript SDKs call a deterministic ALLOW / SANITIZE / BLOCK engine before an agent acts; Python can also enforce locally in process. The Attack Theater makes the defense watchable with real API responses: prompt injection must SANITIZE, while a recipient swap and secret exfiltration must BLOCK. It stops honestly on a network error or unexpected verdict.

APA turns that runtime state into an open trust primitive. The endpoint signs its own Protection Proof, Warden independently verifies the endpoint and signs an attestation, the browser verifier checks Ed25519 without trusting an API verdict, and a hash-chained transparency log exposes issuance and status changes. The Safety Map adds a query-scoped view of public OKX.AI listing text. Together they form infrastructure another marketplace or agent service can adopt, not a claim that one vendor can certify permanent safety.

**How it works / tech stack:**

- FastAPI service with a deterministic injection scanner and drain-address, tool-hijack, secret-exfiltration, and malicious-link analyzers.
- Python `warden-guard` SDK with hosted and local enforcement, async support, middleware, decorators, atomic rolling counters, and an Ed25519 Protection Proof.
- Zero-runtime-dependency TypeScript SDK with a fetch client and Express-style middleware.
- APA v0.1: canonical JSON, two Ed25519 signature layers, endpoint-host TOFU binding, revocation, key-change detection, and a hash-chained transparency log.
- Independent same-origin browser verifier using WebCrypto Ed25519.
- Atomic, timer-ready Safety Index releases built from a query-scoped marketplace snapshot.
- Existing paid `/scan` and `/audit` services remain attached to Agent #3808 through x402 on X Layer.

**Verified metrics / reproducible proof:**

- Attack Theater advances only when the real API returns the exact expected verdict and threat class for all three attacks; fallback or fabricated success is forbidden.
- Detection gate: 92 attack cases, 30 benign guards, and 0 false positives in the committed corpus gate.
- Safety Map snapshot: 730 unique agents sampled out of a highest reported 752 for query `a`, with 22 expected agents absent from the response, 3 listing-text matches, and 0 endpoint audits. It is explicitly a partial/degraded query-scoped capture, not a marketplace-wide certification.
- The APA reference verifier accepts a genuine issuer record and rejects field or count tampering.
- The issuer key, endpoint key, and local counter state are separate; neither the badge nor the verifier claims every request traversed Warden.

**Why Creative Genius:**
Most security entries expose another scanner. Warden combines a watchable immune-response demo, drop-in runtime enforcement, an open cryptographic attestation standard, independent browser verification, a transparency log, and a live-health-map model. The creative leap is turning agent security from a one-off product into a portable trust layer for the agent economy.

**Team:** Ridwan (solo).

**Anything else:**
Warden's claims are deliberately narrow. APA proves endpoint-key control, a fresh conforming guard proof, and an endpoint-signed count or explicit unavailable state at verification time. It does not prove all traffic was routed through the guard, independently audit the endpoint owner's local counter state, or guarantee future safety.
