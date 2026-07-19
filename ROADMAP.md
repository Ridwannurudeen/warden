# Warden post-hackathon roadmap - completion ledger

Status reconciled and locally verified on 2026-07-18 from `feat/post-hackathon-completion`. This document
separates software that can be finished in the repository
from outcomes that require an approved deployment, external systems, elapsed time, funding, customers, or
commercial agreements.

The repository is not evidence that an operator action happened. In particular, source-ready means
implemented and locally testable; it does not mean deployed, published, funded, observed in production, or
adopted by a third party.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| **FINITE SOURCE BUILT / LOCALLY VERIFIED** | The bounded repository implementation exists and its focused local gates pass. |
| **ACCEPTED DETECTOR LIMITATION** | The limitation is measured, published, and intentionally remains visible rather than being hidden by training on the held-out set. |
| **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** | The mechanism and runbook exist, but completion requires an approved action, an external party or service, production credentials, funds, or an observation window. |
| **NOT AUTHORIZED / NOT BUILT** | The work would broaden product scope or cause an external action and was neither authorized nor represented as complete. |

## Finite source completed

| Capability | Repository result | Principal local evidence | Status |
| --- | --- | --- | --- |
| Python and TypeScript SDKs | Typed clients, local Python enforcement, hosted modes, LangChain and LlamaIndex adapters, bounded middleware, and caller-owned x402 payment callbacks are implemented. A validated challenge can authorize exactly one replay; Warden never owns the wallet-signing boundary. | `sdk/python/tests/test_x402_replay.py`, `sdk/ts/tests/x402-replay.test.ts`, adapter and middleware suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Warden Gateway | A fail-closed Python reverse proxy is packaged with a CLI and container build. A BLOCK, invalid decision, or scanner failure does not reach the upstream application. | `sdk/python/warden_guard/gateway.py`, `sdk/python/tests/test_ph5_reverse_proxy.py`, `deploy/GATEWAY.md` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Integration surface | Direct HTTP, source-installed Python and TypeScript, MCP over explicit stdio, LangChain, LlamaIndex, OnchainOS, and the exact supported x402 path are documented without inventing published package names. | `warden/mcp_server.py`, SDK READMEs, `/integrate`, MCP and SDK tests | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Fixed x402 rail | `/scan` and `/audit` are bound in source to x402 v2 `exact`, X Layer, 500000 atomic units (0.5 USDT), and the pinned token, recipient, and EIP-712 domain. Unsupported rail overrides fail at startup. | `warden/payment.py`, `tests/test_payment_rail.py`, `tests/test_r4_x402_route_wiring.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Shared single-host runtime state | SQLite-backed rate windows, verified-payer grants, bounded metrics, and anonymous outbound-probe leases coordinate multiple local workers and survive restarts. Protected rate or lease operations fail closed when shared state is unavailable. | `warden/ratelimit.py`, `warden/observability.py`, `warden/protection_store.py`, rate-limit, observability, and probe-admission suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Endpoint-audit evidence | The immutable battery, exact endpoint and battery binding, consent and benign-liveness controls, complete-run requirement, Ed25519 portable record, transparency-log issuance, expiry, lookup, and revocation are implemented. Records are explicitly point-in-time evidence, not certification. | `audit/warden-core-http-2026-07.json`, `warden/audit_attestations.py`, audit battery and attestation suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Warden Shield lifecycle | Explicit owner enrollment, recurring due-audit scheduling, signed renewal lineage, drift classification, bounded state, metadata-only alerts, and hardened timer units exist. Inconclusive or stale evidence cannot replace the prior baseline. | `warden/shield.py`, `scripts/run_shield.py`, `tests/test_shield_lifecycle.py`, `tests/test_shield_systemd.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Feedback and data moat | Feedback is an explicit opt-in action with redacted retained input, bounded 90-day storage, deduplication, cross-process-safe human review, single-dataset promotion, overlap guards, a canonical corpus fingerprint, and aggregate-only k=5 threat reporting. Nothing learns from feedback automatically. | `warden/feedback_store.py`, `warden/dataset_promotion.py`, `warden/threat_intel.py`, `tests/test_feedback_data_moat.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| ASP Payload Security Standard | A narrow public draft defines the action-boundary decision contract, caller duties, reproducible audit profile, portable evidence, limitations, and versioning in prose and machine-readable form. | `spec/ASP-PAYLOAD-SECURITY-STANDARD.md`, `spec/payload-security-profile-v0.1.json`, `tests/test_payload_security_standard.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Reliability mechanism | Bounded readiness and unsigned x402-challenge probes, five-minute slot accounting, stale and missing-slot handling, transition notification, deterministic monthly summaries, systemd units, and an explicit non-SLA policy exist. | `scripts/monitor_readiness.py`, `scripts/notify_service_transition.py`, `scripts/summarize_service_monitor.py`, reliability suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| APA anchor mechanism | Signed checkpoints can be published atomically into a bounded, append-only, pinnable history that detects truncation or rewriting relative to a retained head. | `scripts/publish_log_checkpoint.py`, `warden/anchor_history.py`, `tests/test_ph4_external_anchor.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Issuer-key rotation | A fail-closed candidate-only rotation orchestrator, public retired-key history, complete re-probe gate, atomic promotion procedure, and rollback runbook exist. Private seed material is not accepted on the command line. | `scripts/rotate_issuer_key.py`, `docs/ISSUER_KEY_ROTATION.md`, issuer-rotation suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Supply-chain gates | Python dependencies are exact and hash-locked; CI installs with hashes, runs `pip-audit`, pins actions to immutable commits, checksum-pins a full-history TruffleHog scan, audits/builds/packs the TypeScript SDK, and follows a reviewed dependency-update policy. | `requirements.lock`, `.github/workflows/ci.yml`, `docs/DEPENDENCY_UPDATE_POLICY.md`, `tests/test_ci_supply_chain.py` | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Corpus and APA portability | The packaged canonical corpus fingerprint, APA schemas, reference verifier, and 12-vector conformance pack are built and included in distribution and site-generation contracts. | `warden/corpus_fingerprint.txt`, `spec/CONFORMANCE.md`, `spec/run_conformance.py`, distribution and conformance suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| Adversarial learning path | Gauntlet submissions remain private pending human review. A genuine confirmed bypass can be promoted only through the reviewed workflow, then receives a signed, transparency-logged WARDEN BREAKER record without automatically mutating the training corpus. | `scripts/review_gauntlet.py`, breaker certificate and Gauntlet process-race suites | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |

## Accepted detector limitation

The current deterministic held-out result is **87/94 attacks detected (92.55% recall) with 0/45 benign
false positives**. The seven published misses are:

- `held-prompt-002`
- `held-prompt-003`
- `held-role-002`
- `held-corpus-002`
- `held-drain-002`
- `held-secret-002`
- `held-evade-mix-003`

This is **ACCEPTED DETECTOR LIMITATION**, not a completion claim about universal safety. The optional semantic
and embedding tiers remain disabled without explicit provider configuration and have no current independently
labeled calibration result. Warden must not copy these misses into detector inputs merely to inflate the
held-out score.

## Source ready, but not externally completed

| Outcome | What is ready | What still has to happen | Status |
| --- | --- | --- | --- |
| Approved production release | Deployment, rollback, nginx, systemd, monitor, anchor, Shield, and rotation runbooks exist. | The user must approve the exact release; an operator must deploy it and run production smoke and rollback checks. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Correct live x402 domain | Source and fixtures use 0.5 USDT and `{"name":"USD₮0","version":"1"}`. | The 2026-07-18 read-only probe still observed live `{"name":"USDT","version":"1"}`. Deploy and reprobe before claiming payable authorization or settlement correctness. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Independent APA witness | Atomic checkpoint publication and pinnable history are implemented. | Retain a history head outside Warden's operator boundary or post it through an independently controlled witness. The committed public anchor remains explicitly unpublished. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Hosted supply-chain execution | The immutable CI workflow and dependency policy are complete locally. | A hosted CI run on the final pushed commit must execute the remote advisory and secret-scanning gates. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Production CORS and infrastructure proof | Source-level exact-origin and wildcard-without-credentials regressions pass. | Reverify deployed response headers, nginx, systemd, filesystem permissions, and live keys after an approved deployment. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Measured availability | The monitor and non-SLA measurement policy are implemented. | Run the independent schedule for all 8,640 five-minute slots in a rolling 30-day window. The committed monitor sentinel is `not_running`; 99.5% is an objective, not achieved uptime or an SLA. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Package distribution | Python and TypeScript build and package gates exist. | Publish only after explicit approval. Until then, documentation must describe source installation rather than registry availability. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Live Marketplace Evidence Index refresh | Bounded fetch, validation, atomic refresh, and dated/degraded provenance are implemented. | The production provider CLI, credentials, schedule, and live discovery still require operator preflight and deployment. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Managed Shield service | Enrollment, timer, lifecycle, renewal, and alerts are implemented. | Approve deployment, enroll real owners and consenting endpoints, configure alert delivery, and observe real recurring runs. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| Live issuer rotation | The runbook and candidate-only gate are implemented. | An operator must prepare real key material, quiesce production, execute the ceremony, verify the release, and preserve the public retired-key history. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |

## Not authorized and not built

The following are product, business, funding, or external ecosystem expansions. They are not a hidden
engineering backlog and must not be represented as completed:

- no deployment, VPS mutation, push of this completion branch, package publication, listing submission,
  hackathon form submission, or social post;
- no funded Gauntlet wallet, honeypot transaction, payout automation, or paid settlement replay;
- no Coinbase Agent.market listing, Base rail, Solana x402 rail, Google AP2 rail, generic multi-chain payment
  abstraction, or new token/payment mode;
- no A2A escrow audit tier, evaluator stake, dispute partnership, marketplace partnership, CertiK
  partnership, grant, customer contract, subscription revenue, or revenue-share agreement;
- no claim of a completed 30-day availability window, achieved SLA, historical uptime, customer enrollment,
  independent witness, review count, or commercial adoption; and
- no public revenue dashboard or claim that Warden's source implementation has produced revenue.

## Original phase plan, reconciled

| Original phase | Current disposition |
| --- | --- |
| Phase 0 - hackathon close-out | Repository and license work exists, but video, campaign, submission, key rotation, outreach, and revenue actions remain approval-gated or external. |
| Phase 1 - production trust floor | The finite rate-limit, observability, privacy/retention, hard-consent, signed-evidence, and corpus-pipeline mechanisms are built. Deployment and measured uptime remain external. |
| Phase 2 - detection and integrations | SDKs, Gateway, adapters, explicit feedback, threat aggregation, Gauntlet review, and optional model-tier orchestration are built. Detector recall remains the published accepted limit; reputation and subscription outcomes are external. |
| Phase 3 - marketplace expansion | The open ASP standard draft is built. Non-OKX rails/listings, A2A escrow, evaluators, stakes, and partnerships are not authorized or built. |
| Phase 4 - recurring security layer | Shield lifecycle, Gateway, and aggregate threat-intelligence source are built. Managed-service deployment, customers, recurring revenue, grants, and a public revenue dashboard are not completed. |

## Current local verification evidence

The following focused gates passed while preparing this ledger. The groups overlap and must not be added
together as a single suite total:

- 229 passed: audit evidence, consent, rate limiting, payment rail, x402 route wiring, observability, probe
  admission, Shield, feedback, standard, reliability, audit portability, rotation, supply chain, conformance,
  anchoring, and distribution tests;
- 16 passed: legacy badge durability/recovery and verified-payer rate-limit regressions;
- 45 passed: Python x402 replay, LangChain, LlamaIndex, and Gateway tests;
- 70 passed: TypeScript client and x402 replay tests;
- benchmark reproduced 87/94 recall and 0/45 false positives with the seven misses above;
- APA reference self-test passed and APA conformance passed all 12 vectors.

The whole-site redesign and its final browser, accessibility, responsive, and performance QA are reported
separately. This ledger deliberately records no Lighthouse score, browser result, deployment result, or final
whole-tree test total that was not established here.

## Standing constraints

- The caller retains final authority: execute the original only after `ALLOW`, the transformed payload only
  after `SANITIZE`, and no consequential action after `BLOCK` or an invalid result.
- `ALLOW` means no implemented detector fired; it is not proof of safety.
- Endpoint audit records are point-in-time evidence, not certification.
- Marketplace public-text signals are not proof that an agent is malicious, safe, or compromised.
- Deterministic held-out evidence stays separate from training inputs.
- Price or rail changes require an explicit source, listing, documentation, and deployment migration; never
  create silent divergence.
- No deploy, push, publish, submission, wallet action, or paid call occurs without explicit user approval.
