# Warden Agent Training + ML Infrastructure — Complete Building Plan

**Date:** 2026-07-24  
**Repository:** `warden-roadmap`  
**Implementation branch:** `feat/post-hackathon-completion`  
**Status:** Active build authority

This plan merges:

1. `2026-07-24-warden-handoff-to-codex.md`;
2. `2026-07-24-warden-trust-layer-build-spec.md`; and
3. the approved Phase 0–2 Agent Training and ML Infrastructure roadmap.

The handoff still overrides the older trust-layer spec where they disagree. The current code and
verified tests override both documents when they describe historical state. This plan adds the
training and infrastructure deliverables that were not present in either trust-layer document.

## 1. Completion boundary

“Built” means all source, tests, documentation, local integration, packaging, and operator runbooks
are complete and pass the full gate. The following actions are deliberately not part of autonomous
source completion:

- pushing commits;
- deploying to the VPS or X Layer;
- signing or broadcasting wallet transactions;
- making paid production calls;
- updating the OKX.AI listing;
- posting to X;
- uploading the demo; or
- submitting the Google form.

Those actions are prepared as an operator ledger and require explicit approval immediately before
execution. An external action is never represented as complete merely because its source/runbook is
ready.

## 2. Binding invariants

1. Existing request and payment contracts remain unchanged. Detector corrections and explicitly
   versioned additive evidence fields must have exact regression coverage.
2. `PAYMENT_AMOUNT` remains `500000`; unsupported payment overrides fail closed.
3. Held-out rows never enter training packs, self-test packs, generated variants, shipped artifacts,
   or detector inputs.
4. Deterministic verdict, pack, mutation, and calibration-selection paths make no model or network
   call.
5. Warden emits technical evidence, not “certification,” accreditation, or safety guarantees.
6. No external action listed in §1 occurs without explicit user approval.
7. Consent remains mandatory for every active endpoint probe.
8. Every behavior change begins with a regression that fails without the change.
9. No payload, secret, wallet credential, or raw audit probe is added to a long-lived operational
   store.
10. Third-party training rows ship only from the exact allowlisted source, revision, path, and license.

## 3. Build order

```text
Plan freeze
  ├─ Phase 0: signed hardening product + complete local loop
  ├─ Phase 1A: SDK self-test + deterministic variant packs
  ├─ Phase 2A: gateway productization
  └─ Trust-layer local-chain closure
       ↓
Phase 1B: public lineage + Shield delivery + Gauntlet promotion
       ↓
Phase 2B: labeled calibration + threshold selection
       ↓
Licensed corpus batches + attribution propagation
       ↓
Full independent gate + security/documentation review
       ↓
Operator-gated launch ledger
```

Independent branches/worktrees may implement non-overlapping file sets in parallel. Each accepted
workstream is reviewed and tested before integration.

## 4. Phase 0 — The Loop, v1

### 4.1 Signed Hardening Pack

**Existing foundation**

- `warden/audit_findings.py` stores bounded per-class counts for conclusive consented audits.
- `warden/hardening.py` deterministically assembles training-only remediation data.
- `warden/api.py` exposes paid `GET` and `POST /harden`.
- `warden/mcp_server.py` exposes `harden_agent`.

**Build**

- Add a canonical signed Hardening Pack record using the existing Ed25519 issuer conventions.
- Bind the signature to every pack field, the source `audit_id`, corpus fingerprint, issue time, and
  deterministic pack identifier/hash.
- Commit the signed record atomically to the existing transparency log.
- Add a public read-only lookup for independently retrieving and verifying a pack record.
- Make `/harden` and `harden_agent` return the signed record without changing the pinned payment rail.
- Return an explicit “nothing to harden” message for a conclusive zero-miss audit.
- Carry third-party source/license attribution for every example included in a pack.

**Primary files**

- `warden/hardening.py`
- `warden/models.py`
- `warden/protection_store.py`
- `warden/api.py`
- `warden/mcp_server.py`
- `warden/issuer_keys.py` or the existing issuer helper actually used after source verification
- `tests/test_harden.py`
- `tests/test_audit_attestations.py` or a focused signed-pack test module

**Tests**

- same audit produces byte-identical canonical pack content;
- valid signature verifies with the correct issuer history;
- any field mutation, wrong key, malformed signature, or mismatched pack ID fails;
- pack log inclusion is independently verifiable;
- failed signing/log commit leaves no partial public record;
- unknown audit is 404;
- fully passing audit returns a signed empty-remediation record;
- held-out rows are absent from every pack;
- GET and POST remain paywalled at 0.5 USDT;
- MCP output matches the HTTP output schema.

### 4.2 Complete F → harden → improved re-audit proof

- Add a deliberately weak local consented endpoint fixture.
- Run the existing audit and retain a signed failing audit record.
- Build the signed pack for exactly the missed classes.
- Apply real documented local enforcement, not a mocked grade change.
- Re-audit with the same battery and subject.
- Require a strictly improved score and grade.
- Verify both audit signatures, the pack signature, and all transparency-log bindings.
- Preserve the honest boundary: the test proves improvement against the fixed battery, not safety.

**Primary tests**

- `tests/test_harden.py`
- a focused integration test if the existing file would mix unit and lifecycle concerns

### 4.3 Route, deployment, and documentation closure

- Add `/harden` to nginx and production smoke/rollback checks.
- Update root API metadata, README route table, MCP table, and integration page.
- Add current source-ready listing copy describing “technical automation + agent training.”
- Describe `warden-gateway` as serving-path guardrail infrastructure without claiming hosted service,
  calibration, or deployment that has not occurred.
- Preserve a failing contract test for every route inventory.

**Primary files**

- `deploy/nginx-warden.conf`
- `deploy/DEPLOY.md`
- `deploy/TRUST-LAYER-DEPLOY.md`
- `README.md`
- `site/integrate.html`
- `site/data/warden-services.json`
- relevant route/deployment/site tests

### 4.4 Phase 0 launch assets — staged, never submitted automatically

- A ≤90-second script demonstrating F → signed pack → enforcement → improved re-audit.
- Recording checklist requiring live execution rather than replayed logs.
- Current `#OKXAI` post draft.
- Current Google form answer draft with explicit placeholders for final approved URLs.
- Listing `#3808` verification checklist and `/harden` update payload.
- Exact operator approval checkpoints for deploy, listing update, recording/upload, post, and form.

## 5. Phase 1 — Agent Training suite

### 5.1 `warden-selftest`

Build a Python SDK command that validates and runs a signed Hardening Pack’s vectors locally before a
paid graded audit.

**Behavior**

- New `warden-selftest` console entry point.
- Accept a pack file or verified public pack URL.
- Verify schema, issuer signature/history, pack identifier, and status before running.
- Reject expired, revoked, malformed, unsigned, or cross-origin evidence.
- Exercise each vector through local fail-closed enforcement or a caller-authorized endpoint.
- Report totals and per-class results without issuing a grade, badge, or certification claim.
- Never store vector payloads or send them to Warden’s paid service in local mode.

**Primary files**

- `sdk/python/pyproject.toml`
- `sdk/python/warden_guard/selftest.py`
- existing SDK verification/client modules after source verification
- `sdk/python/tests/test_selftest.py`
- `sdk/python/README.md`

### 5.2 Deterministic adversarial variant evaluation packs

- Generate structured variants from training rows only.
- Use bounded encoding, Unicode/homoglyph, whitespace, casing, and nesting transformations supported
  by `warden/scanner/normalize.py`.
- Record source-case ID, transform chain, source/license metadata, and resulting hash.
- Deduplicate scanner-equivalent variants.
- Reject overlap with both training datasets, both held-out datasets, and built-in injections where
  the generated artifact would violate separation.
- Produce deterministic JSON evaluation packs suitable for CI.
- Add a CLI and documented CI example.

**Primary files**

- new focused module under `warden/`
- new script under `scripts/`
- `warden/scanner/normalize.py` only if an existing transform must be exposed without changing runtime
  behavior
- focused tests

### 5.3 Public audit-evidence lineage surface

- Rename internal/public “certification lineage” terminology to “audit evidence lineage.”
- Preserve the existing signed Shield lineage backend.
- Add a public page for an enrolled endpoint/target ID.
- Show ordered grade history, dates, comparison state, evidence status, battery identity, and
  independent verification links.
- Verify issuer signatures and transparency inclusion in the browser; do not trust an API boolean.
- Explain stale, revoked, inconclusive, and battery-revision boundaries.

**Primary files**

- `warden/shield.py`
- `warden/api.py`
- `warden/models.py`
- `site/` page and JavaScript
- `scripts/build_site.py` if route generation requires it
- Python and Node tests

### 5.4 Continuous hardening through Shield

- After a conclusive audit with missed or regressed classes, build and persist a fresh signed pack.
- Bind the pack to the exact Shield observation and enrollment revision.
- Never replace a prior baseline or emit a pack for inconclusive/stale evidence.
- Add metadata-only delivery through the existing notifier boundary.
- Make retries idempotent and prevent duplicate packs for the same audit.
- Record delivery state without storing endpoint payloads.

**Primary files**

- `warden/shield.py`
- `warden/hardening.py`
- existing Shield state/model files
- `scripts/run_shield.py`
- `docs/SHIELD_LIFECYCLE.md`
- `tests/test_shield_lifecycle.py`

### 5.5 Human-reviewed Gauntlet → training → pack pipeline

- Keep initial confirmed bypasses in held-out evaluation.
- Add a distinct second operator review for training promotion.
- Require explicit consent/provenance/license facts and a linked WARDEN BREAKER certificate.
- Promote atomically through `dataset_promotion.py`.
- Reject duplicates and overlap across all four datasets and built-in injections.
- Update corpus fingerprint and license manifest atomically.
- Make only the separately approved training copy eligible for future packs.

**Primary files**

- `scripts/review_gauntlet.py` or a separate promotion command if responsibilities would otherwise mix
- `warden/gauntlet_store.py`
- `warden/dataset_promotion.py`
- `warden/corpus_ingestion.py`
- focused Gauntlet/promotion tests
- `benchmark/README.md`

## 6. Phase 2 — ML Infrastructure tier

### 6.1 Gateway productization

**Existing foundation**

- `warden-gateway` fail-closed reverse proxy.
- `deploy/Dockerfile.gateway`.
- Basic local Docker instructions.

**Build**

- Add a gateway-specific hardened systemd unit.
- Add a Docker Compose sidecar example with explicit network/upstream boundaries.
- Add container health checks and graceful shutdown verification.
- Add a bounded metadata-only `/metrics` surface for the gateway.
- Include decisions, blocks, sanitizations, failures, upstream latency, scanner latency, and uptime;
  never payloads, headers, secrets, addresses, or unbounded labels.
- Document fail-closed guarantees and every condition that prevents upstream forwarding.
- Add persistent-state permissions, upgrade, rollback, and local smoke procedures.
- Keep hosted mode explicitly unsupported for paid production until a payment-aware transport exists.

**Primary files**

- `sdk/python/warden_guard/proxy.py`
- `sdk/python/warden_guard/gateway.py`
- `deploy/Dockerfile.gateway`
- `deploy/GATEWAY.md`
- new gateway systemd and Compose manifests
- SDK gateway/proxy tests
- deployment contract tests

### 6.2 Labeled-data calibration and threshold selection

- Define a versioned calibration schema separate from training and held-out evaluation.
- Require independently labeled examples with provenance and reviewer identity/record, without secrets.
- Add a provider-result capture step; network/model execution is explicit and never part of the
  deterministic scanner.
- Add an offline threshold-selection step that consumes only captured labeled results.
- Sweep semantic and embedding thresholds and report confusion matrices, precision, recall,
  false-positive rate, F1, and sample counts.
- Select an operating point using a documented deterministic policy.
- Emit a signed or hashed versioned calibration artifact.
- Never change production thresholds automatically; generate a reviewed proposal.
- Keep current thresholds labeled uncalibrated until a real approved dataset and provider run exist.

**Primary files**

- new calibration module under `warden/`
- new capture/selection scripts under `scripts/`
- versioned schema under `spec/`
- `benchmark/README.md`
- `README.md`
- focused unit and integration tests

### 6.3 Hosted-gateway design boundary

- Specify tenant authentication, isolation, quotas, payment transport, replay protection, retention,
  and failure semantics.
- Do not expose hosted paid mode until the installed payment stack is verified to support the chosen
  transport.
- Keep local gateway operation independent of hosted availability.
- Treat hosted deployment and pricing as operator/business decisions.

## 7. Trust-layer closure retained from the earlier plan

### 7.1 Taxonomy and contract hygiene

- Resolve the MCP06 authoritative-title conflict using a pinned source revision or mark it explicitly
  unmapped.
- Add exact response-contract coverage for additive taxonomy fields.
- Remove stale multivector `xfail` scope after the drain-address fix.
- Record the historical test-order and detector-behavior exceptions honestly.

### 7.2 ERC-8004 local execution

- Verify the current deployed X Layer proxy implementation ABI and preserve evidence.
- Pin a Solidity/EVM toolchain after explicit dependency approval.
- Execute the attestation against a faithful local registry harness.
- Test invalid agents, value/decimal boundaries, self-feedback rejection, valid third-party feedback,
  and event/attestation agreement.
- Do not sign or broadcast a live transaction.

### 7.3 Transparency anchor local execution

- Compile `WardenLogAnchor.sol` with pinned Solidity `0.8.24`.
- Record compiler settings and creation/runtime bytecode hashes.
- Test constructor, authorization, zero root, sequence monotonicity, events, and stored state.
- Deploy locally, submit the Python-built transaction, decode the event, and verify gap/rewrite/
  truncation/head failures.
- Do not deploy to X Layer.

### 7.4 Modern payment rails

- Keep the current design-only result and exact rail unchanged.
- Before implementation, obtain approval for an authenticated read-only `/supported` check and any
  dependency change.
- If verified support exists, implement an additive adapter behind a default-off flag with durable
  replay/expiry/top-up/close tests.
- Do not claim or build unsupported schemes from documentation examples alone.

## 8. Licensed corpus expansion

Process one reviewed batch at a time in this order:

1. AgentDojo;
2. InjecAgent;
3. BIPIA Microsoft-authored attack instruction files only;
4. deepset prompt-injections;
5. Lakera `gandalf_ignore_instructions`;
6. Lakera `gandalf_summarization`; and
7. Microsoft LLMail-Inject labeled unique submissions.

For every batch:

- use the exact allowlisted revision and path;
- inspect the checkout origin and dirty state;
- produce and review the normalized mapping;
- retain per-row source, revision, path, SPDX, and source-case identity;
- promote atomically;
- regenerate the license manifest and corpus fingerprint;
- verify notices ship with source and built distributions;
- verify hardening/self-test/variant packs carry required attribution;
- run the deterministic benchmark and full gate before the next batch.

Never use TensorTrust, `gandalf-rct`, BIPIA contexts/table/code data, unverified paths, or
generative-model-authored corpus rows.

## 9. Full gate

Run after every integrated workstream and at final closeout:

```bash
python -m pytest -q
python -m pytest -q sdk/python/tests
python -m ruff check .
node --test tests/js/*.test.js
python spec/verify_apa.py --selftest
python spec/run_conformance.py
python scripts/benchmark_recall.py --mode deterministic --json
git diff --check
```

Run in `sdk/ts`:

```bash
npm test
npm run build
```

Build/package gates:

```bash
python -m build
python -m build sdk/python
npm pack --dry-run
```

The deterministic benchmark remains `87/94` attacks detected and `0/45` false positives unless an
intentional detector change is separately reviewed and the public evidence is deliberately updated.

## 10. Operator-gated launch ledger

Source completion prepares, but does not execute:

1. fresh listing `#3808` live/review-approved verification;
2. production x402 `USDT` versus source `USD₮0` reprobe after approved deployment;
3. exact release commit and rollback review;
4. VPS deployment and smoke tests;
5. `/harden` OKX.AI listing update;
6. hosted-gateway offering decision;
7. pricing decision;
8. ≤90-second real demo recording/upload;
9. `#OKXAI` post;
10. Google form submission;
11. ERC-8004 feedback transaction; and
12. X Layer transparency-anchor deployment/publication.

Each item requires a separate explicit approval at the point of execution.

## 11. Definition of source-complete

- Every non-operator checkbox above has working production code or an explicitly verified
  external-prerequisite design boundary.
- No placeholder, stub, fabricated external result, or silently narrowed acceptance criterion exists.
- Every behavior has unit or integration coverage proportionate to its boundary.
- All documentation describes observed source state and clearly separates local verification from
  deployed evidence.
- The full gate and independent review are green on the final local commit.
- The working tree is clean, commits remain local, and no external action occurred.
