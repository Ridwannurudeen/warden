# Warden Trust Layer — Consolidated Build Spec

**Date:** 2026-07-24
**Repo:** `warden-roadmap` (branch `feat/post-hackathon-completion`)
**Builder:** Codex (external agent)
**Auditor:** Claude (this spec's author) — audits after the build, does not implement
**Status:** awaiting user approval

---

## 0. How to read this document

This spec is written for an agent that has **not** seen the conversation that produced it. Everything
needed to build is here.

Three kinds of statement appear, and they must be treated differently:

| Marker | Meaning | Builder's duty |
| --- | --- | --- |
| **[VERIFIED]** | Confirmed first-hand on 2026-07-24 by reading the file, calling the live host, or making the RPC call. Evidence cited inline. | Build on it directly. |
| **[UNVERIFIED]** | Sourced from research but **not** independently confirmed. | **Verify before writing code that depends on it.** If it does not hold, stop and report — do not improvise a substitute. |
| **[DECISION]** | A design choice made in this spec. | Follow it. Deviating requires reporting, not silent substitution. |

**The single most important rule:** where this spec and the codebase disagree, **the codebase wins**.
Report the discrepancy; do not force the spec's version.

---

## 1. Context

Warden is a deterministic security service for AI agents. It does two things today:

1. **Payload firewall** — `WardenEngine.scan()` returns `ALLOW` / `SANITIZE` / `BLOCK` on untrusted
   agent input, using pattern, analyzer, and normalization layers.
2. **Endpoint auditor** — `AgentAuditor.audit()` fires a pinned 20-probe attack battery at another
   agent's HTTP endpoint, grades it A–F, and issues a signed Ed25519 attestation.

It is **live and selling**. [VERIFIED] `https://warden.gudman.xyz/health` returns
`{"status":"ok","version":"0.1.0","corpus_size":124,...}`; `/scan` and `/audit` return HTTP 402
payment challenges. It is listed on OKX.AI as agent **#3808** with score 5.0, 100% positive, **22 sold**,
6 five-star reviews.

It is also **on-chain**. [VERIFIED] `ownerOf(3808)` on the X Layer ERC-8004 IdentityRegistry
(`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`) returns `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51`.
OKX registers every OKX.AI agent as an ERC-8004 NFT; the agent number is the token ID.

**The goal of this build:** turn Warden from "a scanner and an auditor" into **the certification and
hardening loop for the agent economy** — audit → harden → re-audit → on-chain attestation.

### Why this is the right wedge

Research (2026) found the guardrail market consolidated hard — five AI-security startups acquired in
~18 months — but every player sells either probabilistic runtime filtering or one-shot red-teaming.
**No competitor sells a deterministic, cryptographically-attested, re-testable certification loop.**
On OKX.AI specifically, no other ASP does payload scanning or endpoint attack-battery audits.
[UNVERIFIED — competitive landscape from research, not re-confirmed first-hand.]

---

## 2. Hard invariants — violating any of these fails the audit

These are non-negotiable. They encode security properties and honesty commitments the project already
made. **A build that breaks one of these is rejected regardless of how well it works.**

### I1. Additive only
`/scan`, `/audit`, `/api/demo/scan`, `/health`, and the legacy badge routes must keep their exact
current behavior. New capability arrives as new routes, new modules, new stores. No repurposing.

### I2. The payment rail is pinned — do not change the price
[VERIFIED — `warden/payment.py`] `PAYMENT_AMOUNT = "500000"` (0.5 USDT) is a module-level constant.
`load_payment_rail()` compares every `WARDEN_PAYMENT_*` environment variable against
`_FIXED_CONFIGURATION` and **raises at startup** on any divergence (`payment.py:103-107`). The rail is
x402 v2 `exact`, network `eip155:196` (X Layer), asset `0x779ded0c9e1022225f8e0630b35a9b54be713736`,
EIP-712 domain `{"name":"USD₮0","version":"1"}`.

New paid routes reuse this exact rail at this exact price. **Introducing a second price point is out of
scope for this build** — it requires a coordinated source + listing + docs + deployment migration and is
a business decision, not an implementation detail.

### I3. Held-out data never enters detector inputs or shipped artifacts
[VERIFIED] `corpus/attacks.jsonl` (94 cases) and `corpus/benign.jsonl` (30) are the training corpus.
`benchmark/held_out_attacks.jsonl` and `benchmark/held_out_benign.jsonl` are the held-out evaluation set.

**Held-out rows must never** be shipped in a hardening pack, added to patterns, or used as detector
input. The published deterministic baseline is 87/94 recall (92.55%) at 0/45 false positives, with seven
named misses. That number stays honest.

### I4. Deterministic paths stay deterministic
No LLM call and no outbound network request in the verdict path. The optional semantic/embedding tiers
remain disabled without explicit provider configuration, and a transport or schema failure there
preserves the deterministic verdict.

### I5. Evidence honesty
Audit records are **point-in-time evidence, not certification**. `ALLOW` means "no implemented detector
fired", not "safe". Attestations may be described as conformity *evidence*; never as legal
certification, and never as an accredited or Notified-Body assessment.

### I6. No external actions
The builder must **not**: deploy, push to any remote, publish a package, submit any form, post
socially, send a transaction, spend funds, touch a wallet key, or call a paid endpoint for real.
On-chain work is written and tested against a local/test harness only. Every one of those actions is
reserved for the user.

### I7. Consent stays hard
The auditor requires target consent via `/.well-known/warden-consent` before firing probes
(`auditor.py:_require_consent`, `_verify_target_consent`). Any new probing capability inherits this.
Soft mode remains available only when `WARDEN_ENVIRONMENT=development`.

### I8. Test-first for behavior changes
Per `README.md` Contributing: add a failing regression test before changing verdict, APA, or site
contracts. Every workstream below lists its required tests.

---

## 3. Verified codebase anchors

The builder should not re-derive these. All [VERIFIED] on 2026-07-24.

### 3.1 Layout
```
warden/            FastAPI service, verdict engine, APA issuer, stores
  api.py           1,144 lines — all HTTP routes + x402 middleware wiring
  engine.py        WardenEngine.scan() orchestration
  auditor.py       AgentAuditor.audit() battery + grading + badge issuance
  payment.py       the single pinned x402 rail
  models.py        Pydantic boundary models
  badge_store.py   JSONL badge persistence
  audit_attestations.py  Ed25519 signed audit records
  shield.py        recurring owner-enrolled audits
  mcp_server.py    FastMCP tools (scan_payload, audit_agent)
  scanner/         patterns.py, scanner.py, normalize.py, semantic.py, embedding.py
  analyzers/       drain address, tool hijack, exfiltration, malicious link
  core/            analyzer.py, registry.py, verdict.py (ReasonCode, Verdict, VerdictEngine)
sdk/python/warden_guard/   client, gateway, proxy, middleware, langchain/llamaindex adapters
sdk/ts/            TypeScript hosted client
corpus/            attacks.jsonl (94), benign.jsonl (30)
benchmark/         held_out_attacks.jsonl, held_out_benign.jsonl  ← NEVER ship
audit/             warden-core-http-2026-07.json (pinned battery, SHA-256 checked at import)
spec/              APA spec, conformance pack, ASP payload security standard
tests/             102 files, all named test_*.py
```

### 3.2 Route declaration pattern — copy this exactly
Paid routes are declared **twice**, POST and GET. The GET twin is not optional:

> [VERIFIED — `api.py:431-434` comment] "OKX's x402-check probes with GET and expects a 402 payment
> challenge; a POST-only paywall returns 405 and reads as an invalid x402 service. OKX's paid
> auto-replay also uses GET."

```python
@app.post("/audit", response_model=AuditResponse)          # api.py:783
async def audit(req: AuditRequest) -> AuditResponse:
    try:
        return await auditor.audit(req.target_url, req.sample_prompts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/audit", response_model=AuditResponse)           # api.py:791
async def audit_get(request: Request) -> AuditResponse:
    fields = await _get_request_fields(request)
    try:
        req = AuditRequest.model_validate(fields)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="...recovery hint...") from exc
    return await audit(req)
```

### 3.3 Adding a paid route touches four places
[VERIFIED] A new paid route is **not** just a decorator. All four must be updated together:

1. `_PAYMENT_OUTPUT_SCHEMAS` — `api.py:249-250`, the `{"input":…, "output":…}` map.
2. The `bazaar` extensions constant alongside `_SCAN_EXTENSIONS` / `_AUDIT_EXTENSIONS` — `api.py:252-253`.
3. `_paid_routes` — `api.py:436-445`, needs both `"POST /path"` and `"GET /path"` entries.
4. The hardcoded path sets at `api.py:459` and `api.py:484`
   (`paid_payment_route = carries_payment and path in {"/scan", "/audit"}`).

Missing #4 is the classic silent bug: the paywall engages but request/response handling diverges.

### 3.4 The gap that shapes Workstream A
[VERIFIED — `models.py:306-381`] `AuditResponse.results` is `list[AuditResult]`, and each
`AuditResult` carries `attack_class`, `sent`, `blocked` — i.e. **per-class pass/fail exists in the
response**.

But the **persisted** records do not keep it:
- `BadgeRecord` (`models.py:312`) stores only `audit_id, target_host, grade, score, blocked, total, issued_at, consent_verified, signature`.
- `AuditAttestationRecord` (`models.py:335`) stores only aggregate counts and grade.

**Therefore `/harden` cannot look up "which classes did this endpoint miss" from an `audit_id` today.**
Workstream A must add that persistence. This is the single most important design constraint in this
spec, and the thing an unaided builder would get wrong.

### 3.5 Threat taxonomy
[VERIFIED — `core/verdict.py:14-25`] `ReasonCode`: `PROMPT_INJECTION`, `ROLE_OVERRIDE`,
`WEB3_INJECTION`, `HIDDEN_UNICODE`, `ENCODING_TRICK`, `STATISTICAL_ANOMALY`, `CORPUS_MATCH`,
`DRAIN_ADDRESS`, `TOOL_HIJACK`, `SECRET_EXFIL`, `MALICIOUS_LINK`.

[VERIFIED — `scanner/patterns.py`] `INJECTION_PATTERNS` families: `direct_instruction`,
`role_override`, `web3_specific`, `control_characters`, `encoding_tricks`. Mapping from family to
`ReasonCode` is `SCANNER_CATEGORY_REASON_CODES` (`core/verdict.py:28`).

### 3.6 Storage pattern to imitate
[VERIFIED — `badge_store.py`] JSONL at a module-level `_STORE_PATH`, an `_exclusive_store_lock()`
context manager for cross-process safety, `_MAX_RECORDS = 5_000` with retention trimming, and a
`record_x` / `get_x` / `list_x` function trio. **New stores follow this shape.**

### 3.7 Battery identity
[VERIFIED — `auditor.py:23-30`] `AUDIT_BATTERY_PATH = audit/warden-core-http-2026-07.json`,
`BATTERY_ID = "warden-core-http"`, `BATTERY_VERSION = "2026-07"`, `AUDIT_BATTERY_SIZE = 20`, plus 3
benign controls. The manifest's canonical-JSON SHA-256 is pinned in `AUDIT_BATTERY_SHA256` and checked
at import — **any edit to the battery file breaks startup until the constant is updated.** Battery
changes also invalidate Shield baselines (a new enrollment revision is required).

### 3.8 Live vs. repo divergence — read this before assuming anything ships
[VERIFIED by probing the live host on 2026-07-24]

| Path | Live status | In repo? |
| --- | --- | --- |
| `/health` | 200 | yes |
| `/scan`, `/audit` | 402 (paywall live) | yes |
| `/theater`, `/trust`, `/apa/log`, `/playground` | 200 | yes |
| `/health/ready` | **404 from nginx** | **yes — `api.py:1079`** |

**The deployed surface is not the repo surface.** A route existing in source does not make it live;
that needs an operator deployment and an nginx location block, both user-gated (I6). Build accordingly
and never claim a new route is live.

---

## 4. Workstreams

Ordered by dependency. A–C are the core product loop; D–F are ecosystem expansion; G is a research
track. Each names its files, its acceptance criteria, and its tests.

---

### Workstream A — Audit result persistence + `/harden` (the certification loop)

**Why:** today an audit ends at "Improve blocking for EXFILTRATION payloads" — a diagnosis with no
treatment. This closes the loop: audit finds the holes, `/harden` delivers the fix kit, re-audit proves
the improvement with a signed grade delta.

#### A1. New module `warden/audit_findings.py`
Persist per-class audit outcomes so `/harden` can look them up by `audit_id`.

Follow the `badge_store.py` shape exactly (3.6). Suggested surface:

```python
def record_findings(audit_id: str, target_host: str, findings: list[dict]) -> None: ...
def get_findings(audit_id: str) -> dict | None: ...
```

- Store at `data/audit-findings/` (runtime state, **not** committed source — mirror how
  `data/feedback/` is treated). [VERIFIED] `.gitignore` lists runtime paths **explicitly**
  (`badges/`, `/data/feedback/`, `/data/shield/`, `data/*.db`), so a new directory is **not** ignored
  by default — you must add `/data/audit-findings/` to `.gitignore` in the same commit.
- Persist per class: `attack_class`, `total`, `blocked`, `missed`. **Do not persist probe payload text**
  — the battery is already public in `audit/`, and storing sent payloads per target adds an exfiltration
  surface for zero benefit.
- Bounded records + retention trimming, cross-process lock, atomic write.
- `audit_id` matches `^[0-9a-f]{16}$` (`models.py:340`).

#### A2. Wire it into `AgentAuditor`
In `auditor.py`, after a conclusive consented audit issues its badge, also record the per-class
findings keyed by the same `audit_id`.

- **Only record when a badge/attestation is issued** — an inconclusive or unconsented run must not
  create findings. This keeps `/harden` from operating on evidence the project refuses to sign.
- Do not change grading, consent, liveness, or badge logic. Purely additive.

#### A3. The hardening pack builder — `warden/hardening.py`
Given a set of missed `ReasonCode`s, build a remediation pack. Per missed class:

- **Example attacks** — drawn from `corpus/attacks.jsonl` filtered by `category`. **Training corpus
  only (I3).** Cap the number per class (suggest ≤5) and make selection deterministic (stable sort by
  `id`, not random) so the same input always yields the same pack.
- **Detection guidance** — which `INJECTION_PATTERNS` family and which analyzer covers that class,
  derived from `SCANNER_CATEGORY_REASON_CODES`. Describe the family; do not dump raw regexes wholesale
  as a copy-paste detector.
- **Integration guidance** — how to place enforcement using what already exists: `WardenClient(local=True,
  fail_open=False)`, the ASGI middleware, or the `warden-gateway` reverse proxy.
- **A pinned `corpus_fingerprint`** — from `warden/corpus_fingerprint.txt`, so a pack is traceable to
  the corpus state that produced it.

Pack content is **data, not prose generated at request time**. No LLM call (I4).

#### A4. The route — `POST /harden` + `GET /harden`
- Request: `HardenRequest { audit_id: str }` — pattern-validated.
- Response: `HardenResponse` — the pack, the source `audit_id`, the classes addressed, the corpus
  fingerprint, and an explicit limitations string.
- Unknown `audit_id` → 404. Known but **fully-passing** audit → a valid pack with zero remediation
  entries and a clear "nothing to harden" message, **not** an error.
- Paid, at the pinned 0.5 USDT rail (I2). Wire all four places from 3.3.
- Add matching models to `models.py` next to the audit models.

#### A5. MCP tool
Add a `harden_agent` tool to `warden/mcp_server.py`, following the existing `scan_payload` /
`audit_agent` shape (`Annotated` + `Field` constrained args, `output_schema=` on the decorator).

#### A6. Docs
Update the route table in `README.md`, and `site/integrate.html` if the route belongs on the
integration surface. Do **not** claim the route is live (3.8).

**Tests — `tests/test_harden.py`** (plus additions to `tests/test_payment_rail.py` and
`tests/test_r4_x402_route_wiring.py` for the new paid route):
1. Findings are recorded for a conclusive consented audit; **not** recorded for inconclusive or
   unconsented runs.
2. `/harden` returns remediation entries covering exactly the missed classes.
3. A fully-passing audit yields an empty-remediation pack, not a 404 or 500.
4. Unknown `audit_id` → 404.
5. **No held-out case ever appears in a pack** — assert against every row of
   `benchmark/held_out_attacks.jsonl` (this is the I3 regression guard and is mandatory).
6. Both `POST /harden` and `GET /harden` are paywalled, and an unpaid GET returns 402.
7. Pack generation is deterministic: same `audit_id` → byte-identical pack.

**Acceptance:** the full loop works end to end against a local deliberately-weak target — audit grades
it F, `/harden` returns the pack for the missed classes, and after mitigation a re-audit grades higher,
with both grades independently signature-verifiable.

---

### Workstream B — Re-audit lineage and the certification record

**Why:** the grade *delta* is the product. A signed "F → A, same battery, same subject" record is the
artifact no competitor issues.

- Extend Shield's existing drift classification (`initial` / `unchanged` / `improved` / `regressed` /
  `inconclusive`, in `shield.py`) into a **certification lineage** view: the ordered history of grades
  for one enrolled subject, each entry bound to its attestation.
- Reuse the existing attestation and transparency-log machinery (`audit_attestations.py`,
  `/apa/audit/{audit_id}`, the hash-chained `/apa/log`). Do not invent a second signing scheme.
- Preserve Shield's rule that inconclusive or stale evidence **never** replaces a prior baseline, and
  that a battery change requires a new enrollment revision.
- Expose lineage read-only. [DECISION] No new paid route in this workstream.

**Tests — extend `tests/test_shield_lifecycle.py`:** lineage ordering; an inconclusive run does not
overwrite a baseline; a battery-version change starts a new revision rather than silently comparing
across batteries; every lineage entry verifies against the issuer key history.

---

### Workstream C — Taxonomy mapping (OWASP ASI / LLM / MCP)

**Why:** a grade is more valuable when it names a recognized standard. This is the difference between
"Warden says B" and "conformity evidence against OWASP's agentic taxonomy".

[UNVERIFIED] Research reports an **OWASP Top 10 for Agentic Applications (ASI01–ASI10), released
2025-12-09**, alongside the OWASP LLM Top 10 (2025, `LLM01` = prompt injection) and an OWASP MCP Top 10
(`MCP03` = tool poisoning). **Verify these identifiers and their exact titles at `genai.owasp.org` and
`owasp.org` before encoding them.** If a category cannot be confirmed, leave it unmapped rather than
guessing.

- Add a **mapping data file** (e.g. `spec/taxonomy-map-v1.json`): Warden `ReasonCode` and each battery
  probe → external taxonomy IDs. Data, not hardcoded logic.
- Surface mapped IDs in audit output and in the hardening pack.
- Schema-version the file and test that every `ReasonCode` and every battery probe has an entry (or an
  explicit `null` with a reason).
- **Wording (I5):** "tested against OWASP ASI 2026 categories X, Y, Z" is acceptable. "OWASP certified"
  is not, and neither is any implication of accredited assessment.

**Tests — `tests/test_taxonomy_map.py`:** every `ReasonCode` covered; every one of the 20 probes covered;
mapping file schema valid; no unmapped entry silently defaults to a real category.

---

### Workstream D — On-chain attestation to ERC-8004 (X Layer)

**Why:** this converts Warden's off-chain Ed25519 evidence into a trust signal the whole OKX ecosystem
can read — and OKX's own tooling surfaces these ratings to every agent.

[VERIFIED] ERC-8004 IdentityRegistry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` and ReputationRegistry
`0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` both have live bytecode on X Layer (chain 196, ERC-1967
proxies). `ownerOf(3808)` → `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51`.

[UNVERIFIED — verify against the deployed ABI before coding] the reputation write is reported as:
```solidity
function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals,
    string tag1, string tag2, string endpoint,
    string feedbackURI, bytes32 feedbackHash) external
```
callable by any address that is **not** the agent's owner/operator (self-feedback is blocked), with
`feedbackURI` / `feedbackHash` emitted in a `NewFeedback` event rather than stored.

**Scope for this build — code only, no transactions (I6):**
- A module that **builds and signs** a feedback transaction mapping a completed audit to the registry
  call (grade → value, `"security-audit"` tag, attestation URI + SHA-256 as the evidence pointer).
- Full test coverage against a **local/mock chain harness**. No mainnet send, no funded key, no
  broadcast.
- A runbook documenting exactly what the user would run to submit one, and what it costs.
- **Blocking prerequisite for the user, not the builder:** confirm `0xf4c9…cfa51` is the user's wallet.
  Under ERC-8004, token ownership is agent control. Do not build key-handling assumptions before this
  is answered.
- Guard rail: the contract blocks self-feedback, so Warden cannot attest about itself. Attestations are
  about *audited third parties* only, and only with the consent already required by I7.

**Tests — `tests/test_onchain_attestation.py`:** correct calldata encoding; grade→value mapping is
lossless and documented; the evidence hash matches `record_sha256` of the attestation; refuses to build
a transaction for an inconclusive/unconsented audit; refuses self-attestation.

---

### Workstream E — Transparency-log anchoring on X Layer

**Why:** the existing ROADMAP lists "independent APA witness" as unfinished because the anchor head
lives inside Warden's own operator boundary. X Layer solves it for pennies.

The mechanism already exists: `scripts/publish_log_checkpoint.py` and `warden/anchor_history.py`
implement signed checkpoints in a bounded, append-only, pinnable history.

**Build:** a minimal anchor contract (`anchor(bytes32 root, uint64 seq)` + event) plus the client code
that publishes a checkpoint root, and a verifier that reconstructs the chain from on-chain events.
Solidity + tests only — **no deployment, no broadcast (I6)**. Include a deployment runbook and a cost
estimate for the user.

**Tests:** root computation matches `anchor_history`; truncation and rewriting are both detected against
a retained head; sequence numbers are monotonic and gaps are detected.

---

### Workstream F — Modern payment rails (metered + subscription)

**Why:** Warden bills per call at a flat 0.5 USDT. Continuous monitoring and high-frequency scanning
need metered and recurring billing. [Context, unverified: adjacent OKX.AI security agents price at
0.05–0.1 USDT, so per-call flat pricing is the weakest commercial surface — but see I2: **this
workstream adds rails, it does not change the price**.]

[UNVERIFIED] Research reports the OKX Agent Payments Protocol supports, beyond x402 `exact`:
an `upto` scheme (Permit2 delegation), `aggr_deferred` (TEE-only), a `period` /
`permit2_subscription` recurring scheme, and MPP payment channels with per-request vouchers
(`payment session open/voucher/topup/close`).

**Before writing any code, verify each scheme against OKX's published payment documentation and the
installed `x402` package's actual API.** [VERIFIED] the code imports
`from x402.http import OKXFacilitatorClient, PaymentOption` and
`from x402.schemas import AssetAmount`; check the installed version in `requirements.lock` for what it
genuinely supports. **Do not build against a scheme that the installed library does not implement.**

Scope: design + implementation behind a **default-off flag**, with the existing `exact` rail untouched
and remaining the default. Report findings before expanding scope.

**Tests:** startup still fails closed on unsupported rail overrides (the `payment.py` invariant must
survive); flag-off behavior is byte-identical to today; new rails are exercised only with the flag on.

---

### Workstream G — Corpus expansion and adversarial generation (research track)

**Why:** 94 cases is small, and the published held-out recall is 92.55% with seven named misses. There
is also a **real production miss** worth investigating first (see §6).

[UNVERIFIED — every license below must be confirmed by reading the source repo's LICENSE file before a
single row is ingested.] Research reports these as MIT/Apache and therefore commercially shippable:
AgentDojo (629 security cases), InjecAgent (1,054), Microsoft LLMail-Inject (~208K prompts), deepset
prompt-injections (662), HackAPrompt, and two Lakera Gandalf sets. It reports **BIPIA (CC BY-SA)** and
**TensorTrust (restrictive)** as **benchmark-only — do not redistribute**.

**Rules:**
- **Verify each license individually.** A dataset whose license cannot be confirmed is not ingested.
- Every ingested case carries **provenance and license metadata**, and the build emits a per-case
  license manifest. This manifest is itself a credibility asset — competitors hiding behind closed
  classifiers cannot offer it.
- Ingestion must respect the existing overlap guards and the single-dataset promotion path
  (`dataset_promotion.py`), and must not cross the training/held-out boundary (I3).
- Adversarial variant generation, if built, uses **structured deterministic mutations** (encoding,
  homoglyph, whitespace, casing) — attributable and reproducible, matching the project's deterministic
  ethos. No generative-model-in-the-loop corpus authoring.

**Tests:** license manifest completeness; no overlap across the four datasets or the built-in injection
list; held-out separation holds after ingestion; benchmark reproduces a recorded baseline.

---

## 5. What is explicitly out of scope

Do not build these. They were considered and deliberately deferred.

- **A second price tier or any price change** — see I2.
- **EAS integration** — [UNVERIFIED but well-sourced] EAS has no official X Layer deployment;
  ERC-8004 covers the agent-attestation case natively.
- **ERC-8004 ValidationRegistry integration** — reported not deployed on X Layer with its spec still in
  revision. Monitor; migrate later. This is the *purpose-built* third-party-auditor primitive, so it is
  the natural future home for audit results — but not today.
- **Exchange OS venue audits** — permissionless deployment reportedly opens Q3 2026; deployer
  interfaces are not public yet.
- **Evaluator registration / OKB staking** — a funded financial action, user-only (I6).
- **Bonded attestations** — a business/treasury decision, not an implementation task.
- **Any deploy, push, publish, listing update, social post, or form submission** — user-only.

---

## 6. Known open issue the builder should investigate first

[VERIFIED — from the public review text on the OKX.AI listing] A buyer reported that a real paid scan
**detected only 1 of 3 planted threats — missing a swapped payout address and an API-key exfiltration
attempt, despite `expected_addresses` being supplied.** It was reportedly fixed same-day and now
catches 3/3.

This matters because it is a **live-behavior gap the local 87/94 benchmark did not surface**, and
Workstream A builds a *hardening* product on top of that same detector.

**Task:** reproduce that scenario as a test (multi-vector payload: prompt injection + swapped
`expected_addresses` recipient + API-key exfiltration, in one payload). Confirm current behavior,
and if it still misses, treat it as a bug with a failing-test-first fix. **Report findings before
building on top of the detector.**

---

## 7. Build order and gates

```
Investigate §6  →  A (persistence → pack → route → MCP)  →  B (lineage)  →  C (taxonomy)
                                                              ↓
                                          D (on-chain attest) ‖ E (anchoring)
                                                              ↓
                                              F (payment rails)  ‖  G (corpus)
```

**Gate between every workstream — all must pass before moving on:**

```bash
python -m pytest -q
python -m ruff check .
node --test tests/js/*.test.js
python spec/verify_apa.py --selftest
python scripts/benchmark_recall.py --mode deterministic --json
```

The benchmark must still report **87/94 recall, 0/45 false positives** unless a change is deliberate,
explained, and re-recorded. A silent movement in that number is a build failure.

`git diff --check` before any commit. Commit per workstream with a clear message. **No pushing (I6).**

---

## 8. Audit checklist (how this build will be graded)

The auditor will independently re-run every gate — a passing claim is not proof. Findings will be
verified against the code, not the build report.

**Invariants**
- [ ] I1 — existing routes byte-identical in behavior; new capability is purely additive
- [ ] I2 — `PAYMENT_AMOUNT` unchanged; `load_payment_rail` still fails closed on override
- [ ] I3 — **no held-out row in any pack, pattern, or shipped artifact** (the mandatory regression test exists and passes)
- [ ] I4 — no LLM or network call in a deterministic verdict path
- [ ] I5 — no "certified" / "guaranteed safe" / accredited-assessment language anywhere
- [ ] I6 — no deploy, push, publish, submission, transaction, or wallet action occurred
- [ ] I7 — consent enforcement intact on every probing path
- [ ] I8 — behavior changes have tests that fail without the change

**Correctness**
- [ ] Paid-route wiring updated in **all four** places (3.3); unpaid GET returns 402
- [ ] Findings recorded only for conclusive, consented audits
- [ ] Pack generation deterministic and reproducible
- [ ] Full loop demonstrated: F → hardening pack → improved grade, both signature-verifiable
- [ ] Every [UNVERIFIED] item the build relied on was independently confirmed, with evidence cited

**Hygiene**
- [ ] `pytest`, `ruff`, JS tests, APA self-test, conformance all green when re-run by the auditor
- [ ] Deterministic benchmark unchanged at 87/94 and 0/45 (or deliberately re-recorded with rationale)
- [ ] No debug prints, scratch files, commented-out code, or placeholder/TODO implementations
- [ ] Runtime state under `data/` is not committed
- [ ] No unrelated refactoring; every changed line traces to a workstream in this spec

**Reporting**
- [ ] Anything unbuildable is reported as unbuilt — **never** stubbed, faked, or quietly narrowed
- [ ] Discrepancies between this spec and the codebase are reported, with the codebase treated as authoritative

---

## 9. Deadline context

[VERIFIED — `web3.okx.com/xlayer/build-x-series`] The OKX.AI Genesis Hackathon closes
**2026-07-27, 23:59 UTC**. Entry requires an ASP that passes OKX's internal review and is **live**, an X
post with `#OKXAI` including a ≤90-second demo, and the Google form. Prize pool $100,000; relevant
awards include **Best Product**, **Software Utility**, and **Revenue Rocket** (judged on campaign-period
revenue, orders, and positive reviews).

**Realism, stated plainly:** with ~3.5 days and a deployment gate the builder cannot pass (3.8, I6),
this spec is **not** scoped as a hackathon sprint. It is the full roadmap, deliberately ordered so
Workstream A alone is a coherent, submittable increment if the user chooses to deploy it — and so the
remainder continues cleanly after the deadline. **Nothing here should be rushed into a state that
breaks an invariant to hit a date.**
