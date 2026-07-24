# Handoff to Codex — Warden Trust Layer

**Date:** 2026-07-24
**Repo:** `C:\Users\gudma\OneDrive\Desktop\GITHUB-FILES\warden-roadmap`
**Branch:** `feat/post-hackathon-completion`
**Your role:** builder — complete every workstream in the build spec.
**My role:** auditor — I will independently re-run every gate on your output. A passing claim in your
report is not evidence; I verify against the code.

---

## 0. Read these first, in this order

1. `docs/superpowers/specs/2026-07-24-warden-trust-layer-build-spec.md` — **the build plan.** Its §2
   invariants are binding and its §8 checklist is exactly how I will grade you.
2. This document — current state, what is done, what changed since the spec was written.

**Precedence:** where this handoff and the spec disagree, **this handoff is newer and wins**. Where
either disagrees with the codebase, **the codebase wins** — report the discrepancy instead of forcing
the document's version.

---

## 1. Current state — verified by me on 2026-07-24

The tree is **green**. I ran every gate myself immediately before writing this:

```
python -m pytest -q          → 1330 passed, 1 skipped, 4 xfailed
python -m ruff check .       → All checks passed!
benchmark (deterministic)    → 87/94 = 92.55% recall, 0 false positives
```

Baseline before any of this work was `1297 passed, 1 skipped`. **Do not let these numbers regress.**
The benchmark's 87/94 and 0 FP are a published honesty commitment — a silent move is a build failure.

### Uncommitted working tree

```
 M .gitignore                      added /data/audit-findings/
 M tests/test_x402_input_schema.py extended paid-route contract to /harden
 M tests/test_r4_x402_route_wiring.py  extended paid-route wiring to /harden
 M warden/api.py                   /harden routes + payment wiring + recovery hint
 M warden/auditor.py               records per-class findings on badge issuance
 M warden/mcp_server.py            harden_agent MCP tool
 M warden/models.py                Harden* models
?? warden/audit_findings.py        NEW — per-class findings store
?? warden/hardening.py             NEW — remediation pack builder
?? spec/taxonomy-map-v1.json       NEW — Workstream C mapping
?? tests/test_taxonomy_map.py      NEW — Workstream C tests
?? tests/test_multivector_payload.py  NEW — §6 investigation
```

**Nothing is committed yet.** Commit per workstream as you go. **Never push (invariant I6).**

---

## 2. What is DONE (verify, do not rebuild)

### Workstream A — mostly complete

| Piece | State |
| --- | --- |
| `warden/audit_findings.py` | **Done.** JSONL store mirroring `badge_store.py` (cross-process lock, atomic write, `_MAX_RECORDS=5000`, env override `WARDEN_AUDIT_FINDINGS_STORE`). Validates `audit_id` as 16 lowercase hex, rejects bad counts and duplicate classes, idempotent on identical re-record, raises on a conflicting record. Stores **counts only — never probe payload text**. |
| `warden/auditor.py` wiring | **Done.** `record_findings(...)` is called *only* inside the `consent_verified and grade != "INCONCLUSIVE"` branch, right after `record_badge`. Uses `fixed_results` only — caller-supplied prompts stay excluded, same prompt-provenance rule as the grade. Helper `AgentAuditor._class_findings` aggregates per class. |
| `warden/hardening.py` | **Done.** `build_pack(findings_record)`. Reads `corpus/attacks.jsonl` **only** (never `benchmark/held_out_*`), ≤5 examples per class, deterministic sort by case id, pins `corpus_fingerprint`. `CLASS_GUIDANCE` covers all 11 `ReasonCode` values with pattern families / analyzers / summary. Zero-missed input yields an empty remediation list, which is a valid pack. |
| `POST` + `GET /harden` | **Done.** Both registered and paywalled. |
| Payment wiring (4 places) | **Done.** `_PAYMENT_OUTPUT_SCHEMAS`, `_HARDEN_EXTENSIONS`, `_paid_routes` (POST+GET), and **both** hardcoded path sets in `rate_limit_middleware`. |
| `_HARDEN_RECOVERY_HINT` | **Done.** OKX auto-replay sends a bodyless GET; without this a paid buyer's task freezes with no recovery path. Mirrors the scan/audit hints. |
| `harden_agent` MCP tool | **Done** in `warden/mcp_server.py`. |

**Verified working:** categories in the battery and the corpus are the **same 11 `ReasonCode` values**,
so mapping is direct — no translation layer needed.

### Workstream C — appears complete, needs your verification pass

`spec/taxonomy-map-v1.json` (11 reason codes, 20 probes, 3 taxonomies with source URLs, status
`public-draft`) and `tests/test_taxonomy_map.py`. I audited the wording for invariant I5 and it passes —
the evidence statement explicitly disclaims certification and accredited assessment.

### §6 investigation — complete, and it found real gaps

`tests/test_multivector_payload.py` — **23 passed, 4 xfailed**. Findings:

- The buyer's reported 3-of-3 case **does not reproduce**: prompt-injection + swapped recipient +
  API-key exfiltration in one payload is caught 3/3 at `BLOCK`/`CRITICAL`, in both depths, with and
  without `expected_addresses`.
- **A plausible mechanism for the "1 of 3" report was identified:** `VerdictEngine._hard_block_reason`
  short-circuits, so `failed_checks` contains only the *first* hard gate while `threat_classes` carries
  all three. A client surfacing `failed_checks` sees 1/3; one surfacing `threat_classes` sees 3/3.
- **Two genuine coverage gaps, encoded as 4 `xfail(strict=True)` tests:**
  1. `DrainAddressAnalyzer` misses a swapped address when it sits **>80 characters** from a
     transfer-intent word (`drain_address.py:144` proximity window). Supplying `expected_addresses`
     never on its own makes a mismatched address suspicious.
  2. `ExfiltrationAnalyzer` misses token shapes and sensitive-noun aliases outside its hardcoded
     vocabularies (e.g. `vk_live_…` behind `x-vendor-token`).

**Note:** `xfail` is a deviation — the repo uses it nowhere else. Keep it (it fails loudly when someone
fixes the detector) unless the user says otherwise, but do not spread the pattern.

**Separately flagged false positive:** ordinary English `"on file:"` hard-blocks at CRITICAL as
`MALICIOUS_LINK` (`"The invoice is on file: INV-2026-0412."`). The bare-token behavior is deliberate —
`tests/test_analyzers.py` asserts `("file:", 90)` — so a fix must thread that needle.

---

## 3. Research findings that CHANGE the spec

### 3.1 Workstream F — the premise is blocked, not dead. **Do not build it blind.**

Verified against the **installed** library (`okxweb3-app-x402==0.1.0`, module reports
`x402.__version__ == "2.5.0"`):

- Only **two** scheme identifiers exist in the entire package: `exact` (full client/server/facilitator)
  and `aggr_deferred` (**server-side only**, no client, not exported from `mechanisms.evm.__init__`).
- **`upto`, `period`, `permit2_subscription`, and all MPP session/voucher/channel primitives: zero
  occurrences.** Not implemented in the installed version.
- Permit2 exists but as an *asset-transfer method inside* `exact`, and **X Layer is not configured for
  it** (`NETWORK_CONFIGS["eip155:196"]` has no `asset_transfer_method`, so it uses EIP-3009).

Verified against **OKX's published docs** (a different question, kept separate):

- `upto`, `aggr_deferred`, and `period` **are** documented by OKX, and OKX's `/supported` *examples*
  advertise them on `eip155:196`. MPP session ops exist but have **no REST endpoints** — OKX's own docs
  say *"Never probe for /open, /voucher, /topup, /close — they don't exist."*
- **PyPI has `okxweb3-app-x402` 0.1.1** (2026-07-09), newer than the installed 0.1.0. No changelog
  published.

**Two hard constraints any Workstream F design must respect:**

1. `scripts/monitor_readiness.py:209-211` hard-fails if the 402 challenge does not contain **exactly
   one** `accepts` entry, and pins scheme/network/payTo/amount/asset. Adding a second `PaymentOption`
   to `/scan`'s `accepts` **breaks production monitoring**, not just a test.
2. `tests/test_payment_rail.py:68` and `tests/test_ph5_reliability.py:266` use `"upto"` as the canonical
   *rejected* value in fail-closed parametrizations. Any new rail must keep both red-when-violated.

**Also note:** `x402.extensions` does not exist in this build; `http/middleware/fastapi.py:70-83`
swallows the `ImportError`, so the bazaar *resource-server extension* is never registered. Route-level
`RouteConfig.extensions` data still flows. Observation only — do not "fix" it.

**Your instruction for F:** do **not** upgrade the library and do **not** add a scheme speculatively.
Produce a written design + a verification plan naming exactly what must be confirmed (a live
authenticated `GET /supported` for `eip155:196`, and the 0.1.0→0.1.1 diff). Implement only behind a
**default-off flag** with `exact` untouched as the default. **The user must approve any dependency
upgrade — that is a real external action (I6).**

### 3.2 Workstream G — licenses are now verified; the spec has been corrected

I amended the spec's Workstream G in place with primary-source license findings. Read it. Headlines:

- **BIPIA is a split verdict** — its `*_attack_*.json` files (250 instructions) are **MIT and
  shippable**; its `table/` and `code/` contexts are **CC BY-SA 4.0**, which is **incompatible with
  Warden's Apache-2.0** and would force ShareAlike onto a paid pack.
- **TensorTrust is unlicensed**, not merely restrictive — no LICENSE file exists on the data repo.
- **`Lakera/gandalf-rct` is non-commercial + no-redistribution "including any excerpts"** and sits one
  directory from two MIT Gandalf sets. Easy, costly accident.
- Category A alone yields **~3,700 clean cases** vs today's 94. You do not need the risky ones.
- Required: **allowlist** ingestion (not denylist), an **SPDX guard test**, and a
  **`THIRD-PARTY-NOTICES`** file shipped with the pack.

### 3.3 Workstream D — the on-chain anchor is confirmed live

I verified these myself by RPC against `https://rpc.xlayer.tech` (chain 196):

- ERC-8004 **IdentityRegistry** `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` — `ownerOf(3808)` returns
  `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51`; `tokenURI(3808)` resolves to an OKX-hosted registration
  JSON named "Warden". **OKX registers every OKX.AI agent as an ERC-8004 NFT; agent number = token ID.**
- ERC-8004 **ReputationRegistry** `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` — **has live bytecode**
  (ERC-1967 proxy). Confirmed by `eth_getCode`.
- The `giveFeedback(...)` ABI shape is still **[UNVERIFIED]** — read it from the deployed contract
  before coding against it.

**Blocking prerequisite, user-only:** confirm `0xf4c9…cfa51` is the user's wallet. Under ERC-8004 token
ownership *is* agent control. Do not build key-handling assumptions before the user answers.

---

## 4. What REMAINS — build all of it

Work in this order. Run the full gate between workstreams.

### A-remainder (finish first — this is the only incomplete core piece)
Write **`tests/test_harden.py`**. The paid-route/402 behavior is already covered by my extensions to
`test_x402_input_schema.py` and `test_r4_x402_route_wiring.py`, so cover the rest:

1. Findings **are** recorded for a conclusive consented audit; **not** recorded for inconclusive, and
   **not** for unconsented.
2. `/harden` returns remediation covering **exactly** the missed classes.
3. A fully-passing audit yields an **empty remediation list** — not a 404, not a 500.
4. Unknown `audit_id` → **404**.
5. **MANDATORY (invariant I3):** assert that **no** row from `benchmark/held_out_attacks.jsonl` appears
   in any pack, for a pack covering **all 11 classes**. This is the regression guard I check first.
6. Pack generation is **deterministic** — same `audit_id` → byte-identical pack.
7. Store behavior: idempotent identical re-record; conflicting record raises; malformed counts rejected.

**Test harness pattern to copy** (from `tests/test_c1_inconclusive_audits.py`): monkeypatch the auditor
*instance* methods `_validate_public_http_url`, `_verify_target_consent`, `_load_representative_attacks`,
`_target_outcome`; set `WARDEN_BADGE_SECRET`; stub `warden.auditor.record_badge`. **Isolate the store**
with `monkeypatch.setattr(audit_findings, "_STORE_PATH", tmp_path / "findings.jsonl")` — both store
functions read that module global at call time. Remember benign controls also pass through
`_target_outcome` and must return `NOT_BLOCKED` or liveness fails and no badge (and so no findings) is
issued.

### Then, in order
- **Workstream B** — re-audit lineage over Shield's existing drift classification. Reuse
  `audit_attestations.py` and the hash-chained `/apa/log`; invent no second signing scheme. Read-only,
  no new paid route.
- **Workstream C** — verify what is already there, close any gaps, confirm every external ID against an
  authoritative OWASP source, and leave anything unconfirmable explicitly unmapped with a reason.
- **Workstream D** — on-chain attestation builder. **Code and tests only against a local/mock chain.**
  No transaction, no funded key, no broadcast. Include a runbook and cost estimate for the user.
- **Workstream E** — X Layer anchor contract + client for the transparency log. Solidity + tests only,
  **no deployment**. Include a deployment runbook.
- **Workstream F** — design + verification plan only, per §3.1 above. Flag default-off.
- **Workstream G** — corpus expansion under the corrected licenses, allowlist + SPDX guard +
  `THIRD-PARTY-NOTICES`. **Do not ingest anything whose license you have not read at its primary
  source.**

### Judgment call I am leaving to you, with a recommendation
The §6 detector gaps (drain proximity, exfil vocabulary) are **real** and Workstream A ships a
*hardening* product on top of that detector. My recommendation: fix the **drain-proximity** gap —
when `expected_addresses` is non-empty, treat any address outside that set as a drain candidate at
reduced confidence regardless of proximity, since the caller has explicitly declared the allowed
recipients. That is a **behavior change with false-positive risk**: do it failing-test-first, and
re-run the benchmark. **If it moves 87/94 or 0/45 at all, stop and report rather than re-recording the
baseline to make it green.**

---

## 5. Rules — these fail the audit if broken

All eight invariants in spec §2 are binding. The ones most at risk in the remaining work:

- **I2 — the price is pinned.** `PAYMENT_AMOUNT = "500000"` and `load_payment_rail` fails closed on any
  override. New paid routes reuse the exact rail at the exact price. **No second price tier.**
- **I3 — held-out data never ships.** Packs read `corpus/attacks.jsonl` only.
- **I6 — no external actions.** No deploy, push, publish, form submission, social post, transaction,
  funded key, wallet action, paid endpoint call, or dependency upgrade without the user. This is the
  one I check hardest.
- **I5 — evidence honesty.** No "certified", "compliant", "guaranteed safe", or implied accredited
  assessment, anywhere, including JSON strings and docs.
- **I1 — additive only.** `/scan`, `/audit`, `/api/demo/scan`, `/health`, legacy badge routes keep exact
  current behavior.

### Two traps I hit — you will hit them too

1. **The auto-formatter strips imports it thinks are unused.** If you add an import before its call
   site, a `PostToolUse` formatter deletes it and you get a `NameError` at import time. **Add the usage
   first, or re-check the import afterward.** This bit me twice.
2. **Paid routes are pinned in test inventories.** Adding one breaks
   `tests/test_x402_input_schema.py` (exact `_paid_routes` set) and `tests/test_r4_x402_route_wiring.py`
   (`expected_routes` list). I already updated both for `/harden`. If you add another paid route,
   update them **and extend their assertions to cover it** — do not merely widen the set.

---

## 6. Gate — run all of it between every workstream

```bash
python -m pytest -q
python -m ruff check .
node --test tests/js/*.test.js
python spec/verify_apa.py --selftest
python scripts/benchmark_recall.py --mode deterministic --json
```

Expected: **≥1330 passed**, ruff clean, benchmark **exactly 87/94 and 0/45**. `git diff --check` before
each commit. Commit per workstream. **Never push.**

## 7. Reporting

Report honestly and specifically:
- Quote **actual** command output. Do not paraphrase a result you did not see.
- Anything unbuildable is reported as **unbuilt** — never stubbed, faked, or quietly narrowed.
- Every `[UNVERIFIED]` item you relied on: state how you confirmed it, with the source.
- Discrepancies between these documents and the codebase: report them; the codebase is authoritative.

I will re-run every gate myself and check your diff line by line against spec §8 before anything is
called done.
