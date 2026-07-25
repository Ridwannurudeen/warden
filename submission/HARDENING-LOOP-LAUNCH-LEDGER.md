# Warden Hardening Loop — Operator Launch Ledger

This ledger separates source completion from external actions. Each action needs fresh preflight,
an exact target, the tested commit, rollback where applicable, and explicit user approval
immediately before execution.

## Release identity

| Field | Value |
| --- | --- |
| Candidate commit | `[TESTED_COMMIT]` |
| Full gate result | `[FULL_GATE_RESULT_AND_DATE_UTC]` |
| Demo harness result | `[DEMO_RESULT_AND_DATE_UTC]` |
| Operator | `[OPERATOR]` |
| Release notes reviewed | `[YES/NO]` |

## Approval sequence

Do not combine approvals. A later approval does not retroactively authorize an earlier step, and an
approval for one destination does not authorize another.

| Order | External action | Required evidence before asking | Exact approval to record | Completion evidence |
| --- | --- | --- | --- | --- |
| 1 | Deploy reviewed API/site release | Clean tested commit, backup/rollback target, target host, deployment diff, secretless smoke plan | `[USER_APPROVAL_DEPLOY]` | `[DEPLOY_TIME_UTC, RELEASE_PATH, SMOKE_RESULT, ROLLBACK_TARGET]` |
| 2 | Verify production | `/health`; unpaid GET+POST `/harden` challenges; public pack evidence route; `/scan` and `/audit` regression; nginx/systemd status | Read-only after approved deploy | `[PRODUCTION_VERIFICATION_RESULT]` |
| 3 | Update listing #3808 | Fresh owner/status/service read; `/harden` absent or current service ID; validation result; exact diff card | `[USER_APPROVAL_LISTING_UPDATE]` | `[UPDATE_RESULT, REVIEW_STATE, TIME_UTC]` |
| 4 | Record demo | Exact tested/deployed commit, cleared screen, approved script, no-funds command | `[USER_APPROVAL_RECORD]` | `[LOCAL_VIDEO_PATH, DURATION, RESOLUTION, REVIEW_RESULT]` |
| 5 | Upload demo | Reviewed local file, exact destination/account, title/description/privacy, rollback/removal path | `[USER_APPROVAL_UPLOAD]` | `[FINAL_APPROVED_VIDEO_URL, TIME_UTC]` |
| 6 | Publish #OKXAI post | Final resolved URLs, exact text, destination account, current listing status | `[USER_APPROVAL_POST]` | `[FINAL_APPROVED_POST_URL, TIME_UTC]` |
| 7 | Submit Google form | Completed non-placeholder answers, signed-out URL check, exact form/destination, one-submit rule | `[USER_APPROVAL_FORM_SUBMIT]` | `[SUBMISSION_CONFIRMATION_OR_RECEIPT, TIME_UTC]` |

## Production verification record

- [ ] `/health` returned the expected JSON 200.
- [ ] Unpaid `GET /harden?audit_id=[VALID_AUDIT_ID]` returned a valid x402 challenge.
- [ ] Unpaid `POST /harden` with `{"audit_id":"[VALID_AUDIT_ID]"}` returned the same pinned payment
      terms.
- [ ] Asset symbol/address presentation was recorded exactly; any source-versus-live `USDT` /
      `USD₮0` mismatch was flagged, not silently changed.
- [ ] The amount was exactly 0.1 USDT / `100000` minimal units.
- [ ] A reviewed paid smoke was separately approved before spending, or marked `[NOT RUN]`.
- [ ] `/apa/hardening/[PACK_ID]` returned the expected active evidence bundle.
- [ ] `/scan` and `/audit` contract smoke checks passed unchanged.
- [ ] Rollback was not needed, or the exact rollback action/result was recorded.

## Listing verification record

| Field | Fresh value |
| --- | --- |
| Agent ID | `3808` |
| Owner matches selected wallet | `[YES/NO — DO NOT RECORD SECRET]` |
| Approval display status | `[CURRENT_VALUE]` |
| Active/online status | `[CURRENT_VALUE]` |
| Existing services | `[CURRENT_SERVICE_IDS_AND_ENDPOINTS]` |
| `/harden` operation | `[CREATE/UPDATE/NO-OP]` |
| Validation result | `[RESULT]` |
| Post-write review state | `[CURRENT_VALUE]` |

Never mark the listing live or approved from a historical snapshot. If ownership does not match,
stop without an update.

## Hosted gateway decision

Recommended: keep hosted paid gateway unavailable for this release.

Reason: the local gateway is source-ready, but hosted operation still needs tenant authentication,
isolation, quotas, replay protection, retention policy, and a verified payment-aware transport. The
current exact rail must not be stretched into an unsupported subscription/session claim.

| Decision | Record |
| --- | --- |
| Local gateway release | `Source-ready; deployment is operator-gated` |
| Hosted gateway | `[KEEP UNAVAILABLE / APPROVED FOR SEPARATE DESIGN]` |
| Tenant/payment architecture approved | `[NO/YES + SPEC]` |
| Public hosted-service claim allowed | `[NO/YES]` |

## Pricing decision

Decided 2026-07-25 by the operator: move every paid route to 0.1 USDT (`100000` minimal units), the
lowest price on the pinned rail rather than a per-route experiment.

Reason: the constraint on demand at this stage is willingness to try an unfamiliar security service,
not margin, and one price across all four routes preserves the single-`accepts` route contract that
the tests pin. `warden-selftest` remains the free practice funnel. Any subscription or
hosted-gateway price requires a separate reviewed proposal and an explicit listing update.

This is the coordinated migration that invariant I2 requires: source, tests, docs, site catalogue,
and the listing fees all move together.

**Endpoint first, listing second.** If the listing drops to 0.1 while the endpoint still demands
`500000`, buyers create and fund tasks at 0.1 that the 402 then rejects — real failed tasks against an
agent currently at 100% approval. The reverse order only breaks the `/hire` command builder, and costs
nobody money.

**Known gap during the window: `/hire` payment commands will not build.**
`site/hire.js` derives the expected atomic amount from the catalogue `feeAmount` and requires the live
`accepts` entry to match it exactly (`site/hire.js:82-99`); no match throws before any command is
generated. The catalogue is **generated**, not hand-maintained — `scripts/build_index.py:213` writes
`site/data/warden-services.json` from `data/marketplace/agents-v1.jsonl`, whose Warden entry still
records `0.5` as fetched on 2026-07-18. So the catalogue cannot honestly read 0.1 until OKX itself
advertises 0.1.

Order of operations, with the gap open between 1 and 3:

1. Deploy the 0.1 endpoint build.
2. Update the four listing fees to 0.1 and wait for approval.
3. Re-fetch the marketplace snapshot, regenerate the catalogue, update the
   `tests/test_hire_catalog.py` fee assertion to match the new snapshot, and redeploy the site index.

Keep 1→3 tight. Do not hand-edit `site/data/warden-services.json` to close the gap early: the next
index build overwrites it, so the edit reads as done while changing nothing.

| Service | Launch price decision |
| --- | --- |
| `/scan` | `0.1 USDT — reduced from 0.5` |
| `/audit` | `0.1 USDT — reduced from 0.5` |
| `/harden` | `0.1 USDT — new service on existing rail` |
| `/variant-audit` | `0.1 USDT — new service on existing rail` |
| `warden-selftest` | `Free local tool` |
| Hosted gateway/subscription | `[NOT OFFERED]` |

## Stop conditions

Stop the relevant action immediately if:

- the candidate commit differs from the fully tested commit;
- a required URL or status is unverified;
- listing ownership does not match the selected wallet;
- the platform returns a new payload shape or validation error;
- payment terms differ from the pinned amount/network/asset expectation;
- a credential, payment signature, or private window appears in the recording;
- the final post or form still contains a placeholder; or
- explicit approval for that exact action and destination is absent.
