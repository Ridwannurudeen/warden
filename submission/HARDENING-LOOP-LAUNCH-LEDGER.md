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
- [ ] The amount was exactly 0.5 USDT / `500000` minimal units.
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

Recommended: keep `/scan`, `/audit`, and `/harden` at the pinned 0.5 USDT price for launch.

Reason: it preserves the tested additive route contract and avoids combining a product release with
an unvalidated pricing experiment. `warden-selftest` remains the free practice funnel. Any
subscription or hosted-gateway price requires a separate reviewed proposal and an explicit listing
update.

| Service | Launch price decision |
| --- | --- |
| `/scan` | `0.5 USDT — unchanged` |
| `/audit` | `0.5 USDT — unchanged` |
| `/harden` | `0.5 USDT — new service on existing rail` |
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
