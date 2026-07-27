# Warden Hardening Loop — Launch Package

Status: source-ready and staged locally. Nothing in this package authorizes deployment, listing
updates, recording/upload, posting, payment, authentication, or form submission.

## Product truth used by this package

- `POST /audit` runs the fixed `warden-core-http` battery against a consented endpoint and can issue
  a signed audit record.
- `GET` and `POST /harden` accept a completed 16-character `audit_id` and return a deterministic,
  Ed25519-signed Hardening Pack on the same pinned 0.1 USDT x402 rail.
- A pack references its source audit, contains training-corpus examples only, carries source/license
  provenance, expires after 30 days, and is committed to Warden's transparency log.
- `warden-selftest` can independently verify a public pack evidence bundle and exercise its vectors.
- Local enforcement uses `WardenClient(local=True, fail_open=False)` or `warden-gateway`.
- Re-audit uses the existing `/audit`; no special grade-changing route exists.
- Improvement is evidence against the fixed battery at two points in time. It is not certification,
  permanent safety, or proof that every request traversed Warden.

## No-funds preflight

From the repository root:

```powershell
python demo/run_hardening_loop.py
```

The command starts a loopback-only consented endpoint and uses ephemeral evidence state. It performs
no wallet action, payment, public endpoint call, deployment, upload, or submission. It must exit 0
and show:

1. `before.grade` = `F`;
2. a non-empty signed `hardening_pack.addressed_classes`;
3. fail-closed SDK enforcement plus the endpoint's deny-by-default command allowlist;
4. `after.grade` = `A` and a strictly greater score;
5. transparency events `audit-issued`, `hardening-pack-issued`, `audit-issued`; and
6. `transparency.chain_verified` = `true`.

Do not record a failed or manually edited output. Diagnose the failure, rerun the source, and record
one continuous successful execution.

## 84-second participation demo

Target: 84 seconds. Hard stop: 90 seconds. Record at 1280×720 or higher with a real voice. The
opening introduces Warden as the ASP, the buyer scenario explains why it is useful, and the
continuous run shows the product rather than replaying saved evidence.

| Time | Action | Narration | Evidence visible |
| --- | --- | --- | --- |
| 00:00–00:10 | Show a title card reading **Warden ASP: audit → harden → re-audit**, then the command before execution. | “Meet Warden, an ASP for agent security and training. It helps builders find what an endpoint misses, harden it, and prove the improvement.” | ASP name, buyer use case, and command are readable; no wallet, credential, or unrelated window is visible. |
| 00:10–00:20 | Run `python demo/run_hardening_loop.py`. Point to `before`. | “This consented test endpoint starts weak. Warden's fixed battery produces signed grade F evidence.” | `battery`, before `audit_id`, grade `F`, and score are visible. |
| 00:20–00:36 | Point to `hardening_pack`. | “From that audit ID, Warden creates a deterministic, Ed25519-signed Hardening Pack for the missed classes, using training-only examples with provenance.” | Pack ID, addressed classes, and `signature_verified: true` are visible. |
| 00:36–00:49 | Point to `enforcement`. | “The endpoint applies the treatment through real fail-closed local enforcement and its own deny-by-default action policy.” | SDK and application-policy lines are visible. |
| 00:49–01:03 | Point to `after`. | “The same battery runs again. The score moves from zero to one hundred, and the endpoint earns A—with no mocked grade change.” | After audit ID, grade `A`, and score are visible beside or immediately after before evidence. |
| 01:03–01:15 | Point to `transparency`. | “The before audit, treatment, and re-audit are separate signed records in one verified transparency chain.” | Three ordered events, checkpoint sequence, and `chain_verified: true` are visible. |
| 01:15–01:24 | Point to `limitations`; stop. | “This proves improvement against this battery at these times. It is technical evidence, not certification or a future-safety guarantee.” | The limitation sentence remains visible at the cut. |

## Recording checklist

- [ ] The exact tested commit is recorded in the operator ledger.
- [ ] The presenter uses the checked-in command without editing output or replaying a saved log.
- [ ] The recording shows one continuous invocation and exit.
- [ ] The first and second audit IDs are distinct and visible.
- [ ] Grade F, the signed pack, real enforcement, grade A, and verified log chain are all visible.
- [ ] The opening explicitly introduces Warden as the ASP and explains the endpoint-builder use case.
- [ ] The narration says “training corpus” and never claims held-out cases ship in packs.
- [ ] The narration says “technical evidence” and never says certification, accredited, guaranteed
      safe, all attacks, or permanent protection.
- [ ] No key, token, wallet, payment signature, `.env` file, notification, or personal information
      appears in any frame.
- [ ] The final cut is 90 seconds or shorter, at least 1280×720, and uses a real voice.
- [ ] The file is reviewed locally before any upload.
- [ ] Recording and upload each have explicit user approval recorded in the launch ledger.

## Listing #3808 verification checklist

This is a fresh authenticated operator check, not a claim about current status.

- [ ] Fetch agent #3808 immediately before any edit.
- [ ] Confirm the returned owner address matches the operator's currently selected wallet.
- [ ] Record current `approvalDisplayStatus`, online/active state, profile description, and service
      inventory without exposing wallet credentials.
- [ ] Confirm `/scan` and `/audit` remain present and unchanged.
- [ ] Confirm `/harden` is absent before using a create delta. If it already exists, stop and obtain
      its service ID; an update delta is required instead.
- [ ] Confirm the reviewed production deployment exposes valid unpaid x402 challenges on both
      `GET /harden` and `POST /harden`.
- [ ] Confirm the displayed payment terms are the intended X Layer asset and exactly 0.1 USDT.
- [ ] Run the platform's listing validation once against the final profile copy and the create/update
      service entry.
- [ ] Review the exact diff card and obtain explicit user confirmation before the listing write.
- [ ] After an approved write, record the returned review state. Do not claim live/approved until a
      fresh read proves it.

### Exact candidate service delta

Use this object only after the checklist proves `/harden` is a new service. The operator-facing
listing flow must still perform its required current-state fetch, validation, diff, and confirmation.

```json
[
  {
    "operation": "create",
    "serviceName": "Signed Hardening Pack",
    "serviceDescription": "Builds a deterministic, Ed25519-signed Hardening Pack for the missed classes in a completed Warden audit.\nProvide the 16-character audit_id from a completed consented audit.",
    "serviceType": "A2MCP",
    "fee": "0.1",
    "endpoint": "https://warden.gudman.xyz/harden"
  }
]
```

If the service already exists, do not reuse this payload: obtain its current service ID and prepare
an `operation: "update"` delta containing that ID and the complete reviewed field values.

### Candidate profile description

> Warden provides technical security automation and agent training infrastructure: paid payload
> scans, consented endpoint audits, signed Hardening Packs, local self-tests, and a fail-closed
> serving-path gateway. It returns narrow technical evidence, not certification or a safety
> guarantee.

This copy is staged, not authorized. The current profile description must be fetched first and the
exact before/after diff must be approved before an update.

## External URL placeholders

Replace only after the corresponding approved action succeeds and the URL is verified:

- Product: `https://warden.gudman.xyz`
- Hardening Pack evidence: `https://warden.gudman.xyz/apa/hardening/[PACK_ID]`
- Demo video: `[FINAL_APPROVED_VIDEO_URL]`
- #OKXAI post: `[FINAL_APPROVED_POST_URL]`
- Repository/spec: `[FINAL_APPROVED_REPOSITORY_URL]`
- Listing #3808: `[VERIFIED_LISTING_3808_URL]`

The current post and form drafts are:

- [`hardening-loop-post.md`](hardening-loop-post.md)
- [`HARDENING-LOOP-FORM.md`](HARDENING-LOOP-FORM.md)
- [`HARDENING-LOOP-LAUNCH-LEDGER.md`](HARDENING-LOOP-LAUNCH-LEDGER.md)
