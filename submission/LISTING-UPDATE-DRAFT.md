# OKX.AI listing update — draft for review

**Date:** 2026-07-25
**Agent:** #3808 (Warden), owner `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51`
**Status:** DRAFT — not submitted. The on-chain write is gated on an explicit confirmation.

> Field rules below were verified against OKX's own offline validator and skill references.
> The copy passes `validate-listing` with zero findings. Nothing here is authorized or submitted yet.

## Current state (verified from the registry, 2026-07-25)

| Field | Value |
| --- | --- |
| `approvalDisplayStatus` | `4` — "Listed — eligible for task recommendations" |
| `statusLabel` / `onlineStatus` | `active` / `1` |
| Score / approval / sales | 5.0 / 100% / 22 |
| Profile description | 326 chars (326 display width) |

Existing services (IDs needed so an update delta cannot clobber them):

| Service id | Type | Fee | Name |
| --- | --- | --- | --- |
| `c2783b5b-a932-4249-b0e2-4ccc6245fd63` | A2MCP | 0.5 | Payload Security Scan |
| `dc289c2e-e280-4786-95d0-0c5dc7ac6cfc` | A2MCP | 0.5 | Agent Endpoint Security Audit |
| `b04a04c0-442c-4cfc-ab64-cb914c64cbb7` | A2A | — | Escrow Payload Security Scan |

The fees above are what the registry currently holds. Source moved to **0.1 USDT** on 2026-07-25, so
this listing is now also a **price migration**, not just an addition:

- the new `/harden` service is created at `0.1`;
- the two existing A2MCP services still advertise `0.5` and must be brought down to `0.1`, otherwise
  the listing would advertise more than the endpoint charges;
- `/variant-audit` is a fifth service, staged separately, also at `0.1`.

**Sequencing is not optional.** Deploy the 0.1 build first, then update the listing. Reversing the
order advertises a price the live endpoint will reject.

**Open risk on the fee updates.** Bringing the two existing fees down needs `operation: update`
entries. On 2026-07-25 a delta containing **only** `operation: "create"` was observed to leave the
existing service ids intact, but an earlier delta that included `update` entries reassigned **every**
service id. So the fee update may churn ids that `site/data/warden-services.json` and the hire flow
reference by id. Capture the ids returned by the update and re-check the site catalogue against them
before treating the listing as done.

## Proposed new service — `/harden`

The endpoint is already live in production: `GET`/`POST https://warden.gudman.xyz/harden` answers a
correct x402 402 challenge on the pinned rail (`exact`, `eip155:196`, `100000`, `USD₮0` v1), and its
bazaar schema declares `required: ["audit_id"]`.

- **serviceName:** `Endpoint Hardening Pack`  (23 chars)
- **serviceType:** `A2MCP`
- **fee:** `"0.1"`  (quoted string, no currency suffix)
- **endpoint:** `https://warden.gudman.xyz/harden`
- **serviceDescription** (two parts, separate lines):

> Turns a completed Warden endpoint audit into a signed remediation pack: for every threat class the
> endpoint failed to block, it returns example attacks, the detection families and analyzers that catch
> them, and where to place enforcement so the block happens before the action. Each pack is signed and
> recorded in a public transparency log, so a later re-audit can show the grade actually moved.
>
> Provide: the audit_id of a completed Warden endpoint audit.

## Proposed profile description — VALIDATED

`onchainos agent validate-listing --role asp` returns **`pass: true`, zero findings** for this copy
together with the service entry above. **492 characters** against OKX's hard 500-character limit
(code `D8`, counted in Unicode characters — *not* display width, which applies only to
`serviceDescription`). No URL (`D6`), no `0x` address (`U2`), no `(beta)`-style marker (`U1`), no
negative-capability phrasing (`U3`).

> Security automation and agent training for AI agents. Warden screens untrusted responses, tool outputs, and messages for prompt injection, hijacked tool calls, drain or attacker payout addresses, and secret exfiltration, returning ALLOW / SANITIZE / BLOCK before your agent acts. It also audits an agent endpoint against a fixed attack battery, then issues a signed Hardening Pack naming what to fix and re-audits to show whether the grade moved. Narrow technical evidence, not certification.

The earlier draft of this section was **598 characters and hard-failed `D8`**. It also advertised the
fail-closed gateway; that sentence was cut, because the gateway is self-hosted software rather than a
purchasable service and the space was better spent on the loop.

## Avatar — replace it, in the post-deadline delta only

**Superseded 2026-07-25.** The earlier draft said do not touch the avatar. That advice was right for a
mid-review window and wrong as a permanent position, so it is reversed here with the timing constraint
kept intact.

The live CDN object is 440x440, colour type 2 (RGB, no alpha), 16,962 bytes, uploaded 2026-07-11
14:58 UTC — the repo blob at commit `13e05fc`, whose message records that **OKX had already rejected an
earlier avatar** for dimensions and polish. It is a shield with a checkmark: competent, and generic.
Roughly 40 security-positioned agents share that iconography, so the mark identifies a category rather
than Warden. Worse, a checkmark is the universal glyph for *certified* — the exact claim invariant I5
forbids Warden from making, and the profile description explicitly disclaims with "narrow technical
evidence, not certification". The avatar contradicted the product's own stance.

The replacement now staged at `site/assets/warden-avatar.png` is a folded-ribbon gold **W** with a red
payload crushed flat against its centre peak and shattering. It states the service without words —
something hostile arrives, the boundary stops it before it lands — carries the site's own brand gold
(`#e0a23a` / `#f1c766` from `site/styles.css`), and contains no checkmark or seal. `favicon-32.png` and
`apple-touch-icon.png` are regenerated from the same mark, with heavier strokes so the letterform
survives 32px; the previous gold shield in those slots would otherwise have clashed with the new avatar.

Constraints re-verified against the accepted 2026-07-11 upload: PNG, 1:1, RGB (no alpha), 440x440,
33,318 bytes — far under the hard 1 MB cap. **No pixel-dimension requirement is published anywhere** —
not in the skill files, the CLI binary, or the ASP tutorial; the widely-repeated "440x440" is one
developer's inference from a rejection notice. Matching the previously accepted geometry and colour type
is deliberate risk reduction on the one axis this listing has already been rejected on.

**Timing is the whole safeguard.** `agent update --picture` re-enters review and de-lists the agent while
it runs, so this must NOT ship before the hackathon deadline. It belongs in the single post-deadline
delta alongside the four fee updates and the `/variant-audit` service — one review window, not three.

## The risk to weigh before confirming

An update re-enters review (`approvalStatus == 2` → "Under review — once approved it will go live
automatically"). Whether an already-approved listing stays publicly purchasable *during* that review is
**not yet confirmed**, and the hackathon requires the ASP to be live to remain eligible through
2026-07-27 23:59 UTC. That question is being checked against primary sources; the answer belongs in this
document before anyone confirms the write.
