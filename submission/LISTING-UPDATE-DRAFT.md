# OKX.AI listing update — draft for review

**Date:** 2026-07-25
**Agent:** #3808 (Warden), owner `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51`
**Status:** DRAFT — not submitted. The on-chain write is gated on an explicit confirmation.

> Character limits and the exact service-key constraints are still being confirmed against OKX's own
> published rules. Wording below may need trimming once those land. Nothing here is authorized yet.

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

The update adds a **fourth** service with `operation: create` and leaves the three above untouched.

## Proposed new service — `/harden`

The endpoint is already live in production: `GET`/`POST https://warden.gudman.xyz/harden` answers a
correct x402 402 challenge on the pinned rail (`exact`, `eip155:196`, `500000`, `USD₮0` v1), and its
bazaar schema declares `required: ["audit_id"]`.

- **serviceName:** `Endpoint Hardening Pack`  (23 chars)
- **serviceType:** `A2MCP`
- **fee:** `"0.5"`  (quoted string, no currency suffix)
- **endpoint:** `https://warden.gudman.xyz/harden`
- **serviceDescription** (two parts, separate lines):

> Turns a completed Warden endpoint audit into a signed remediation pack: for every threat class the
> endpoint failed to block, it returns example attacks, the detection families and analyzers that catch
> them, and where to place enforcement so the block happens before the action. Each pack is signed and
> recorded in a public transparency log, so a later re-audit can show the grade actually moved.
>
> Provide: the audit_id of a completed Warden endpoint audit.

## Proposed profile description

Positioning: **technical automation + agent training**, with the gateway named honestly as serving-path
infrastructure rather than a hosted product.

> Security automation and agent training for the agent economy. Warden screens untrusted responses, tool
> outputs, and messages for prompt injection, hijacked tool calls, drain or attacker payout addresses, and
> secret exfiltration, returning ALLOW / SANITIZE / BLOCK before your agent acts. It audits another agent's
> endpoint against a fixed attack battery, then issues a signed Hardening Pack naming exactly what to fix
> and re-audits to show whether the grade moved. A fail-closed gateway is available to run in front of your
> own serving path. It returns narrow technical evidence, not certification.

Deliberate choices: no links, no example prompts, no tech-stack list, no pricing, no celebrity or
third-party names, and the final sentence keeps the honesty commitment that Warden never claims
certification.

## Avatar

Under assessment. The live avatar is
`https://static.okx.com/cdn/web3/wallet/marketplace/headimages/agent/avatar/65ae9b37-4cd0-40d8-8440-affa2d333090.png`
and the repo copy is `site/assets/warden-avatar.png`. It will only be replaced if it actually fails a
published requirement — a working avatar on a 5.0-rated listing is not worth churning for taste.

## The risk to weigh before confirming

An update re-enters review (`approvalStatus == 2` → "Under review — once approved it will go live
automatically"). Whether an already-approved listing stays publicly purchasable *during* that review is
**not yet confirmed**, and the hackathon requires the ASP to be live to remain eligible through
2026-07-27 23:59 UTC. That question is being checked against primary sources; the answer belongs in this
document before anyone confirms the write.
