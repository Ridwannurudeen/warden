# Hosted Gateway — Design Boundary

**Status:** design boundary only. **Nothing here is built, deployed, priced, or offered.** This document
exists so that a future hosted offering has a written contract to be measured against, and so the shape of
that offering does not get decided implicitly by an implementation detail.

The local gateway that *is* built — `warden-gateway`, a fail-closed reverse proxy the operator runs
themselves — is documented in [`deploy/GATEWAY.md`](../deploy/GATEWAY.md) and is unaffected by everything
below.

## Scope note: `--mode hosted` is not this

`sdk/python/warden_guard/gateway.py` accepts `--mode hosted`, which makes the **operator's own** gateway call
Warden's hosted `/scan` instead of scanning in-process. That is a client-side transport choice inside a
single-tenant deployment. It is **not** the multi-tenant hosted gateway described here, and the two must not
be conflated in documentation or marketing.

## Non-negotiable invariants

### I-A. Local operation never depends on hosted availability
The self-hosted gateway must keep working with no network path to any Warden-operated service. A hosted
offering may not introduce a phone-home, a licence check, a required registration, or a config default that
degrades local operation when Warden is unreachable. Local mode is the product; hosted is a convenience.

### I-B. Fail-closed is preserved per tenant
The existing guarantee — a `BLOCK`, an invalid decision, or a scanner failure never reaches the upstream
application — applies per tenant. A hosted control-plane failure must fail **closed** for the tenant, never
open. Quota exhaustion is also a closed failure (§Quotas), not a silent pass-through.

### I-C. No paid hosted mode until the payment stack is verified
Hosted paid mode must not be exposed until the installed payment library is confirmed to support the chosen
transport. As of 2026-07-25 the installed `okxweb3-app-x402==0.1.0` implements **only** the `exact` scheme
(`aggr_deferred` is server-side only, with no client); `upto`, `period`/`permit2_subscription`, and MPP
session/voucher primitives are absent — see [`MODERN_PAYMENT_RAILS_DESIGN.md`](MODERN_PAYMENT_RAILS_DESIGN.md).
A metered hosted gateway therefore has **no supported transport today**, and inventing one off-rail is out of
scope.

### I-D. Hosted deployment and pricing are operator/business decisions
This document does not set a price, a tier, an SLA, or a launch date. It defines only the technical contract
such an offering would have to satisfy.

## Required decisions, and the standard each must meet

### Tenant authentication
A hosted gateway terminates traffic for parties who are not the operator, so tenant identity has to be
established before any scan is attributed or billed.

- Long-lived shared secrets in config files are not acceptable as the only mechanism.
- Credentials must be revocable per tenant without redeploying, and rotation must not require downtime.
- A rejected or unknown credential is a closed failure, and the rejection must not leak whether the tenant
  exists.
- Warden already has an Ed25519 issuer and an endpoint-key TOFU binding for APA; reuse an existing primitive
  rather than adding a fourth key system.

### Isolation
- No tenant may observe another tenant's payloads, verdicts, counters, or timing.
- The bounded per-process metrics the local gateway exposes (`/metrics`: eight base metrics — rendered as
  twelve lines, since the two latency histograms also emit `_count` and `_sum` — with zero variable labels,
  so cardinality is constant) are **single-tenant by construction**. A hosted deployment must not relabel
  them per tenant
  — that reintroduces unbounded cardinality and turns the metrics surface into a cross-tenant side channel.
- State (rate windows, verified-payer grants, quota counters) must be keyed by tenant with no shared
  mutable structure that one tenant can grow without bound.

### Quotas
- Every tenant has an explicit ceiling; there is no unlimited tier by omission.
- Quota exhaustion fails **closed** for that tenant and is visible to them as a distinct, documented
  condition — never silently degraded scanning, never a best-effort `ALLOW`.
- Quota accounting must survive a restart, and must not be reconstructible from another tenant's traffic.

### Payment transport
Blocked by I-C. When it unblocks, the transport must be named explicitly, its scheme confirmed against the
installed library **and** the facilitator's live `/supported` response for the target network, and the
existing pinned `exact` rail must remain the untouched default. `scripts/monitor_readiness.py` currently
hard-fails unless the 402 challenge carries **exactly one** `accepts` entry, so adding a second payment
option to a live route breaks production monitoring — that check has to be reworked deliberately, not
bypassed.

### Replay protection
- A payment authorization must grant exactly one unit of service. Published 2026 research on x402 records
  248 grants obtained from a single authorization against servers without idempotency, so this cannot be
  left to the transport.
- Scan requests must be idempotent under retry, keyed so that a replayed request is recognizable per tenant.
- Responses must carry `Cache-Control: no-store`; the same research records complete cache leakage of paid
  responses through a default nginx configuration.

### Retention
- Default retention for tenant payloads is **none**. A hosted gateway that stores what it scans becomes the
  highest-value target in the system.
- Anything retained requires explicit per-tenant opt-in, a stated bound, and redaction on the way in —
  mirroring the existing feedback contract (`POST /api/feedback`: explicit consent, caller-redacted
  reproducer, 90-day bound, no field for the original payload).
- Aggregate reporting stays k-anonymous, as the current threat-intel summary already is (k=5).

### Failure semantics
Each of these needs a defined, documented behaviour before launch — and every one of them resolves to a
closed failure for the affected tenant:

| Condition | Required behaviour |
| --- | --- |
| Control plane unreachable | tenant fails closed; other tenants unaffected |
| Tenant credential invalid or revoked | closed, no existence disclosure |
| Quota exhausted | closed, distinct documented condition |
| Scanner error | closed (already the local contract) |
| Payment verification unavailable | closed; never provisional service |
| Upstream tenant application down | tenant's own error surfaces unchanged; not reported as a Warden verdict |

## What would have to be true before any hosted launch

1. I-C unblocked: a real transport verified against the installed library and the live facilitator.
2. Each decision above resolved in writing, with tests for the closed-failure paths.
3. A published statement of what the hosted mode does **not** guarantee, consistent with the existing honest
   limits — in particular that `ALLOW` means no implemented detector fired, not that a payload is safe.
4. An explicit operator decision on retention and pricing (I-D).

Until then, the honest description of Warden's gateway is the one already published: a fail-closed reverse
proxy the operator runs themselves, with no hosted multi-tenant offering.
