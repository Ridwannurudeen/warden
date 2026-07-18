# Service-level measurement policy

This policy defines Warden's public service-level evidence. It is an engineering measurement
contract, not a contractual service-level agreement. It creates no service credits, remedies, or
guaranteed uptime.

## Signals

The scheduled monitor records two bounded signals every five minutes:

- **Application readiness** is `ready` only when the local `GET /health/ready` response is HTTP 200
  and carries the exact documented `deterministic_scanner`, `paid_routes`, and `semantic_model`
  checks. The deterministic scanner and paid-route configuration must be ready; the optional
  semantic model may be ready or disabled.
- **Unsigned x402 challenge generation** is `ready` only when a benign `POST /scan` returns the
  pinned HTTP 402 challenge for `https://warden.gudman.xyz/scan`: x402 v2, the `exact` scheme,
  X Layer `eip155:196`, the published Warden recipient, 500000 base units, and the published USDT
  asset. The monitor never signs, pays, verifies a payer, or requests settlement.

The challenge signal establishes only that Warden generated the expected unsigned terms. It is not
payment availability, successful settlement, payer readiness, or third-party facilitator uptime.
The 99.5% objective published on the status page applies only to application readiness.

## Five-minute slots

Samples are assigned to UTC five-minute slots. If a slot contains multiple samples, that component
is ready only when every sample in the slot is ready. A missing slot, timeout, malformed response,
disabled payment path, HTTP failure, or explicit non-ready result is unavailable. This prevents
duplicate probes or missing evidence from improving the result.

The live status page anchors its rolling window to the browser's current checked time and reports a
30-day result only when all 8,640 current-window slots are observed. Slots after the latest sample
are therefore missing rather than silently excluded. A latest sample more than ten minutes old is
explicitly `stale`; the committed empty sentinel is `not running`. Before the current window is
complete, availability says `Not measured`. The deterministic monthly summarizer uses calendar
months in UTC and divides ready slots by every expected slot in that month, including missing slots.

## Evidence generation

`scripts/monitor_readiness.py` writes the bounded schema-v2 source record atomically.
`scripts/summarize_service_monitor.py --month YYYY-MM` produces a deterministic monthly summary with
the cadence, expected and observed slot counts, per-signal ready counts, percentages, completeness,
and the SHA-256 digest of the source bytes. The application field is `availability_percent`; the
unsigned challenge field is deliberately `readiness_percent`. `scripts/notify_service_transition.py`
evaluates the same ten-minute dead-man boundary. The monitor service checks the previous record before
each probe, so a missed interval becomes a deduplicated degradation event when scheduling resumes; the
public status surface exposes staleness immediately from the retained timestamp.

The source monitor retains at most 9,000 samples. Operators must preserve a completed month's source
and summary outside the rolling file if long-term evidence is required. A summary proves only what
the retained probes observed; it does not establish causes, user-visible success for every request,
or an independent third-party uptime measurement.
