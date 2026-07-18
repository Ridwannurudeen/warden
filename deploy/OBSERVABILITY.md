# Runtime observability, service evidence, and APA anchor publication

Set `WARDEN_JSON_LOGS=1` to emit one compact JSON line for every completed HTTP scan. Each event
contains only a Warden-generated request ID, the verdict, and latency in milliseconds. Payloads,
contexts, detector matches, sanitized text, and secrets are never passed to the logger.

`GET /health/stats` exposes:

- current worker uptime;
- completed HTTP scan count across workers;
- BLOCK counts grouped by implemented threat class;
- p50 latency over the most recent 1,024 completed scans.

Production sets `WARDEN_METRICS_DB=/opt/warden/data/runtime-metrics.db`. The bounded SQLite store
survives application restarts and aggregates multiple workers. It contains only totals, threat-class
counts, and latency values; it has no payload, context, match, URL, secret, or sanitized-content
column. Every SQLite connection is closed after its bounded transaction or read. A storage failure
cannot fail a scan: the worker retains bounded local deltas, merges them into snapshots while the
store is unavailable, and flushes each delta exactly once after recovery. These remain operational
signals, not historical uptime, an SLA, or an audit record.

Production also sets `WARDEN_RATE_LIMIT_DB=/opt/warden/data/rate-limit.db`. Fixed-window counters
and verified-payer grants are committed under SQLite write transactions, so restarts and separate
processes cannot reset or independently spend the same quota. Each operation removes expired
windows and grants. The database stores only rate-limit scope, canonical client address,
window/count, and grant expiry. If it cannot be opened or committed, protected routes fail closed
with `429`; verified-payer elevation is withheld.

When `WARDEN_RATE_LIMIT_DB` is absent, local development and tests use one temporary database per
process. That keeps an unconfigured local server usable without creating repository state, but it is
not a multi-process production mode. Every production launcher must set the shared path explicitly.

Production runs two Uvicorn workers after verifying each mutable safety boundary:

- runtime metrics and rate limits use their configured bounded SQLite stores;
- APA protection records, nonce replay state, transparency entries, and anonymous outbound-probe
  leases share `WARDEN_PROTECTION_DB=/opt/warden/data/protection.db`;
- Gauntlet and feedback records use cross-process locks, atomic replacement, and bounded retention;
- the legacy badge registry uses the same locked, atomic retention pattern.

Every API worker and the scheduled re-probe process acquires one anonymous SQLite lease before
validating DNS or opening an outbound connection. The transaction removes expired leases and admits
at most four probes across all processes. Leases contain only a random identifier and expiry, never
an endpoint, payload, proof, or response. Normal completion and cancellation release the lease;
process crashes cannot leave a permanent slot because orphaned leases expire after ten seconds.
SQLite contention is bounded to 500 milliseconds. Full capacity or an unavailable admission store
fails closed before network access. The in-process semaphore remains as a local backstop.

When `WARDEN_PROTECTION_DB` is absent, local development retains the in-process four-probe cap and
does not require a shared admission database. This is not an approved multi-worker mode.

The legacy HMAC badge registry is atomically rewritten under a cross-process file lock and retains
the newest 5,000 records. A failed replacement leaves the prior complete registry in place. This
bounds steady-state JSONL size and lookup cost; records older than the retained window are no longer
available from the legacy badge endpoints. Portable endpoint-audit attestations use their separate
signed SQLite/transparency-log lifecycle.

## Scheduled service evidence

`warden-monitor.timer` runs every five minutes. Its service records both the exact local application
readiness response and the pinned unsigned `/scan` x402 challenge in
`/opt/warden/monitor/service-monitor.json`. The challenge check proves only generation of Warden's
published unsigned terms; it does not sign, pay, settle, or measure facilitator uptime. Before each
probe, the notifier evaluates the previous timestamp against a ten-minute dead-man boundary. It
sends HTTPS webhook events only on deduplicated degradation and recovery transitions. Its URL is read from
`WARDEN_ALERT_WEBHOOK_URL` in the root-managed `/opt/warden/monitor-alert.env`; it is never placed on
the command line or in the published evidence. Failed notifications do not advance notifier state,
so the next run retries the same transition.

The webhook is an operator-controlled residual trust boundary: root can configure an HTTPS endpoint
on a private network, and the notifier is permitted to contact it. Protect and review that file as
carefully as any outbound infrastructure configuration; the application never accepts a webhook URL
from a request or public JSON.

Create `/opt/warden/monitor` as `warden:warden` mode `0750`. Keep
`monitor-alert.env` as `root:warden` mode `0640`. Install and enable
`warden-monitor.service` and `warden-monitor.timer` only after the webhook and the exact paths have
been reviewed. Nginx serves only the evidence JSON through the exact
`/data/service-monitor.json` alias; notifier state remains private.

The status page anchors the rolling 30-day window to its current checked time, marks a latest sample
older than ten minutes as stale, and does not claim achieved availability until all current-window
slots exist. It reports application readiness and unsigned x402 challenge generation separately.
For a completed calendar month, generate deterministic evidence with:

```bash
python scripts/summarize_service_monitor.py \
  --input /opt/warden/monitor/service-monitor.json \
  --month YYYY-MM \
  --output /opt/warden/monitor/service-level-YYYY-MM.json
```

Missing, disabled, malformed, and failed slots count as unavailable. Preserve completed source and
summary files before the bounded live window rolls forward. `docs/SERVICE_LEVEL_POLICY.md` is the
measurement contract; it is not a contractual SLA.

## Public APA checkpoint history

Publish the current signed APA checkpoint and append it to the committed public history with:

```bash
python scripts/publish_log_checkpoint.py
```

After preserving a returned `history_head_hash` outside the deployment, require that pin on every
later publication:

```bash
python scripts/publish_log_checkpoint.py --pinned-history-head <64-lowercase-hex>
```

The command writes the history first and then updates the legacy current checkpoint file atomically.
`warden-anchor-publish.timer` runs that publisher every fifteen minutes against the read-only
protection database and writes to `/opt/warden/anchor`. The service reads
only the database path from its unit. It blocks both application and index environment files and
does not load signing material.

Before enabling the timer, create `/opt/warden/anchor` as `warden:warden` mode `0750` and seed
`apa-log-anchor-history.json` there from the reviewed committed empty history. Nginx serves the
current checkpoint and full history through exact read-only aliases. The browser validates the log
chain once, then checks each bounded history checkpoint against its precomputed prefix hash.

`GET /apa/log/anchor`, the static current checkpoint, and same-origin history still share Warden's
operator boundary. Preserve a returned `history_head_hash` outside the deployment and compare or pin
it independently to detect coherent rollback. Independent retention or on-chain posting of a
history-head hash remains an operator action; the timer does not claim that an external witness
exists.
