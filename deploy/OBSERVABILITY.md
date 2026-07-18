# Runtime observability and APA anchor publication

Set `WARDEN_JSON_LOGS=1` to emit one compact JSON line for every completed HTTP scan. Each event
contains only a Warden-generated request ID, the verdict, and latency in milliseconds. Payloads,
contexts, detector matches, sanitized text, and secrets are never passed to the logger.

`GET /health/stats` exposes:

- process uptime;
- completed HTTP scan count;
- BLOCK counts grouped by implemented threat class;
- p50 latency over the most recent 1,024 completed scans.

These counters are process-local and reset on restart. They are operational signals, not historical
uptime, an SLA, or a durable audit record.

Publish the current signed APA checkpoint and append it to the committed public history with:

```bash
python scripts/publish_log_checkpoint.py
```

After preserving a returned `history_head_hash` outside the deployment, require that pin on every
later publication:

```bash
python scripts/publish_log_checkpoint.py --pinned-history-head <64-lowercase-hex>
```

The command writes `site/data/apa-log-anchor-history.json` first and then updates the legacy current
checkpoint file atomically. `GET /apa/log/anchor` exposes the current signed checkpoint from the
running service, but shares that service's storage boundary and is not an independent witness.
Independent retention or on-chain posting of a history-head hash remains an operator action.
