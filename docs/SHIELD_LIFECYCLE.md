# Warden Shield lifecycle

Warden Shield is source-ready, not deployed. It schedules recurring endpoint audits only for targets whose
owners have been explicitly enrolled by an operator. It does not create a contractual SLA, certification, or
proof of future safety. Each successful result remains point-in-time evidence.

## Enrollment contract

Start from `deploy/shield-targets.example.json`. The installed
`/opt/warden/shield-targets.json` must be a regular root-owned file, readable by the `warden` group, and must
contain no more than 32 targets. Each target binds:

- a stable `target_id` and `owner_id`;
- literal `owner_enrolled: true`;
- a monotonically increasing `enrollment_revision`;
- one canonical HTTPS endpoint without credentials, query parameters, or a fragment;
- a re-audit interval from 24 through 672 hours;
- the expected fixed battery ID, version, and SHA-256; and
- optionally `"delivery": {"webhook_url": "<HTTPS URL>"}`, the owner's own destination for this
  target's alerts.

The optional `delivery` block is part of the hashed enrollment, so adding, changing, or removing it
requires an incremented `enrollment_revision` like any other enrollment change. When a target enrols a
destination it is used instead of the operator-wide `WARDEN_SHIELD_WEBHOOK_URL`; a target with no
`delivery` block still falls back to that single global operator webhook.

Owner enrollment does not replace endpoint consent. Every run still uses `AgentAuditor`, which performs the
existing SSRF-safe public-address validation, IP-pinned request, `/.well-known/warden-consent` check, fixed
attack battery, benign liveness controls, response limits, and 30-second total deadline. Shield never supplies
caller prompts or bypasses those boundaries.

Changing an endpoint, owner, interval, or expected battery requires increasing `enrollment_revision`. A
revision rollback or an unversioned change fails closed. Removing a target unenrolls it; an explicit empty
target list is valid.

## Evidence and comparison

A conclusive audit follows the existing evidence path:

```text
AgentAuditor
  -> signed version-2 audit badge
  -> badge store
  -> portable Ed25519 APA audit record
  -> issuance entry in the transparency log
  -> Shield lifecycle comparison
```

Shield verifies the full badge, reuses the idempotent badge-to-APA publication function, requires intact log
evidence, checks that the portable record is active and unexpired, and binds its subject to the enrolled URL.
It compares results only when the previous and observed records have the same battery ID, version, and SHA-256.

| State          | Meaning |
| -------------- | ------- |
| `initial`      | First active, conclusive signed record for this enrollment revision. |
| `unchanged`    | Same battery and score as the prior accepted record. |
| `improved`     | Same battery and a higher score. |
| `regressed`    | Same battery and a lower score. |
| `inconclusive` | Audit failure, partial audit, missing/invalid/stale/revoked evidence, subject mismatch, or battery change. |

An inconclusive or stale result never replaces the prior accepted baseline. A battery change is also
inconclusive until the owner is re-enrolled with an incremented revision and the new expected battery. That
explicit revision deliberately starts a new baseline instead of comparing across batteries. The auditor may
publish a genuinely conclusive point-in-time record before Shield discovers that its battery is not the
enrollment's expected battery; Shield records that observation but does not renew the lifecycle baseline.

The state file is an atomically replaced, fsync-backed JSON document protected by both an OS file lock and the
service's outer `flock`. It retains at most 32 target states and 1,000 events. Events contain target IDs,
scores, battery identities, timestamps, audit IDs, and fixed operator actions. Shield does not store probe
payloads, target URLs, response bodies, signatures, credentials, or exception text in lifecycle events.

## Continuous hardening

A conclusive audit that Shield accepts as a baseline is also checked against the per-class findings the
auditor retained for that same `audit_id`. Shield issues a signed hardening pack when the drift is
`regressed`, or when the retained findings show at least one unblocked class. Issuance reuses the existing
`hardening.publish_pack` path, so the pack is Ed25519-signed by the same issuer, committed to the same
hash-chained transparency log, and readable at `/apa/hardening/{pack_id}`. There is no second signing
scheme and no pack content beyond the committed training corpus and guidance table.

An inconclusive comparison never issues a pack. Shield refuses to build remediation on evidence it also
refuses to accept as a baseline, which covers audit failure, an inconclusive grade, missing, invalid,
stale, or revoked evidence, a subject mismatch, and a battery change.

The pack outcome is recorded on the lifecycle event as a bounded `hardening` block holding a status, the
`pack_id`, the source `audit_id`, and the addressed class names. Issuance is idempotent per `audit_id`, so
a repeated observation of one audit returns the existing pack instead of committing a second one. Because
the block is not part of the event's hashed identity, a transient issuance failure does not change the
`event_id`.

| Status | Meaning |
| ------ | ------- |
| `not_applicable` | Inconclusive comparison, or a conclusive audit that missed no class. |
| `findings_unavailable` | No retained per-class findings for that audit; no pack was built. |
| `issue_failed` | Signing or log commitment failed; the run exits nonzero. |
| `issued` | A signed, log-committed pack exists for that audit. |

## Alerts and service outcome

Regressions, inconclusive runs, issued packs, and failed pack issuance create actionable bounded events.
Alerts go to the target's enrolled `delivery.webhook_url` when it has one, and otherwise to the
operator-wide `WARDEN_SHIELD_WEBHOOK_URL`. Either must be HTTPS and receives only the event metadata above
plus the `hardening` block, with redirects and ambient proxy settings disabled. Delivery is attempted at
most twice per event under one `Idempotency-Key`; failure after that is persisted without logging the URL
or error detail. Pack contents, including example payloads, are never pushed to a webhook — the alert
carries only the `pack_id` needed to fetch the signed pack.

The runner exits nonzero for every regression, inconclusive result, or failed pack issuance, even when
webhook delivery succeeds. This gives systemd and external operators a clear failure signal when no
notifier is configured. Initial, unchanged, and improved runs return zero. Journal output is count-only.

## Operator preparation

No command in this section has been run against a server. Deployment requires explicit approval.

Create `/opt/warden/shield.env` as a regular `root:warden` file with mode `0640`. Give it only the values
Shield needs:

```text
WARDEN_ENVIRONMENT=production
WARDEN_REQUIRE_CONSENT=true
WARDEN_BADGE_SECRET=<existing badge integrity secret>
WARDEN_ISSUER_KEY=<existing current issuer seed>
WARDEN_ISSUER_KID=<existing current issuer key ID>
WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history.json
WARDEN_PROTECTION_DB=/opt/warden/data/protection.db
WARDEN_SHIELD_WEBHOOK_URL=<optional HTTPS operator webhook for targets with no enrolled destination>
```

Do not copy payment, wallet, model-provider, marketplace, or analytics credentials into this file. The
service cannot read the main application or index environment files.

After reviewing the exact release and target enrollments:

```bash
set -euo pipefail
test -f /opt/warden/shield-targets.json
test ! -L /opt/warden/shield-targets.json
test -f /opt/warden/shield.env
test ! -L /opt/warden/shield.env
test "$(stat -c '%U:%G:%a' /opt/warden/shield-targets.json)" = root:warden:640
test "$(stat -c '%U:%G:%a' /opt/warden/shield.env)" = root:warden:640
install -d -o warden -g warden -m 0700 /opt/warden/data/shield

systemd-analyze verify \
  /opt/warden/deploy/systemd/warden-shield.service \
  /opt/warden/deploy/systemd/warden-shield.timer
install -m 0644 /opt/warden/deploy/systemd/warden-shield.service \
  /etc/systemd/system/warden-shield.service
install -m 0644 /opt/warden/deploy/systemd/warden-shield.timer \
  /etc/systemd/system/warden-shield.timer
systemctl daemon-reload
systemctl start warden-shield.service
systemctl enable --now warden-shield.timer
systemctl list-timers --all warden-shield.timer
journalctl -u warden-shield.service -n 100 --no-pager
```

The daily timer audits only due targets, uses up to 15 minutes of scheduling jitter, and catches a missed
calendar run with `Persistent=true`. The source unit has a 20-minute whole-service limit; the enrollment cap
and auditor's per-target deadline keep work bounded. The maximum 28-day interval is two days shorter than the
portable audit record's 30-day lifetime, leaving renewal margin for the daily schedule and its jitter.

To stop recurring audits without deleting forensic state:

```bash
systemctl disable --now warden-shield.timer
systemctl stop warden-shield.service || true
```

Retain `/opt/warden/data/shield/lifecycle.json` for review. Removing or rewriting it discards the local
comparison lineage; it does not revoke already issued badge or APA evidence.

## Commercial boundary

This implementation supplies the finite lifecycle mechanism, signed renewals, drift records, and operator
timer. It does not establish that a live managed Shield service is deployed, that any customer enrolled, that
alert delivery was configured, that a recurring audit completed in production, or that a commercial support
or response commitment exists.
