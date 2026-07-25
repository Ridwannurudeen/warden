# Trust Layer Deploy — Definitive Runbook (flat layout)

**Scope:** the numbered vhost-only steps change exactly one nginx file. An approved flat application
upgrade must also follow the mandatory gate below, which installs the reviewed `warden.service`,
`warden-monitor.{service,timer}`, and `warden-anchor-publish.{service,timer}` from `/opt/warden`.
The two paths are intentionally separate; never install scheduled units during an nginx-only change.
Warden Shield is a separate, owner-enrolled opt-in lifecycle with its own service and daily timer; this
runbook does not install or enable it.

**Two artifacts, not one:** `/opt/warden` is the application; `/opt/warden-site` is the nginx static root
(`root /opt/warden-site;`). An app-only deploy leaves any new page 404 — `/lineage` did exactly that on
2026-07-25 until `site/` was overlaid into `/opt/warden-site` too. Back that directory up first, and preserve
the host-generated `data/marketplace-summary.json` and `data/warden-services.json`, which `build_index.py`
regenerates on the host and which Step 0 asserts.

**Log route boundary:** `/log` is the flat static compatibility page served from
`/opt/warden-site/log.html`. `/apa/log` is the canonical FastAPI route: it returns JSON by default and returns
the app copy of `site/log.html` only when the request explicitly accepts `text/html`.

**Why only nginx:** the 2026-07-16 outage happened because the previous `deploy/nginx-warden.conf` pointed at a
blue-green layout (`/opt/warden-site/current`, `/opt/warden-index/current`) that does not exist on this host.
The repo conf has been fixed to serve the flat layout that is actually deployed (`root /opt/warden-site;`,
agents/docs/data served from the same tree — `build_site.py` output and the generated agents pages are committed
into `site/` and synced flat). The reviewed functional deltas are the missing APA proxy locations plus exact
read-only aliases for `/data/service-monitor.json`, `/data/apa-log-anchor.json`, and
`/data/apa-log-anchor-history.json`. Those aliases point only into the flat `/opt/warden/monitor` and
`/opt/warden/anchor` runtime directories. Blue-green stays a future migration (see the note at the top of
`deploy/DEPLOY.md`).

**Shared-host rule:** the vhost file is warden-only (`server_name warden.gudman.xyz`). `nginx -t` validates the
whole nginx config; `reload` is graceful and does not drop other vhosts' traffic. No other project's files,
units, or ports are touched. Do not run `systemctl restart nginx` — reload only.

**Idempotency:** every step is safe to re-run. Installing the same conf twice and reloading twice is a no-op.

---

## Live install reality (verified 2026-07-25) — read before choosing a path

Always confirm with `ls /etc/systemd/system | grep -i warden` before acting; this section is a snapshot,
not a guarantee.

**Superseded 2026-07-25.** The 2026-07-19 snapshot recorded a minimal install with the monitor and anchor
lineage absent and told operators not to run the app-upgrade gate. That is no longer true: the gate has
since been run twice against this box, most recently for the 0.1 USDT deploy, and it installed the units it
describes. The evidence lineage is now live. Do not follow the older guidance.

Verified on the box (`75.119.153.252`) on 2026-07-25:

- `warden.service` — active, enabled. `User=warden`, `Group=warden`, `WorkingDirectory=/opt/warden`,
  `ExecStart=/opt/warden/.venv/bin/uvicorn warden.api:app --host 127.0.0.1 --port 8031`,
  `ReadWritePaths=/opt/warden/data /opt/warden/badges /opt/warden/gauntlet /opt/warden/logs`,
  `ProtectSystem=strict`, plus a `warden.service.d/privatetmp.conf` drop-in (`PrivateTmp=yes`).
- `warden-anchor-publish.service` (static) and `warden-anchor-publish.timer` — **active and enabled**.
- `warden-monitor.service` (static) and `warden-monitor.timer` — **installed but the timer is disabled**,
  deliberately, under the "deploy now, alert later" deviation documented in the gate below.
- `/opt/warden/monitor` and `/opt/warden/anchor` — **both exist**, mode `751` (`0750` plus the `o+x`
  traversal the gate grants so nginx can serve the aliased evidence files).
- `warden-a2a.service` — a separate OKX buyer-agent (#4844) daemon; unrelated to the API.
- `warden-scan-bot.service` — also present on the box and likewise unrelated to the API.

**Still absent:** `/opt/warden/monitor-alert.env`, so no alert destination is configured. That single fact
is what keeps `warden-monitor.timer` disabled and makes the monitor one-shot fail inertly; see the approved
deviation in the gate below. `warden-apa-reprobe.{service,timer}` are also still not installed.

**Choosing a path:** the app-upgrade gate below is the correct, exercised procedure for a source deploy, run
with that deviation. The minimal code-only redeploy that follows remains valid for a source-only change when
you want to skip the log-checkpoint migration and unit reinstall entirely.

### Minimal code-only redeploy (the procedure that matches this box)

For an approved change that touches only Python source with **no dependency change, no `protection.db`
schema change, and no new routes** (e.g. an additive request field), use this. It restarts `warden.service`
(~10s blip on the paid `/scan` `/audit` routes) and touches nothing else.

Run locally from the repo root after the reviewed commit is on `main` and the tracked worktree is clean:

```bash
set -euo pipefail
test -z "$(git status --porcelain --untracked-files=no)"   # no uncommitted tracked changes
release="$(git rev-parse --verify HEAD)"

# 1. Back up the live source (rollback artifact).
ssh root@75.119.153.252 'ts=$(date -u +%Y%m%dT%H%M%SZ); cd /opt/warden; tar czf "/root/warden-code.pre-$ts.tgz" warden scripts site deploy pyproject.toml; echo "backup: /root/warden-code.pre-$ts.tgz"'

# 2. Ship reviewed source to a staging dir and confirm the change is present.
git archive --format=tar HEAD | ssh root@75.119.153.252 'stage=$(mktemp -d /root/warden-stage.XXXXXX); tar -xf - -C "$stage"; test -f "$stage/warden/api.py"; echo "$stage" > /root/warden-stage.last; echo "staged: $stage"'

# 3. Overlay source, FIX PERMS, smoke-test, restart, verify.
ssh root@75.119.153.252 '
set -euo pipefail
stage=$(cat /root/warden-stage.last)
rsync -a --exclude ".venv/" --exclude ".env" --exclude "data/" --exclude "badges/" \
  --exclude "gauntlet/" --exclude "logs/" "$stage"/ /opt/warden/
# CRITICAL: rsync with a trailing-slash source copies the source ROOT dir mode onto /opt/warden.
# mktemp -d is 0700, which locks the warden user out of its own WorkingDirectory and the service
# crash-loops with status=200/CHDIR ("Changing to the requested working directory failed").
# Always reassert 755 on /opt/warden after any rsync/overlay.
chmod 755 /opt/warden
chown root:root /opt/warden/pyproject.toml
chown -R root:root /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy
chmod 0644 /opt/warden/pyproject.toml
chmod -R u=rwX,go=rX /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy
/opt/warden/.venv/bin/python -c "import warden.api, warden.auditor; print(\"import-ok\")"
systemctl reset-failed warden.service || true
systemctl restart warden.service
for i in $(seq 1 15); do curl -fsS http://127.0.0.1:8031/health >/dev/null && { echo health-ok; break; }; sleep 1; done
systemctl is-active warden.service
rm -rf -- "$stage"; rm -f /root/warden-stage.last
'
```

Then run the **Step 5** public verification below. Rollback: stop the service, extract the pre-deploy tarball
over `/opt/warden`, `chmod 755 /opt/warden`, restart.

---

## Mandatory flat app-upgrade gate — signed log checkpoint and hardened unit

> **Status (2026-07-25):** this gate is the exercised path — it has been run twice against the live box, most
> recently for the 0.1 USDT deploy, and the monitor/anchor units it installs are now present (see "Live install
> reality" above). The one prerequisite still missing is `monitor-alert.env`, so run it under the approved
> "deploy now, alert later" deviation below. The earlier 2026-07-19 drift warning, which said these units were
> absent and this gate should not be run, is superseded. The minimal code-only redeploy above remains a valid
> lighter alternative for a source-only change.

The numbered Trust Layer steps below remain nginx-only. When an approved deploy also replaces the flat
application at `/opt/warden`, this gate is mandatory before the new code starts. The app service is the flat
layout's transparency-log writer; any installed reprobe timer/service is stopped as well. A failed migration or
unit validation leaves the app stopped. Do not bypass that fail-closed state.

Before replacing any Python source or virtual-environment files, quiesce writers and take a cold database
backup:

```bash
set -euo pipefail

# Capture installed files and live enablement before quiescing anything.
unit_backup="/root/warden-evidence-units.pre-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$unit_backup"
install -d -m 0700 "$unit_backup"
for unit in \
  warden-monitor.service warden-monitor.timer \
  warden-anchor-publish.service warden-anchor-publish.timer
do
  if test -f "/etc/systemd/system/$unit"; then
    cp -a -- "/etc/systemd/system/$unit" "$unit_backup/$unit"
  else
    : > "$unit_backup/$unit.absent"
  fi
  systemctl is-enabled "$unit" > "$unit_backup/$unit.enabled" 2>/dev/null || true
  systemctl is-active "$unit" > "$unit_backup/$unit.active" 2>/dev/null || true
done
printf '%s\n' "$unit_backup" > /root/warden-evidence-units.last

systemctl stop warden.service
for unit in \
  warden-monitor.timer warden-monitor.service \
  warden-anchor-publish.timer warden-anchor-publish.service \
  warden-apa-reprobe.timer warden-apa-reprobe.service
do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
done
! systemctl is-active --quiet warden.service
! systemctl is-active --quiet warden-monitor.service
! systemctl is-active --quiet warden-anchor-publish.service
! systemctl is-active --quiet warden-apa-reprobe.service
test -f /opt/warden/data/protection.db
test ! -L /opt/warden/data/protection.db
backup="/root/warden-protection.pre-checkpoint-$(date -u +%Y%m%dT%H%M%SZ).db"
test ! -e "$backup"
cp -a -- /opt/warden/data/protection.db "$backup"
test -f "$backup"
```

Keep those units stopped while the reviewed app artifact and its dependencies are installed at the existing
flat paths. Source and virtual-environment files remain root-owned and read-only to the runtime user; only the
six explicit runtime directories are writable. Then run the guarded migration with the application
environment loaded as `warden`:

```bash
set -euo pipefail
! systemctl is-active --quiet warden.service
chown root:root /opt/warden/pyproject.toml
chown -R root:root /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy /opt/warden/.venv
chmod 0644 /opt/warden/pyproject.toml
chmod -R u=rwX,go=rX /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy /opt/warden/.venv
install -d -o warden -g warden -m 0750 \
  /opt/warden/data /opt/warden/badges /opt/warden/gauntlet /opt/warden/logs \
  /opt/warden/monitor /opt/warden/anchor

# nginx aliases /data/service-monitor.json, /data/apa-log-anchor.json and
# /data/apa-log-anchor-history.json into /opt/warden/monitor and /opt/warden/anchor.
# nginx runs as www-data, which is not in the warden group, so at 0750 it cannot
# traverse those directories and all three routes answer 403. Grant traversal only
# (o+x): the directory still cannot be listed, and every file inside is already
# public evidence served through those aliases. Verified necessary on 2026-07-25 —
# without this the three routes regress from 200 to 403.
chmod o+x /opt/warden/monitor /opt/warden/anchor

runuser -u warden -- env -i HOME=/opt/warden PATH=/opt/warden/.venv/bin:/usr/local/bin:/usr/bin:/bin bash -s <<'WARDEN_MIGRATION'
set -euo pipefail
set -a
. /opt/warden/.env
set +a
cd /opt/warden
exec .venv/bin/python - <<'PY'
import os
import sqlite3

from warden.protection_store import (
    migrate_log_checkpoint,
    read_log,
    read_log_checkpoint,
    verify_log_chain,
)

db_path = os.environ["WARDEN_PROTECTION_DB"]
connection = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True)
try:
    table_exists = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'log_anchor'"
    ).fetchone()
    has_anchor = table_exists is not None and connection.execute(
        "SELECT 1 FROM log_anchor WHERE singleton = 1"
    ).fetchone() is not None
finally:
    connection.close()

if has_anchor:
    checkpoint = read_log_checkpoint()
else:
    checkpoint = migrate_log_checkpoint()

entries = read_log()
if not verify_log_chain(entries, checkpoint):
    raise RuntimeError("transparency log does not match its signed checkpoint")
PY
WARDEN_MIGRATION

# Verify all candidates before replacing any installed unit.
systemd-analyze verify \
  /opt/warden/deploy/warden.service \
  /opt/warden/deploy/systemd/warden-monitor.service \
  /opt/warden/deploy/systemd/warden-monitor.timer \
  /opt/warden/deploy/systemd/warden-anchor-publish.service \
  /opt/warden/deploy/systemd/warden-anchor-publish.timer

# These four assertions require a configured alert destination before the monitor
# timer may be enabled. They are load-bearing: they run AFTER warden.service has
# already been stopped, so on a host without monitor-alert.env this gate aborts and
# leaves the app down. Verified missing on the live host 2026-07-25.
#
# APPROVED DEVIATION (2026-07-25, "deploy now, alert later"): when no alert
# destination is configured yet, skip these four assertions AND do not enable
# warden-monitor.timer below. The seeded service-monitor.json then keeps reporting
# status "not_running", which is the honest state and matches the published README.
# Re-running this gate with the file present is the way to adopt alerting later; it
# needs no app downtime. Do not skip these assertions while also enabling the timer.
#
# Under this deviation `systemctl start warden-monitor.service` below also FAILS, and
# that failure is expected and inert. Its ExecStartPre runs notify_service_transition.py,
# which requires WARDEN_ALERT_WEBHOOK_URL from the absent monitor-alert.env and returns 1
# (scripts/notify_service_transition.py:109,213), so ExecStart never reaches the readiness
# probe and service-monitor.json keeps its seeded "not_running" value. warden.service is
# unaffected. Observed 2026-07-25 during the 0.1 USDT deploy. Run it last, outside any
# `set -e` block that also starts the app, and `systemctl reset-failed
# warden-monitor.service` afterwards so the unit is not left in a failed state.
test -f /opt/warden/monitor-alert.env
test ! -L /opt/warden/monitor-alert.env
test "$(stat -c '%U:%G:%a' /opt/warden/monitor-alert.env)" = "root:warden:640"
grep -q '^WARDEN_ALERT_WEBHOOK_URL=https://' /opt/warden/monitor-alert.env

# The pre-quiesce block persisted the path so active/enabled state is not lost.
unit_backup="$(cat /root/warden-evidence-units.last)"
test -d "$unit_backup"

# Seed the bounded monitor and append-only anchor lineage only when no runtime copy exists.
# The `install -d` block earlier in this gate already created /opt/warden/monitor and
# /opt/warden/anchor at mode 0750 (verified absent on the live host 2026-07-25, so that
# block is doing real work on the first upgrade — do not skip it).
if ! test -e /opt/warden/monitor/service-monitor.json; then
  install -o warden -g warden -m 0644 \
    /opt/warden/site/data/service-monitor.json \
    /opt/warden/monitor/service-monitor.json
fi
if ! test -e /opt/warden/anchor/apa-log-anchor-history.json; then
  install -o warden -g warden -m 0644 \
    /opt/warden/site/data/apa-log-anchor-history.json \
    /opt/warden/anchor/apa-log-anchor-history.json
fi

install -m 0644 /opt/warden/deploy/warden.service /etc/systemd/system/warden.service
install -m 0644 /opt/warden/deploy/systemd/warden-monitor.service \
  /etc/systemd/system/warden-monitor.service
install -m 0644 /opt/warden/deploy/systemd/warden-monitor.timer \
  /etc/systemd/system/warden-monitor.timer
install -m 0644 /opt/warden/deploy/systemd/warden-anchor-publish.service \
  /etc/systemd/system/warden-anchor-publish.service
install -m 0644 /opt/warden/deploy/systemd/warden-anchor-publish.timer \
  /etc/systemd/system/warden-anchor-publish.timer
systemctl daemon-reload
systemd-analyze verify \
  /etc/systemd/system/warden.service \
  /etc/systemd/system/warden-monitor.service \
  /etc/systemd/system/warden-monitor.timer \
  /etc/systemd/system/warden-anchor-publish.service \
  /etc/systemd/system/warden-anchor-publish.timer
systemctl start warden.service
curl -fsS http://127.0.0.1:8031/health >/dev/null
systemctl start warden-monitor.service
systemctl start warden-anchor-publish.service
systemctl enable --now warden-monitor.timer warden-anchor-publish.timer
systemctl is-active --quiet warden-monitor.timer
systemctl is-active --quiet warden-anchor-publish.timer
systemctl list-timers --all warden-monitor.timer warden-anchor-publish.timer
printf 'Scheduled-unit rollback state: %s\n' "$unit_backup"
if systemctl cat warden-apa-reprobe.timer >/dev/null 2>&1; then
  systemctl start warden-apa-reprobe.timer
fi
```

The guard calls `migrate_log_checkpoint()` until the database has a local anchor row. That function validates
the complete contiguous legacy chain, adopts a matching pre-anchor signed checkpoint when present, or signs a
legacy head that has no checkpoint. Once anchored, the read path verifies the anchor, checkpoint, signature,
and full log together. Missing or malformed partial state fails closed, and re-running the gate is idempotent.

### Scheduled-unit rollback and restoration

If either one-shot fails validation or its first run, stop and restore the unit state before retrying.
Replace `<unit-backup-dir>` with the path printed by the install gate:

```bash
set -euo pipefail
backup=<unit-backup-dir>
systemctl disable --now warden-monitor.timer warden-anchor-publish.timer || true
systemctl stop warden-monitor.service warden-anchor-publish.service || true
for unit in \
  warden-monitor.service warden-monitor.timer \
  warden-anchor-publish.service warden-anchor-publish.timer
do
  if test -f "$backup/$unit.absent"; then
    rm -f -- "/etc/systemd/system/$unit"
  else
    install -m 0644 "$backup/$unit" "/etc/systemd/system/$unit"
  fi
done
systemctl daemon-reload
for timer in warden-monitor.timer warden-anchor-publish.timer; do
  if grep -qx enabled "$backup/$timer.enabled"; then
    systemctl enable "$timer"
  else
    systemctl disable "$timer" || true
  fi
  if grep -qx active "$backup/$timer.active"; then
    systemctl start "$timer"
  else
    systemctl stop "$timer" || true
  fi
done
```

Runtime JSON under `/opt/warden/monitor` and `/opt/warden/anchor` is retained during rollback as
forensic evidence. Restoring a previous anchor history must be a deliberate, independently pinned
lineage decision; never delete or silently replace it.

---

## Step 0 — Preflight (read-only gates; all must pass before touching anything)

```bash
ssh root@75.119.153.252 '
set -euo pipefail
systemctl is-active warden.service                                   # -> active
ss -tlnp | grep -q "127.0.0.1:8031"                                  # backend listening
test -f /opt/warden/site/log.html                                    # required by GET /apa/log HTML branch
test -f /opt/warden-site/log.html                                   # required by static GET /log
test -f /opt/warden-site/index.html
test -f /opt/warden-site/agents/index.html
test -f /opt/warden-site/agents/3808.html
test -f /opt/warden-site/docs/index.html
test -f /opt/warden-site/data/marketplace-summary.json
test -f /opt/warden-site/data/warden-services.json
test -f /root/warden-nginx.predeploy-1784174709.conf                 # rollback artifact present
curl -fsS http://127.0.0.1:8031/health >/dev/null
curl -fsS http://127.0.0.1:8031/.well-known/apa-issuer.json | grep -q "\"issuer\""
echo PREFLIGHT-OK
'
```

**Gate:** output ends with `PREFLIGHT-OK`. If any line fails, STOP — the problem is not nginx.

## Step 1 — Fresh backup of the currently live conf

```bash
ssh root@75.119.153.252 'cp -a /etc/nginx/sites-available/warden.gudman.xyz.conf /root/warden-nginx.pre-trustlayer-$(date +%s).conf && ls -la /root/warden-nginx.pre-trustlayer-*.conf'
```

**Gate:** the new backup file is listed. (The older `/root/warden-nginx.predeploy-1784174709.conf` remains the
deep-rollback artifact; this fresh one is the one-step rollback for THIS change.)

## Step 2 — Ship the fixed conf and review the diff before installing

Run from the local repo root (`warden/`):

```bash
scp deploy/nginx-warden.conf root@75.119.153.252:/root/warden-nginx.trustlayer.candidate.conf
ssh root@75.119.153.252 'diff -u /etc/nginx/sites-available/warden.gudman.xyz.conf /root/warden-nginx.trustlayer.candidate.conf || true'
```

**Gate (manual review):** the diff may show only the `location /apa/ { ... }`,
`location = /.well-known/apa-issuer.json { ... }`, `location = /harden { ... }` and
`location = /variant-audit { ... }` proxy blocks (all proxying to `http://127.0.0.1:8031`) plus these
exact aliases:

- `/data/service-monitor.json` → `/opt/warden/monitor/service-monitor.json`;
- `/data/apa-log-anchor.json` → `/opt/warden/anchor/apa-log-anchor.json`;
- `/data/apa-log-anchor-history.json` → `/opt/warden/anchor/apa-log-anchor-history.json`.

No `root` change away from `/opt/warden-site`, no `/opt/warden-index`, no `current`, no listen/server_name/ssl
changes, and no directory-wide alias for runtime state. If anything else appears, STOP and investigate.

`location = /harden` and `location = /variant-audit` are both expected here because the paid hardening and
adversarial variant-pack routes are additive and must reach the app — Step 5b below requires public
`/harden` and `/variant-audit` to answer 402. Both ride the same pinned rail as `/scan` and `/audit`
(0.1 USDT, `exact`, `eip155:196`); a diff that also changes a price or a rail parameter is out of scope for
this runbook and must STOP. `/lineage` must **not** appear as its own block: it is a static page served by
the existing `location /` catch-all (`try_files $uri $uri.html`).

## Step 3 — Install + syntax gate (the only mutating step)

```bash
ssh root@75.119.153.252 '
set -euo pipefail
install -m 0644 /root/warden-nginx.trustlayer.candidate.conf /etc/nginx/sites-available/warden.gudman.xyz.conf
nginx -t
'
```

**Gate:** `nginx -t` prints `syntax is ok` / `test is successful`. On failure, the running nginx is UNAFFECTED
(no reload happened); roll back the file immediately:

```bash
# Rollback for step 3 (replace <ts> with the step-1 timestamp)
ssh root@75.119.153.252 'cp -a /root/warden-nginx.pre-trustlayer-<ts>.conf /etc/nginx/sites-available/warden.gudman.xyz.conf && nginx -t'
```

## Step 4 — Reload nginx (graceful)

```bash
ssh root@75.119.153.252 'systemctl reload nginx'
```

Rollback for step 4 (restores prior behavior in one command):

```bash
ssh root@75.119.153.252 'cp -a /root/warden-nginx.pre-trustlayer-<ts>.conf /etc/nginx/sites-available/warden.gudman.xyz.conf && nginx -t && systemctl reload nginx'
```

## Step 5 — Full public verification (all must pass)

Run locally:

```bash
set -euo pipefail
base=https://warden.gudman.xyz

# 5a. Static pages and the /log compatibility page -> 200
for p in / /playground /hire /docs /status /badges /agents /agents/3808 /gauntlet /showcase /theater /verify /trust /lineage /log /integrate /privacy /terms; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base$p")
  echo "$p -> $code"; test "$code" = 200
done

# 5b. Frozen paid contract: /scan, /audit, /harden and /variant-audit -> 402, GET and POST
#     (DO NOT expect anything else). The paywall middleware answers before body validation, so the
#     probe body is irrelevant here: an unpaid request must be 402 and never 400/422 (that would mean
#     the paywall is not engaged). This holds for /variant-audit too even though the body below is not
#     a valid variant-audit request — a 400/422 there is a wiring failure, not a schema complaint.
for m in GET POST; do for p in /scan /audit /harden /variant-audit; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" -H 'content-type: application/json' -d '{"payload":"hi"}' "$base$p")
  echo "$m $p -> $code"; test "$code" = 402
done; done
curl -s -X POST -H 'content-type: application/json' -d '{"payload":"hi"}' "$base/scan" | grep -q '"outputSchema"'   # additive schema present
onchainos agent x402-check --endpoint "$base/scan" --body '{"payload":"hi"}'                                        # -> valid:true

# 5c. APA routes (the fix under test). /apa/log is canonical: JSON by default,
#     HTML only when the request explicitly accepts text/html.
curl -fsS "$base/.well-known/apa-issuer.json" | grep -q '"issuer"'                        # 200 JSON
curl -fsS "$base/apa/log" | grep -q '"entries"'                                           # JSON branch
curl -fsS -H 'Accept: text/html' "$base/apa/log" | grep -qi '<html'                       # HTML branch (site/log.html)
curl -fsS "$base/data/service-monitor.json" | grep -q '"schema_version": 2'
curl -fsS "$base/data/apa-log-anchor.json" | grep -q '"schema_version": 1'
curl -fsS "$base/data/apa-log-anchor-history.json" | grep -q '"history_head_hash"'
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{}' "$base/apa/register")" = 422   # reaches FastAPI (422 validation), NOT 404/405 from nginx
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{}' "$base/apa/revoke")" = 422
# Signed hardening-pack lookup: an unknown pack id must reach FastAPI and 404, not 404 from nginx.
# (A valid-format-but-absent id and a malformed id both return 404 — verified locally 2026-07-25.)
test "$(curl -s -o /dev/null -w '%{http_code}' "$base/apa/hardening/$(printf '0%.0s' $(seq 64))")" = 404
# Audit evidence lineage page (served by the static catch-all try_files, no dedicated nginx block).
curl -fsS "$base/lineage" | grep -q 'data-lineage'

# 5d. Demo APIs
curl -fsS -X POST -H 'content-type: application/json' -d '{"payload":"hello"}' "$base/api/demo/scan"    | grep -q '"verdict"'
curl -fsS -X POST -H 'content-type: application/json' -d '{"payload":"hello"}' "$base/api/demo/theater" | grep -q '"asp_receipt"'

# 5e. Co-host spot check (shared VPS collateral-damage proof)
test "$(curl -s -o /dev/null -w '%{http_code}' https://gapguard.gudman.xyz/)" = 200
test "$(curl -s -o /dev/null -w '%{http_code}' https://bequest.gudman.xyz/)" = 200

echo ALL-GREEN
```

**Gate:** `ALL-GREEN`. Any failure → run the step-4 rollback, re-verify the static pages return 200, then
investigate offline. (Note: `/api/demo/*` shares a 20/min rate limit; a 429 during rapid re-runs is the rate
limiter, not a deploy failure — wait a minute and retry.)

## Deep rollback — full return to the pre-Trust-Layer state

Only if you must undo the ENTIRE 2026-07-16 deploy (code + site + unit + nginx), not just this vhost change:

```bash
ssh root@75.119.153.252 '
set -euo pipefail
systemctl disable --now warden-monitor.timer warden-anchor-publish.timer || true
systemctl stop warden-monitor.service warden-anchor-publish.service || true
systemctl stop warden.service
tar -xzf /root/warden-code.predeploy-1784174709.tgz -C /opt/warden
tar -xzf /root/warden-site.predeploy-1784174709.tgz -C /opt/warden-site
install -m 0644 /root/warden-svc.predeploy-1784174709.service /etc/systemd/system/warden.service
install -m 0644 /root/warden-nginx.predeploy-1784174709.conf /etc/nginx/sites-available/warden.gudman.xyz.conf
systemctl daemon-reload
nginx -t
systemctl start warden.service
curl -fsS http://127.0.0.1:8031/health >/dev/null
systemctl reload nginx
'
```

(Verified 2026-07-16: both tarballs contain `./`-relative members, i.e. they were created from inside
`/opt/warden` and `/opt/warden-site`, so the `-C` targets above are correct. Note this overlays — it does not
delete files added by the new deploy; that is acceptable for restoring service.) After service recovery,
restore the four scheduled-unit files and their prior enablement from the recorded unit backup by following
**Scheduled-unit rollback and restoration** above. Do not re-enable either timer against rolled-back code.

## What the numbered nginx-only procedure does NOT do

- It does not replace or restart `warden.service`, and it does not establish that the installed app matches
  the current reviewed source. An approved application upgrade must use the mandatory flat app-upgrade gate
  above before the new code starts.
- It does not change `/opt/warden`, `/opt/warden-site`, `/opt/warden/.env`, or any other project's footprint.
  The monitor and anchor timers are installed only by the separate flat app-upgrade gate.
- It does not install the versioned-release Marketplace Evidence Index stack (`/opt/warden-index`,
  `current/` symlinks, or the `warden-fetch` identity). That migration remains governed by
  `deploy/DEPLOY.md`. An already installed APA re-probe timer is preserved and restarted by the flat
  app-upgrade gate; it is not installed by the numbered nginx steps.
- It does not install or enable Warden Shield. That owner-enrolled lifecycle remains a separate opt-in
  procedure documented in `docs/SHIELD_LIFECYCLE.md`.
