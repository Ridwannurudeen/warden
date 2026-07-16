# Trust Layer Deploy — Definitive Runbook (flat layout)

**Scope:** this deploy changes exactly ONE file on the VPS — the nginx vhost
`/etc/nginx/sites-available/warden.gudman.xyz.conf` — followed by `nginx -t` and one `systemctl reload nginx`.
Nothing else. The app code, the static site, and `warden.service` are already deployed and verified live.

**Why only nginx:** the 2026-07-16 outage happened because the previous `deploy/nginx-warden.conf` pointed at a
blue-green layout (`/opt/warden-site/current`, `/opt/warden-index/current`) that does not exist on this host.
The repo conf has been fixed to serve the flat layout that is actually deployed (`root /opt/warden-site;`,
agents/docs/data served from the same tree — `build_site.py` output and the generated agents pages are committed
into `site/` and synced flat). The only functional delta vs the currently live (rolled-back) conf is the three
missing proxy locations: `location /apa/`, `location = /.well-known/apa-issuer.json`, and it is otherwise
identical to the conf that is serving the site right now. Blue-green stays a future migration (see the note at
the top of `deploy/DEPLOY.md`).

**Shared-host rule:** the vhost file is warden-only (`server_name warden.gudman.xyz`). `nginx -t` validates the
whole nginx config; `reload` is graceful and does not drop other vhosts' traffic. No other project's files,
units, or ports are touched. Do not run `systemctl restart nginx` — reload only.

**Idempotency:** every step is safe to re-run. Installing the same conf twice and reloading twice is a no-op.

---

## Mandatory flat app-upgrade gate — signed log checkpoint and hardened unit

The numbered Trust Layer steps below remain nginx-only. When an approved deploy also replaces the flat
application at `/opt/warden`, this gate is mandatory before the new code starts. The app service is the flat
layout's transparency-log writer; any installed reprobe timer/service is stopped as well. A failed migration or
unit validation leaves the app stopped. Do not bypass that fail-closed state.

Before replacing any Python source or virtual-environment files, quiesce writers and take a cold database
backup:

```bash
set -euo pipefail
systemctl stop warden.service
for unit in warden-apa-reprobe.timer warden-apa-reprobe.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; fi
done
! systemctl is-active --quiet warden.service
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
four explicit runtime directories are writable. Then run the guarded migration with the application
environment loaded as `warden`:

```bash
set -euo pipefail
! systemctl is-active --quiet warden.service
chown root:root /opt/warden/pyproject.toml
chown -R root:root /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy /opt/warden/.venv
chmod 0644 /opt/warden/pyproject.toml
chmod -R u=rwX,go=rX /opt/warden/warden /opt/warden/scripts /opt/warden/site /opt/warden/deploy /opt/warden/.venv
install -d -o warden -g warden -m 0750 /opt/warden/data /opt/warden/badges /opt/warden/gauntlet /opt/warden/logs

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
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'log_checkpoint'"
    ).fetchone()
    has_checkpoint = table_exists is not None and connection.execute(
        "SELECT 1 FROM log_checkpoint WHERE singleton = 1"
    ).fetchone() is not None
finally:
    connection.close()

if has_checkpoint:
    checkpoint = read_log_checkpoint()
else:
    checkpoint = migrate_log_checkpoint()

entries = read_log()
if not verify_log_chain(entries, checkpoint):
    raise RuntimeError("transparency log does not match its signed checkpoint")
PY
WARDEN_MIGRATION

install -m 0644 /opt/warden/deploy/warden.service /etc/systemd/system/warden.service
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/warden.service
systemctl start warden.service
curl -fsS http://127.0.0.1:8031/health >/dev/null
if systemctl cat warden-apa-reprobe.timer >/dev/null 2>&1; then
  systemctl start warden-apa-reprobe.timer
fi
```

The guard calls `migrate_log_checkpoint()` only when the legacy database has no checkpoint row. That function
validates the complete contiguous legacy chain before signing it and refuses to overwrite an existing
checkpoint. On re-run, the existing signed checkpoint is verified against the full log instead, making the
overall gate idempotent without weakening either failure mode.

---

## Step 0 — Preflight (read-only gates; all must pass before touching anything)

```bash
ssh root@75.119.153.252 '
set -euo pipefail
systemctl is-active warden.service                                   # -> active
ss -tlnp | grep -q "127.0.0.1:8031"                                  # backend listening
test -f /opt/warden/site/log.html                                    # required by GET /apa/log html branch
                                                                     #   (warden/api.py:43 APA_LOG_PAGE = <app>/site/log.html)
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

**Gate (manual review):** the diff must show ONLY additions of the `location /apa/ { ... }` proxy block and the
`location = /.well-known/apa-issuer.json { ... }` proxy block (both proxying to `http://127.0.0.1:8031`).
No `root` change away from `/opt/warden-site`, no `/opt/warden-index`, no `current`, no listen/server_name/ssl
changes. If anything else appears, STOP and investigate — do not install.

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

# 5a. Every static page -> 200
for p in / /playground /hire /docs /status /badges /agents /agents/3808 /gauntlet /showcase /theater /verify /log /integrate /privacy /terms; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base$p")
  echo "$p -> $code"; test "$code" = 200
done

# 5b. Frozen paid contract: /scan and /audit -> 402, GET and POST (DO NOT expect anything else)
for m in GET POST; do for p in /scan /audit; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" -H 'content-type: application/json' -d '{"payload":"hi"}' "$base$p")
  echo "$m $p -> $code"; test "$code" = 402
done; done
curl -s -X POST -H 'content-type: application/json' -d '{"payload":"hi"}' "$base/scan" | grep -q '"outputSchema"'   # additive schema present
onchainos agent x402-check --endpoint "$base/scan" --body '{"payload":"hi"}'                                        # -> valid:true

# 5c. APA routes (the fix under test)
curl -fsS "$base/.well-known/apa-issuer.json" | grep -q '"issuer"'                        # 200 JSON
curl -fsS "$base/apa/log" | grep -q '"entries"'                                           # JSON branch
curl -fsS -H 'Accept: text/html' "$base/apa/log" | grep -qi '<html'                       # HTML branch (site/log.html)
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{}' "$base/apa/register")" = 422   # reaches FastAPI (422 validation), NOT 404/405 from nginx
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{}' "$base/apa/revoke")" = 422

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
delete files added by the new deploy; that is acceptable for restoring service.)

## What this deploy explicitly does NOT do

- No `warden.service` restart (app already runs the verified Trust Layer code).
- No changes to `/opt/warden`, `/opt/warden-site`, `/opt/warden/.env`, or any other project's footprint.
- No blue-green migration: `/opt/warden-index`, `current/` symlinks, `warden-fetch`, and the index/reprobe
  timers remain future work per `deploy/DEPLOY.md`.
