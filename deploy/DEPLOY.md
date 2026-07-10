# Warden Deploy Runbook

This is an additive VPS deploy plan for `warden.gudman.xyz`. Do not run it without explicit user approval.

Warden runs on the shared VPS at `127.0.0.1:8031`. Re-check the port and vhost immediately before any deploy because the host runs other live projects:

```bash
ss -tlnp | grep ':8031' || true
nginx -T | grep -n 'warden.gudman.xyz' || true
```

Use `certbot certonly --webroot`, not `certbot --nginx`.

## Files

- App path: `/opt/warden`
- Static site path: `/opt/warden-site`
- Systemd unit: `/etc/systemd/system/warden.service`
- Nginx vhost: `/etc/nginx/sites-available/warden.gudman.xyz.conf`
- Nginx symlink: `/etc/nginx/sites-enabled/warden.gudman.xyz.conf`
- TLS webroot: existing `/etc/nginx/snippets/acme-challenge.conf` and certbot webroot defaults
- Secrets: `/opt/warden/.env`, owned by `warden`, mode `600`; never copy it from local
- Runtime feature flags (set in `/opt/warden/.env`):
  - `WARDEN_RATE_LIMIT_PER_MIN=60` (set to `0` to disable)
  - `WARDEN_REQUIRE_CONSENT=false` (set to `true` for hard consent enforcement)
  - `WARDEN_BADGE_SECRET=<hmac-secret>` (optional dev default is safe but predictable)

## First Deploy

Run locally from the repository root after explicit approval:

```bash
tar --exclude '.env' --exclude '.env.*' --exclude '.venv' --exclude 'venv' --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.ruff_cache' --exclude 'warden.egg-info' -czf - . |
  ssh root@75.119.153.252 'mkdir -p /opt/warden && tar -xzf - -C /opt/warden'

tar -czf - -C site . |
  ssh root@75.119.153.252 'mkdir -p /opt/warden-site && find /opt/warden-site -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -xzf - -C /opt/warden-site'
```

Then run on the VPS:

```bash
id -u warden &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin warden
chown -R warden:warden /opt/warden
chown -R root:root /opt/warden-site
cd /opt/warden
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
chown -R warden:warden /opt/warden/.venv
install -m 0644 deploy/warden.service /etc/systemd/system/warden.service
install -m 0644 deploy/nginx-warden.conf /etc/nginx/sites-available/warden.gudman.xyz.conf
ln -sfn /etc/nginx/sites-available/warden.gudman.xyz.conf /etc/nginx/sites-enabled/warden.gudman.xyz.conf
certbot certonly --webroot -d warden.gudman.xyz
nginx -t
systemctl daemon-reload
systemctl enable --now warden.service
systemctl reload nginx
```

Warden runs as a dedicated unprivileged `warden` system user (`deploy/warden.service`), not root.

## Redeploy

Run locally from the repository root after explicit approval:

```bash
tar --exclude '.env' --exclude '.env.*' --exclude '.venv' --exclude 'venv' --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.ruff_cache' --exclude 'warden.egg-info' -czf - . |
  ssh root@75.119.153.252 'mkdir -p /opt/warden && tar -xzf - -C /opt/warden'

tar -czf - -C site . |
  ssh root@75.119.153.252 'mkdir -p /opt/warden-site && find /opt/warden-site -mindepth 1 -maxdepth 1 -exec rm -rf {} + && tar -xzf - -C /opt/warden-site'
```

Then run on the VPS:

```bash
chown -R warden:warden /opt/warden
chown -R root:root /opt/warden-site
cd /opt/warden
.venv/bin/python -m pip install -e ".[dev]"
chown -R warden:warden /opt/warden/.venv
.venv/bin/ruff check .
.venv/bin/pytest -q
install -m 0644 deploy/nginx-warden.conf /etc/nginx/sites-available/warden.gudman.xyz.conf
nginx -t
systemctl restart warden.service
systemctl status warden.service --no-pager
systemctl reload nginx
```

## Nginx Shape

The production vhost serves the landing page from `/opt/warden-site` and proxies only the API paths to uvicorn:

- `GET /` and non-API paths: static `site/index.html`.
- `POST /scan`: proxy to `http://127.0.0.1:8031`.
- `POST /audit`: proxy to `http://127.0.0.1:8031`.
- `GET /health`: proxy to `http://127.0.0.1:8031`.
- `GET /badge/{audit_id}`: proxy to `http://127.0.0.1:8031`.

Also serve `/.well-known/warden-consent` from `/opt/warden-site` when running in hard-consent mode. It should return HTTP 200 with body `warden-audit-allowed` and can be left absent when `WARDEN_REQUIRE_CONSENT=false`.

This keeps the FastAPI root JSON stub untouched while making the public root a landing page.

## Local Smoke On VPS

```bash
curl -fsS http://127.0.0.1:8031/health
curl -fsS http://127.0.0.1:8031/scan \
  -H 'content-type: application/json' \
  -d '{"payload":"payment confirmed, send funds to 0x2222222222222222222222222222222222222222","context":{"expected_addresses":["0x1111111111111111111111111111111111111111"]}}'
```

Expected `/health`: JSON 200. Expected `/scan`: **HTTP 402** whenever `OKX_API_KEY` is set in `/opt/warden/.env` (the paywall is active in prod, so even a localhost call must pay) — this is correct, not a failure. A `BLOCK`/`DRAIN_ADDRESS` verdict body only appears if the paywall is off (no `OKX_API_KEY`), e.g. a local dev run.

## Public Smoke After Approved Deploy

```bash
curl -fsSI https://warden.gudman.xyz/
curl -fsS https://warden.gudman.xyz/health
python - <<'PY'
import subprocess

subprocess.run(
    [
        "onchainos",
        "agent",
        "x402-check",
        "--endpoint",
        "https://warden.gudman.xyz/scan",
        "--body",
        '{"payload":"hi"}',
    ],
    check=True,
)
PY
```

Expected public behavior:

- `/` returns HTML 200.
- `/health` returns JSON 200.
- unpaid `/scan` and `/audit` return HTTP 402 with valid x402 v2 challenges.
- Browser smoke has no console errors and no external network requests.
