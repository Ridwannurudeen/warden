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
  - `WARDEN_DEMO_RATE_LIMIT_PER_MIN=20` (shared limit for public demo and Gauntlet routes)
  - `WARDEN_REQUIRE_CONSENT=false` (set to `true` for hard consent enforcement)
  - `WARDEN_BADGE_SECRET=<strong-random-hmac-secret>` (required in production; the public development default is forgeable)

## First Deploy

Run locally from the repository root after explicit approval:

```bash
python scripts/build_site.py
python scripts/build_index.py --refresh

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
(
  set -a
  . /opt/warden/.env
  set +a
  .venv/bin/python scripts/build_index.py \
    --output /opt/warden-site/agents \
    --hire-catalog /opt/warden-site/data/warden-services.json \
    --marketplace-summary /opt/warden-site/data/marketplace-summary.json \
    --badge-store /opt/warden/badges/issued.jsonl \
    --badge-links /opt/warden/data/marketplace/badge-links-v1.json
)
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
python scripts/build_site.py
python scripts/build_index.py --refresh

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
(
  set -a
  . /opt/warden/.env
  set +a
  .venv/bin/python scripts/build_index.py \
    --output /opt/warden-site/agents \
    --hire-catalog /opt/warden-site/data/warden-services.json \
    --marketplace-summary /opt/warden-site/data/marketplace-summary.json \
    --badge-store /opt/warden/badges/issued.jsonl \
    --badge-links /opt/warden/data/marketplace/badge-links-v1.json
)
install -m 0644 deploy/nginx-warden.conf /etc/nginx/sites-available/warden.gudman.xyz.conf
nginx -t
systemctl restart warden.service
systemctl status warden.service --no-pager
systemctl reload nginx
```

## Nginx Shape

The production vhost serves real static pages from `/opt/warden-site`; unknown paths return 404 instead of falling back to the landing page.

The local pre-deploy build refreshes the marketplace snapshot through the read-only CLI. If that refresh fails, stop the deploy. Run `python scripts/build_index.py` without `--refresh` only when intentionally accepting the timestamp disclosed by the committed snapshot.

Issued badges remain runtime state on the VPS. After each upload, the VPS-side build reads `/opt/warden/badges/issued.jsonl` with the production signing environment in a subshell, then writes the public pages to `/opt/warden-site`. A badge is attached to an agent only when `data/marketplace/badge-links-v1.json` explicitly links its audit ID to that agent and the signed target host matches one of the agent's listed service hosts. Review each link before adding it; hostname matching alone is not ownership proof.

- `/` serves `site/index.html`.
- `/playground`, `/gauntlet`, `/hire`, `/integrate`, `/status`, `/privacy`, and `/terms` resolve to their matching `.html` files.
- `/agents` serves the generated marketplace index and `/agents/{numeric_id}` serves the corresponding generated agent page.
- `/docs` serves the generated documentation index and `/docs/{reason_slug}` serves a generated reason-code page.
- `/badges` serves the registry from `site/badges.html`; `/badges/{audit_id}` serves the verifier from `site/badge.html`.
- Singular `GET /badge/{audit_id}` remains the FastAPI badge-verification endpoint.
- `POST /scan`, `POST /audit`, and `GET /health` proxy to `http://127.0.0.1:8031`.
- `/api/*` proxies the free demo, Gauntlet, and badge-registry APIs to `http://127.0.0.1:8031`.
- `/assets/*`, `/data/*`, and other existing static files are served directly; missing files return 404.

The vhost enforces a self-only Content Security Policy. Site HTML, CSS, JavaScript, fonts, images, and browser API calls must not load from another origin. External links are navigation only.

Also serve `/.well-known/warden-consent` from `/opt/warden-site` when running in hard-consent mode. It should return HTTP 200 with body `warden-audit-allowed` and can be left absent when `WARDEN_REQUIRE_CONSENT=false`.

This keeps the FastAPI root JSON stub untouched while making the public root a multi-page static site.

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
curl -fsSI https://warden.gudman.xyz/playground
curl -fsSI https://warden.gudman.xyz/agents
curl -fsSI https://warden.gudman.xyz/docs
curl -fsSI https://warden.gudman.xyz/badges
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
- Extensionless static routes return their own HTML pages; an unknown route returns HTTP 404.
- `/agents/{id}` and `/docs/{reason_slug}` return their generated pages.
- `/badges` returns the static registry, while `/badge/{audit_id}` remains the JSON verification API.
- `/health` returns JSON 200.
- unpaid `/scan` and `/audit` return HTTP 402 with valid x402 v2 challenges.
- Browser smoke has no console errors and no cross-origin resource requests.
