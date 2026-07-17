# Warden Deploy Runbook

> **Production note (2026-07-16):** the live VPS runs a FLAT layout (`/opt/warden` app dir, `/opt/warden-site`
> static dir, no `current/` symlinks, no `/opt/warden-index`, no `warden-fetch` user or index units). The
> blue-green release layout described below was never installed and installing its nginx conf against the flat
> layout caused a full static-site outage on 2026-07-16. `deploy/nginx-warden.conf` now targets the flat layout.
> **The current, verified production procedure is `deploy/TRUST-LAYER-DEPLOY.md` — use that.** This file is the
> long-form design for a future migration to the versioned-release layout; do not run its activation block
> until that migration is explicitly undertaken (it requires the `warden-fetch` user, index units, `index.env`,
> `issuer-history.json`, and an authenticated `onchainos` CLI on the VPS, none of which exist today).

This is an additive VPS deploy plan for `warden.gudman.xyz`. Do not run it without explicit user approval.

Warden runs on the shared VPS at `127.0.0.1:8031`. Re-check the port and vhost immediately before any deploy because the host runs other live projects:

```bash
set -euo pipefail
ss -tlnp | grep ':8031' || true
nginx -T | grep -n 'warden.gudman.xyz' || true
```

Use only `certbot certonly --webroot` for certificate issuance.

## Files

- App path: `/opt/warden/current` (atomic symlink to `/opt/warden/releases/<commit>`)
- Persistent app state: `/opt/warden/.env`, `/opt/warden/badges`, `/opt/warden/gauntlet`, `/opt/warden/data`, and `/opt/warden/logs`; none live inside a release
- Static site path: `/opt/warden-site/current` (atomic symlink to `/opt/warden-site/releases/<commit>`)
- Live index path: `/opt/warden-index`; immutable captures live under `/opt/warden-index/releases/<capture>`
- Public snapshot handoff: `/opt/warden-snapshot/agents-v1.jsonl`, atomically replaced by the secretless fetch service and read by the index builder
- Systemd unit: `/etc/systemd/system/warden.service`
- Index units: `/etc/systemd/system/warden-index-fetch.service`, `/etc/systemd/system/warden-index.service`, and `/etc/systemd/system/warden-index.timer`
- APA freshness units: `/etc/systemd/system/warden-apa-reprobe.service` and `/etc/systemd/system/warden-apa-reprobe.timer`
- Nginx vhost: `/etc/nginx/sites-available/warden.gudman.xyz.conf`
- Nginx symlink: `/etc/nginx/sites-enabled/warden.gudman.xyz.conf`
- TLS webroot: existing `/etc/nginx/snippets/acme-challenge.conf` and certbot webroot defaults
- Application secrets: `/opt/warden/.env`, owned by `root:warden`, mode `640`; never copy it from local or source it as root
- Issuer history: `/opt/warden/issuer-history.json`, owned by `root:warden`, mode `640`; it contains only recent verify-only public keys and finite retirement cutoffs
- Index environment: `/opt/warden/index.env`, owned by `root:warden`, mode `640`, containing only `WARDEN_BADGE_SECRET`, the current public `WARDEN_ISSUER_PUBLIC_KEY`, and `WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history.json`; only the `warden` builder receives it
- Marketplace fetch identity: `warden-fetch`, with a separate primary group and home at `/var/lib/warden-fetch`; it owns the read-only marketplace CLI credentials but cannot read either Warden environment file
- Runtime feature flags (set in `/opt/warden/.env`):
  - `WARDEN_RATE_LIMIT_PER_MIN=60` (set to `0` to disable)
  - `WARDEN_DEMO_RATE_LIMIT_PER_MIN=20` (shared limit for public demo and Gauntlet routes)
  - `WARDEN_REQUIRE_CONSENT=true` (hard consent is the default; set to `false` to restore soft consent, which lets an audit proceed against a target that has not opted in)
  - `WARDEN_BADGE_SECRET=<strong-random-hmac-secret>` (required in production; the public development default is forgeable)
  - `WARDEN_ISSUER_KEY=<base64url-ed25519-seed>` (required in production; never let a release generate the development fallback)
  - `WARDEN_ISSUER_KID=<unique-current-key-id>` and `WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history.json` (the current signer plus public-only retired-key history)
  - `WARDEN_PROTECTION_DB=/opt/warden/data/protection.db` (keeps APA bindings, nonces, attestations, and the transparency log outside releases)

## First Deploy

Run locally from the repository root after explicit approval:

```bash
set -euo pipefail
python scripts/build_site.py
test -z "$(git status --porcelain)"
release="$(git rev-parse --verify HEAD)"
test "${#release}" -eq 40
case "$release" in (*[!0-9a-f]*|'') exit 1 ;; esac

git archive --format=tar HEAD |
  ssh root@75.119.153.252 "set -euo pipefail; test ! -L /opt/warden; test ! -L /opt/warden/releases; if test -e /opt/warden/current || test -L /opt/warden/current; then test -L /opt/warden/current; active=\$(readlink -f -- /opt/warden/current); test \"\$(dirname -- \"\$active\")\" = /opt/warden/releases; active_release=\$(basename -- \"\$active\"); test \"\${#active_release}\" -eq 40; case \"\$active_release\" in (*[!0-9a-f]*|'') exit 1 ;; esac; fi; install -d -m 0755 /opt/warden/releases; test ! -e /opt/warden/releases/$release; test ! -L /opt/warden/releases/$release; incoming=\$(mktemp -d /opt/warden/releases/.incoming-$release.XXXXXX); trap 'rm -rf -- \"\$incoming\"' EXIT; tar -xf - -C \"\$incoming\"; test -f \"\$incoming/pyproject.toml\"; test -f \"\$incoming/warden/api.py\"; mv \"\$incoming\" /opt/warden/releases/$release; trap - EXIT"

git archive --format=tar HEAD site |
  ssh root@75.119.153.252 "set -euo pipefail; test ! -L /opt/warden-site; test ! -L /opt/warden-site/releases; if test -e /opt/warden-site/current || test -L /opt/warden-site/current; then test -L /opt/warden-site/current; active=\$(readlink -f -- /opt/warden-site/current); test \"\$(dirname -- \"\$active\")\" = /opt/warden-site/releases; active_release=\$(basename -- \"\$active\"); test \"\${#active_release}\" -eq 40; case \"\$active_release\" in (*[!0-9a-f]*|'') exit 1 ;; esac; fi; install -d -m 0755 /opt/warden-site/releases; test ! -e /opt/warden-site/releases/$release; test ! -L /opt/warden-site/releases/$release; incoming=\$(mktemp -d /opt/warden-site/releases/.incoming-$release.XXXXXX); trap 'rm -rf -- \"\$incoming\"' EXIT; tar -xf - --strip-components=1 -C \"\$incoming\"; test -f \"\$incoming/index.html\"; test -f \"\$incoming/app.js\"; mv \"\$incoming\" /opt/warden-site/releases/$release; trap - EXIT"
```

`git archive` includes only the reviewed commit, so ignored issuer keys, databases, badge state, `.git`,
dependency directories, and local build output cannot enter either upload. The clean-worktree gate binds both
archives to the exact commit under review. Each archive is extracted into a new versioned directory; neither
upload overlays the active application or changes a `current` symlink. A failed upload is cleaned from its
fixed `.incoming-<commit>.*` path and cannot mix with the active release.

Then run on the VPS:

The actual VPS `onchainos` path and version are **unverified until an approved deploy**. The two read-only
preflight commands below are a hard gate: if either fails, stop, establish an authenticated CLI installation
for the `warden-fetch` user, update the unit's explicit `PATH` if required, and re-run the checks before enabling the
timer. Never print or copy the CLI's credentials into the runbook or journal.

```bash
set -euo pipefail
release='<paste the exact local git rev-parse output>'
test "${#release}" -eq 40
case "$release" in (*[!0-9a-f]*|'') exit 1 ;; esac
app="/opt/warden/releases/$release"
static="/opt/warden-site/releases/$release"
index_candidate="/opt/warden-index/candidates/$release"
candidate_unit_dir=/run/systemd/system
candidate_port=18031

reject_symlink() {
  if test -L "$1"; then
    echo "Refusing symlinked deployment path: $1" >&2
    exit 1
  fi
}

validate_current_link() {
  link="$1"
  releases="$2"
  if ! test -e "$link" && ! test -L "$link"; then
    return 0
  fi
  test -L "$link"
  resolved="$(readlink -f -- "$link")"
  test -d "$resolved"
  test "$(dirname -- "$resolved")" = "$releases"
  version="$(basename -- "$resolved")"
  test "${#version}" -eq 40
  case "$version" in (*[!0-9a-f]*|'') exit 1 ;; esac
}

reject_symlink /opt/warden
reject_symlink /opt/warden/releases
reject_symlink /opt/warden-site
reject_symlink /opt/warden-site/releases
reject_symlink /opt/warden-index
reject_symlink /opt/warden-index/releases
reject_symlink /opt/warden-index/candidates
reject_symlink /opt/warden-snapshot
reject_symlink /var/lib/warden-fetch
reject_symlink /opt/warden/badges
reject_symlink /opt/warden/gauntlet
reject_symlink /opt/warden/data
reject_symlink /opt/warden/logs
reject_symlink /opt/warden/data/apa_issuer.key
reject_symlink /opt/warden/issuer-history.json
reject_symlink /opt/warden/.env
reject_symlink /opt/warden/index.env
validate_current_link /opt/warden/current /opt/warden/releases
validate_current_link /opt/warden-site/current /opt/warden-site/releases
validate_current_link /opt/warden-index/current /opt/warden-index/releases
test -d "$app"
test -d "$static"
test ! -L "$app"
test ! -L "$static"
test ! -e "$index_candidate"
test ! -L "$index_candidate"

previous_app=""
previous_app_target=""
previous_static=""
previous_static_target=""
previous_index_target=""
previous_index_release=""
if test -L /opt/warden/current; then
  previous_app="$(readlink -f -- /opt/warden/current)"
  previous_app_target="$(readlink -- /opt/warden/current)"
fi
if test -L /opt/warden-site/current; then
  previous_static="$(readlink -f -- /opt/warden-site/current)"
  previous_static_target="$(readlink -- /opt/warden-site/current)"
fi
if test -n "$previous_app" || test -n "$previous_static"; then
  test -n "$previous_app"
  test -n "$previous_static"
  test "$(basename -- "$previous_app")" = "$(basename -- "$previous_static")"
fi

service_was_active=0
if systemctl is-active --quiet warden.service; then
  service_was_active=1
fi
service_was_enabled=0
if systemctl is-enabled --quiet warden.service; then
  service_was_enabled=1
fi
timer_was_active=0
if systemctl is-active --quiet warden-index.timer; then
  timer_was_active=1
fi
timer_was_enabled=0
if systemctl is-enabled --quiet warden-index.timer; then
  timer_was_enabled=1
fi
reprobe_timer_was_active=0
if systemctl is-active --quiet warden-apa-reprobe.timer; then
  reprobe_timer_was_active=1
fi
reprobe_timer_was_enabled=0
if systemctl is-enabled --quiet warden-apa-reprobe.timer; then
  reprobe_timer_was_enabled=1
fi

id -u warden &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin warden
id -u warden-fetch &>/dev/null || useradd --system --home-dir /var/lib/warden-fetch --create-home --shell /usr/sbin/nologin warden-fetch
if id -nG warden-fetch | tr ' ' '\n' | grep -Fxq warden; then
  echo "warden-fetch must not belong to the secret-bearing warden group" >&2
  exit 1
fi
install -d -o root -g root -m 0755 /opt/warden /opt/warden/releases /opt/warden-site /opt/warden-site/releases
install -d -o warden -g warden -m 0750 /opt/warden/badges /opt/warden/gauntlet /opt/warden/data /opt/warden/logs
install -d -o warden -g warden -m 0755 /opt/warden-index /opt/warden-index/releases /opt/warden-index/candidates
install -d -o warden-fetch -g warden-fetch -m 0755 /opt/warden-snapshot
install -d -o warden-fetch -g warden-fetch -m 0700 /var/lib/warden-fetch
chown -hR warden:warden /opt/warden/badges /opt/warden/gauntlet /opt/warden/data /opt/warden/logs
if test -e /opt/warden/data/apa_issuer.key; then
  test -f /opt/warden/data/apa_issuer.key
  chown warden:warden /opt/warden/data/apa_issuer.key
  chmod 0600 /opt/warden/data/apa_issuer.key
fi
test -f /opt/warden/.env
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_KEY=(ed25519-seed:)?[A-Za-z0-9_-]{43}[[:space:]]*$' /opt/warden/.env)" -eq 1
test -f /opt/warden/index.env
test -f /opt/warden/issuer-history.json
chown root:warden /opt/warden/.env /opt/warden/index.env
chown root:warden /opt/warden/issuer-history.json
chmod 0640 /opt/warden/.env /opt/warden/index.env
chmod 0640 /opt/warden/issuer-history.json
runuser -u warden-fetch -- test ! -r /opt/warden/.env
runuser -u warden-fetch -- test ! -r /opt/warden/index.env
test "$(grep -Ec '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' /opt/warden/index.env)" -eq 3
grep -Eq '^[[:space:]]*WARDEN_BADGE_SECRET=.{20,}$' /opt/warden/index.env
grep -Eq '^[[:space:]]*WARDEN_ISSUER_PUBLIC_KEY=ed25519:[A-Za-z0-9_-]{43}[[:space:]]*$' /opt/warden/index.env
grep -Eq '^[[:space:]]*WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history\.json[[:space:]]*$' /opt/warden/index.env

test ! -e "$app/.venv"
python3 -m venv "$app/.venv"
"$app/.venv/bin/python" -m pip install --upgrade pip
"$app/.venv/bin/python" -m pip install -e "$app[dev]"
cd "$app"
"$app/.venv/bin/ruff" check .
"$app/.venv/bin/pytest" -q
"$app/.venv/bin/python" spec/verify_apa.py --selftest
test ! -e "$app/badges"
test ! -e "$app/gauntlet"
test ! -e "$app/data/protection.db"
test ! -L "$app/badges"
test ! -L "$app/gauntlet"
test ! -L "$app/data/protection.db"
chown -R root:root "$app" "$static"
chmod -R u=rwX,go=rX "$app" "$static"
ln -s /opt/warden/badges "$app/badges"
ln -s /opt/warden/gauntlet "$app/gauntlet"
test "$(readlink -f "$app/badges")" = /opt/warden/badges
test "$(readlink -f "$app/gauntlet")" = /opt/warden/gauntlet

runuser -u warden -- env APP="$app" bash -c 'set -euo pipefail; set -a; . /opt/warden/.env; set +a; app_badge_secret="$WARDEN_BADGE_SECRET"; app_issuer_history="$WARDEN_ISSUER_HISTORY"; set -a; . /opt/warden/index.env; set +a; test "$app_badge_secret" = "$WARDEN_BADGE_SECRET"; test "$app_issuer_history" = "$WARDEN_ISSUER_HISTORY"; test "${WARDEN_PROTECTION_DB:-}" = /opt/warden/data/protection.db; exec "$APP/.venv/bin/python" -c "$1"' _ 'import os; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from warden import protection; from warden.badges import b64u_decode, b64u_encode; seed = b64u_decode(os.environ["WARDEN_ISSUER_KEY"]); assert len(seed) == 32; assert os.environ["WARDEN_ISSUER_PUBLIC_KEY"] == b64u_encode(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw(), "ed25519"); document = protection.issuer_document(); assert document["keys"][0]["pub"] == os.environ["WARDEN_ISSUER_PUBLIC_KEY"]'
test -x /usr/bin/flock
runuser -u warden-fetch -- env -i HOME=/var/lib/warden-fetch PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" bash -c 'set -euo pipefail; command -v onchainos; onchainos --version'
runuser -u warden-fetch -- env -i HOME=/var/lib/warden-fetch PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" onchainos agent search --query a --page 1 --page-size 1 >/dev/null

render_app_service() {
  source_service="$1"
  target_service="$2"
  app_root="$3"
  sed -e "s#^WorkingDirectory=/opt/warden\$#WorkingDirectory=$app_root#" \
      -e "s#^ExecStart=/opt/warden/.venv/#ExecStart=$app_root/.venv/#" \
      "$source_service" >"$target_service"
}

candidate_service="$candidate_unit_dir/warden-candidate.service"
candidate_index_fetch_service="$candidate_unit_dir/warden-index-fetch-candidate.service"
candidate_index_service="$candidate_unit_dir/warden-index-candidate.service"
candidate_index_timer="$candidate_unit_dir/warden-index-candidate.timer"
candidate_reprobe_service="$candidate_unit_dir/warden-apa-reprobe-candidate.service"
candidate_reprobe_timer="$candidate_unit_dir/warden-apa-reprobe-candidate.timer"
test ! -e "$candidate_service"
test ! -L "$candidate_service"
test ! -e "$candidate_index_fetch_service"
test ! -L "$candidate_index_fetch_service"
test ! -e "$candidate_index_service"
test ! -L "$candidate_index_service"
test ! -e "$candidate_index_timer"
test ! -L "$candidate_index_timer"
test ! -e "$candidate_reprobe_service"
test ! -L "$candidate_reprobe_service"
test ! -e "$candidate_reprobe_timer"
test ! -L "$candidate_reprobe_timer"
render_app_service "$app/deploy/warden.service" "$candidate_service" "$app"
sed -i -e "s#--port 8031#--port $candidate_port#" "$candidate_service"
sed -e "s#/opt/warden/current#$app#g" "$app/deploy/systemd/warden-index-fetch.service" >"$candidate_index_fetch_service"
sed -e "s#/opt/warden/current#$app#g" -e "s#--index-root /opt/warden-index#--index-root $index_candidate#" -e 's#warden-index-fetch.service#warden-index-fetch-candidate.service#g' "$app/deploy/systemd/warden-index.service" >"$candidate_index_service"
sed -e 's#Unit=warden-index.service#Unit=warden-index-candidate.service#' "$app/deploy/systemd/warden-index.timer" >"$candidate_index_timer"
sed -e "s#/opt/warden/current#$app#g" "$app/deploy/systemd/warden-apa-reprobe.service" >"$candidate_reprobe_service"
sed -e 's#Unit=warden-apa-reprobe.service#Unit=warden-apa-reprobe-candidate.service#' "$app/deploy/systemd/warden-apa-reprobe.timer" >"$candidate_reprobe_timer"

config_backup="$(mktemp -d /run/warden-config-backup.$release.XXXXXX)"
app_link_created=0
static_link_created=0
index_link_created=0
rollback_app_link_created=0
rollback_static_link_created=0
rollback_index_link_created=0
configs_installed=0
cleanup_candidates() {
  status=$?
  set +e
  systemctl stop warden-candidate.service >/dev/null 2>&1
  systemctl stop warden-index-candidate.service warden-index-fetch-candidate.service >/dev/null 2>&1
  for unit in "$candidate_service" "$candidate_index_fetch_service" "$candidate_index_service" "$candidate_index_timer" "$candidate_reprobe_service" "$candidate_reprobe_timer"; do
    if test -e "$unit" || test -L "$unit"; then unlink "$unit"; fi
  done
  if test "$app_link_created" -eq 1 && test -L "$app_link"; then unlink "$app_link"; fi
  if test "$static_link_created" -eq 1 && test -L "$static_link"; then unlink "$static_link"; fi
  if test "$index_link_created" -eq 1 && test -L "$index_link"; then unlink "$index_link"; fi
  if test "$rollback_app_link_created" -eq 1 && test -L "$rollback_app_link"; then unlink "$rollback_app_link"; fi
  if test "$rollback_static_link_created" -eq 1 && test -L "$rollback_static_link"; then unlink "$rollback_static_link"; fi
  if test "$rollback_index_link_created" -eq 1 && test -L "$rollback_index_link"; then unlink "$rollback_index_link"; fi
  if test "$configs_installed" -eq 1; then restore_legacy_configs; fi
  systemctl daemon-reload >/dev/null 2>&1
  if test "$timer_was_active" -eq 1; then systemctl start warden-index.timer; fi
  if test "$reprobe_timer_was_active" -eq 1; then systemctl start warden-apa-reprobe.timer; fi
  if test -d "$config_backup" && ! test -L "$config_backup"; then rm -rf -- "$config_backup"; fi
  trap - EXIT
  exit "$status"
}
trap cleanup_candidates EXIT

backup_config() {
  config="$1"
  name="$2"
  if test -e "$config" || test -L "$config"; then
    cp -a --no-dereference "$config" "$config_backup/$name"
  fi
}
backup_config /etc/systemd/system/warden.service warden.service
backup_config /etc/systemd/system/warden-index-fetch.service warden-index-fetch.service
backup_config /etc/systemd/system/warden-index.service warden-index.service
backup_config /etc/systemd/system/warden-index.timer warden-index.timer
backup_config /etc/systemd/system/warden-apa-reprobe.service warden-apa-reprobe.service
backup_config /etc/systemd/system/warden-apa-reprobe.timer warden-apa-reprobe.timer
backup_config /etc/nginx/sites-available/warden.gudman.xyz.conf nginx-available.conf
backup_config /etc/nginx/sites-enabled/warden.gudman.xyz.conf nginx-enabled.conf

systemd-analyze verify "$candidate_unit_dir/warden-candidate.service" "$candidate_unit_dir/warden-index-fetch-candidate.service" "$candidate_unit_dir/warden-index-candidate.service" "$candidate_unit_dir/warden-index-candidate.timer" "$candidate_unit_dir/warden-apa-reprobe-candidate.service" "$candidate_unit_dir/warden-apa-reprobe-candidate.timer"
systemctl daemon-reload
systemctl start warden-candidate.service
candidate_healthy=0
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$candidate_port/health" >/dev/null; then
    candidate_healthy=1
    break
  fi
  systemctl is-active --quiet warden-candidate.service || break
  sleep 1
done
test "$candidate_healthy" -eq 1
runuser -u warden -- env APP="$app" PORT="$candidate_port" bash -c 'set -euo pipefail; set -a; . /opt/warden/index.env; set +a; curl -fsS "http://127.0.0.1:$PORT/.well-known/apa-issuer.json" | "$APP/.venv/bin/python" -c "$1"' _ 'import json, os, sys; from pathlib import Path; from scripts.build_index import MAX_SAFE_UNIX_SECONDS, load_apa_issuer_history; document = json.load(sys.stdin); history = load_apa_issuer_history(Path(os.environ["WARDEN_ISSUER_HISTORY"]), os.environ["WARDEN_ISSUER_PUBLIC_KEY"]); expected = [(os.environ["WARDEN_ISSUER_PUBLIC_KEY"], MAX_SAFE_UNIX_SECONDS), *((key.pub, key.not_after) for key in history)]; actual = [(key.get("pub"), key.get("not_after")) for key in document.get("keys", []) if isinstance(key, dict)]; assert document.get("issuer") == "warden" and actual == expected, "issuer document does not match index verification keys"'
systemctl stop warden-candidate.service
if systemctl is-active --quiet warden-index.timer; then systemctl stop warden-index.timer; fi
if systemctl is-active --quiet warden-index.service; then
  echo "warden-index.service is already running; retry after it finishes" >&2
  exit 1
fi
validate_current_link /opt/warden-index/current /opt/warden-index/releases
if test -L /opt/warden-index/current; then
  previous_index_target="$(readlink -- /opt/warden-index/current)"
  previous_index_release="$(readlink -f -- /opt/warden-index/current)"
fi
if systemctl is-active --quiet warden-apa-reprobe.timer; then systemctl stop warden-apa-reprobe.timer; fi
if systemctl is-active --quiet warden-apa-reprobe.service; then
  echo "warden-apa-reprobe.service is already running; retry after it finishes" >&2
  exit 1
fi
systemctl start warden-index-candidate.service
test -L "$index_candidate/current"
candidate_index_release="$(readlink -f -- "$index_candidate/current")"
test "$(dirname -- "$candidate_index_release")" = "$index_candidate/releases"
chmod 0644 "$candidate_index_release/data/marketplace-summary.json" "$candidate_index_release/data/warden-services.json"
test "$(stat -c '%a' "$candidate_index_release/data/marketplace-summary.json")" = 644
test "$(stat -c '%a' "$candidate_index_release/data/warden-services.json")" = 644
capture="$(basename -- "$candidate_index_release")"
test "${#capture}" -eq 16
capture_digits="${capture:0:8}${capture:9:6}"
test "${capture:8:1}" = T
test "${capture:15:1}" = Z
case "$capture_digits" in (*[!0-9]*|'') exit 1 ;; esac
live_index_release="/opt/warden-index/releases/$capture"
test ! -e "$live_index_release"
test ! -L "$live_index_release"
unlink "$index_candidate/current"
mv "$candidate_index_release" "$live_index_release"
rmdir "$index_candidate/releases" "$index_candidate"
index_target="releases/$capture"

install_release_configs() {
  source_app="$1"
  rendered_app_service="$config_backup/warden-active.service"
  render_app_service "$source_app/deploy/warden.service" "$rendered_app_service" /opt/warden/current || return
  install -m 0644 "$rendered_app_service" /etc/systemd/system/warden.service || return
  install -m 0644 "$source_app/deploy/systemd/warden-index-fetch.service" /etc/systemd/system/warden-index-fetch.service || return
  install -m 0644 "$source_app/deploy/systemd/warden-index.service" /etc/systemd/system/warden-index.service || return
  install -m 0644 "$source_app/deploy/systemd/warden-index.timer" /etc/systemd/system/warden-index.timer || return
  install -m 0644 "$source_app/deploy/systemd/warden-apa-reprobe.service" /etc/systemd/system/warden-apa-reprobe.service || return
  install -m 0644 "$source_app/deploy/systemd/warden-apa-reprobe.timer" /etc/systemd/system/warden-apa-reprobe.timer || return
  install -m 0644 "$source_app/deploy/nginx-warden.conf" /etc/nginx/sites-available/warden.gudman.xyz.conf || return
  ln -sfn /etc/nginx/sites-available/warden.gudman.xyz.conf /etc/nginx/sites-enabled/warden.gudman.xyz.conf || return
}

restore_legacy_configs() {
  while read -r config name; do
    if test -e "$config" || test -L "$config"; then unlink "$config"; fi
    backup="$config_backup/$name"
    if test -e "$backup" || test -L "$backup"; then cp -a --no-dereference "$backup" "$config"; fi
  done <<'CONFIGS'
/etc/systemd/system/warden.service warden.service
/etc/systemd/system/warden-index-fetch.service warden-index-fetch.service
/etc/systemd/system/warden-index.service warden-index.service
/etc/systemd/system/warden-index.timer warden-index.timer
/etc/systemd/system/warden-apa-reprobe.service warden-apa-reprobe.service
/etc/systemd/system/warden-apa-reprobe.timer warden-apa-reprobe.timer
/etc/nginx/sites-available/warden.gudman.xyz.conf nginx-available.conf
/etc/nginx/sites-enabled/warden.gudman.xyz.conf nginx-enabled.conf
CONFIGS
}

rollback_release() {
  systemctl stop warden.service || true
  if test -n "$previous_app"; then
    rollback_app_link="/opt/warden/.current-rollback-$release"
    rollback_static_link="/opt/warden-site/.current-rollback-$release"
    test ! -e "$rollback_app_link" && test ! -L "$rollback_app_link"
    test ! -e "$rollback_static_link" && test ! -L "$rollback_static_link"
    ln -s "$previous_app_target" "$rollback_app_link"
    rollback_app_link_created=1
    ln -s "$previous_static_target" "$rollback_static_link"
    rollback_static_link_created=1
    mv -Tf "$rollback_app_link" /opt/warden/current
    mv -Tf "$rollback_static_link" /opt/warden-site/current
  else
    if test -L /opt/warden/current; then unlink /opt/warden/current; fi
    if test -L /opt/warden-site/current; then unlink /opt/warden-site/current; fi
  fi
  restore_legacy_configs
  if test -n "$previous_index_target"; then
    rollback_index_link="/opt/warden-index/.current-rollback-$release"
    test ! -e "$rollback_index_link" && test ! -L "$rollback_index_link"
    ln -s "$previous_index_target" "$rollback_index_link"
    rollback_index_link_created=1
    mv -Tf "$rollback_index_link" /opt/warden-index/current
  elif test -L /opt/warden-index/current; then
    unlink /opt/warden-index/current
  fi
  systemctl daemon-reload
  nginx -t
  if test "$service_was_enabled" -eq 1; then
    systemctl enable warden.service
  else
    systemctl disable warden.service || true
  fi
  if test "$timer_was_enabled" -eq 1; then
    systemctl enable warden-index.timer
  else
    systemctl disable --now warden-index.timer || true
  fi
  if test "$reprobe_timer_was_enabled" -eq 1; then
    systemctl enable warden-apa-reprobe.timer
  else
    systemctl disable --now warden-apa-reprobe.timer || true
  fi
  if test "$service_was_active" -eq 1; then
    systemctl restart warden.service
    curl -fsS http://127.0.0.1:8031/health >/dev/null
  fi
  if test "$timer_was_active" -eq 1; then
    systemctl start warden-index.timer
  else
    systemctl stop warden-index.timer || true
  fi
  if test "$reprobe_timer_was_active" -eq 1; then
    systemctl start warden-apa-reprobe.timer
  else
    systemctl stop warden-apa-reprobe.timer || true
  fi
  systemctl reload nginx
  configs_installed=0
}

validate_static_index_contract() {
  static_release="$1"
  test -f "$static_release/app.js"
  if grep -Fq 'marketplace-summary.json' "$static_release/app.js"; then
    grep -Fq 'value?.schemaVersion !== 2' "$static_release/app.js"
    grep -Fq 'const query = value?.query;' "$static_release/app.js"
  fi
}

"$app/.venv/bin/python" "$app/scripts/refresh_safety_index.py" --validate-release "$live_index_release"
if test -n "$previous_index_release"; then
  "$app/.venv/bin/python" "$app/scripts/refresh_safety_index.py" --validate-release "$previous_index_release"
fi
validate_static_index_contract "$static"
if test -n "$previous_static"; then validate_static_index_contract "$previous_static"; fi

if ! test -f /etc/letsencrypt/live/warden.gudman.xyz/fullchain.pem; then
  certbot certonly --webroot -d warden.gudman.xyz
fi
configs_installed=1
install_release_configs "$app"
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/warden.service /etc/systemd/system/warden-index-fetch.service /etc/systemd/system/warden-index.service /etc/systemd/system/warden-index.timer /etc/systemd/system/warden-apa-reprobe.service /etc/systemd/system/warden-apa-reprobe.timer
nginx -t

activate_release() {
  app_link="/opt/warden/.current-$release"
  static_link="/opt/warden-site/.current-$release"
  index_link="/opt/warden-index/.current-$release"
  test ! -e "$app_link" && test ! -L "$app_link" || return
  test ! -e "$static_link" && test ! -L "$static_link" || return
  test ! -e "$index_link" && test ! -L "$index_link" || return
  ln -s "releases/$release" "$app_link" || return
  app_link_created=1
  ln -s "releases/$release" "$static_link" || return
  static_link_created=1
  ln -s "$index_target" "$index_link" || return
  index_link_created=1
  mv -Tf "$app_link" /opt/warden/current || return
  mv -Tf "$static_link" /opt/warden-site/current || return
  mv -Tf "$index_link" /opt/warden-index/current || return
  systemctl restart warden.service || return
  curl -fsS http://127.0.0.1:8031/health >/dev/null || return
  systemctl enable warden.service || return
  systemctl enable --now warden-index.timer || return
  systemctl enable --now warden-apa-reprobe.timer || return
  systemctl reload nginx || return
  systemctl list-timers warden-index.timer warden-apa-reprobe.timer --all || return
}

systemd-analyze calendar '*-*-* 00/6:00:00 UTC'
systemd-analyze calendar '*-*-* *:00/15:00 UTC'
if ! activate_release; then
  rollback_release
  exit 1
fi
configs_installed=0
```

Warden runs as a dedicated unprivileged `warden` system user (`deploy/warden.service`), not root. Tests,
dependency installation, state symlinks, and read-only permissions are complete before either `current`
symlink changes. The application service can write only the persistent state paths outside `releases`.
The three `current` links are individually atomic but the sequence is not traffic-atomic as a bundle. Before
the first link changes, the runbook validates both current and candidate index captures against the exact
v2 marketplace-summary contract (including `query`) and checks every static release that consumes that feed
for the same schema/query parser. This explicit cross-version gate keeps each transient link combination
backward-compatible without introducing a second bundle pointer.

## Redeploy

Run locally from the repository root after explicit approval:

```bash
set -euo pipefail
python scripts/build_site.py
test -z "$(git status --porcelain)"
release="$(git rev-parse --verify HEAD)"
test "${#release}" -eq 40
case "$release" in (*[!0-9a-f]*|'') exit 1 ;; esac

git archive --format=tar HEAD |
  ssh root@75.119.153.252 "set -euo pipefail; test ! -L /opt/warden; test ! -L /opt/warden/releases; if test -e /opt/warden/current || test -L /opt/warden/current; then test -L /opt/warden/current; active=\$(readlink -f -- /opt/warden/current); test \"\$(dirname -- \"\$active\")\" = /opt/warden/releases; active_release=\$(basename -- \"\$active\"); test \"\${#active_release}\" -eq 40; case \"\$active_release\" in (*[!0-9a-f]*|'') exit 1 ;; esac; fi; install -d -m 0755 /opt/warden/releases; test ! -e /opt/warden/releases/$release; test ! -L /opt/warden/releases/$release; incoming=\$(mktemp -d /opt/warden/releases/.incoming-$release.XXXXXX); trap 'rm -rf -- \"\$incoming\"' EXIT; tar -xf - -C \"\$incoming\"; test -f \"\$incoming/pyproject.toml\"; test -f \"\$incoming/warden/api.py\"; mv \"\$incoming\" /opt/warden/releases/$release; trap - EXIT"

git archive --format=tar HEAD site |
  ssh root@75.119.153.252 "set -euo pipefail; test ! -L /opt/warden-site; test ! -L /opt/warden-site/releases; if test -e /opt/warden-site/current || test -L /opt/warden-site/current; then test -L /opt/warden-site/current; active=\$(readlink -f -- /opt/warden-site/current); test \"\$(dirname -- \"\$active\")\" = /opt/warden-site/releases; active_release=\$(basename -- \"\$active\"); test \"\${#active_release}\" -eq 40; case \"\$active_release\" in (*[!0-9a-f]*|'') exit 1 ;; esac; fi; install -d -m 0755 /opt/warden-site/releases; test ! -e /opt/warden-site/releases/$release; test ! -L /opt/warden-site/releases/$release; incoming=\$(mktemp -d /opt/warden-site/releases/.incoming-$release.XXXXXX); trap 'rm -rf -- \"\$incoming\"' EXIT; tar -xf - --strip-components=1 -C \"\$incoming\"; test -f \"\$incoming/index.html\"; test -f \"\$incoming/app.js\"; mv \"\$incoming\" /opt/warden-site/releases/$release; trap - EXIT"
```

For the VPS activation, use the canonical block above:

Run the complete VPS activation block under **First Deploy** with the new commit. It is intentionally the
single canonical activation procedure for both first deploys and redeploys: it detects a flat legacy install
or a versioned current release, validates the candidate on alternate resources, and rolls back to the exact
pre-run state on an activation failure. Certificate issuance is conditional, so the same block is safe for a
redeploy.

## Application Rollback

Rollback selects one previously validated application/static commit and changes only the two `current`
symlinks, then installs that same commit's systemd and nginx files. Inspect the targets first; never delete a
release during rollback:

```bash
set -euo pipefail
release='<known prior 40-character commit>'
test "${#release}" -eq 40
case "$release" in (*[!0-9a-f]*|'') exit 1 ;; esac
app="/opt/warden/releases/$release"
static="/opt/warden-site/releases/$release"

reject_symlink() {
  if test -L "$1"; then echo "Refusing symlinked deployment path: $1" >&2; exit 1; fi
}
validate_current_link() {
  link="$1"
  releases="$2"
  if ! test -e "$link" && ! test -L "$link"; then return 0; fi
  test -L "$link"
  resolved="$(readlink -f -- "$link")"
  test -d "$resolved"
  test "$(dirname -- "$resolved")" = "$releases"
  version="$(basename -- "$resolved")"
  test "${#version}" -eq 40
  case "$version" in (*[!0-9a-f]*|'') exit 1 ;; esac
}
render_app_service() {
  source_service="$1"
  target_service="$2"
  app_root="$3"
  sed -e "s#^WorkingDirectory=/opt/warden\$#WorkingDirectory=$app_root#" \
      -e "s#^ExecStart=/opt/warden/.venv/#ExecStart=$app_root/.venv/#" \
      "$source_service" >"$target_service"
}
reject_symlink /opt/warden
reject_symlink /opt/warden/releases
reject_symlink /opt/warden-site
reject_symlink /opt/warden-site/releases
reject_symlink /opt/warden-index
reject_symlink /opt/warden-index/releases
reject_symlink /opt/warden/badges
reject_symlink /opt/warden/gauntlet
reject_symlink /opt/warden/data
reject_symlink /opt/warden/logs
reject_symlink /opt/warden/issuer-history.json
validate_current_link /opt/warden/current /opt/warden/releases
validate_current_link /opt/warden-site/current /opt/warden-site/releases
validate_current_link /opt/warden-index/current /opt/warden-index/releases
test -d "$app"
test -d "$static"
test ! -L "$app"
test ! -L "$static"
test -x "$app/.venv/bin/uvicorn"
test ! -e "/opt/warden/.current-rollback-$release"
test ! -L "/opt/warden/.current-rollback-$release"
test ! -e "/opt/warden-site/.current-rollback-$release"
test ! -L "/opt/warden-site/.current-rollback-$release"
rollback_service="$(mktemp)"
trap 'rm -f -- "$rollback_service"' EXIT
render_app_service "$app/deploy/warden.service" "$rollback_service" /opt/warden/current
install -m 0644 "$rollback_service" /etc/systemd/system/warden.service
rm -f -- "$rollback_service"
trap - EXIT
install -m 0644 "$app/deploy/systemd/warden-index-fetch.service" /etc/systemd/system/warden-index-fetch.service
install -m 0644 "$app/deploy/systemd/warden-index.service" /etc/systemd/system/warden-index.service
install -m 0644 "$app/deploy/systemd/warden-index.timer" /etc/systemd/system/warden-index.timer
install -m 0644 "$app/deploy/systemd/warden-apa-reprobe.service" /etc/systemd/system/warden-apa-reprobe.service
install -m 0644 "$app/deploy/systemd/warden-apa-reprobe.timer" /etc/systemd/system/warden-apa-reprobe.timer
install -m 0644 "$app/deploy/nginx-warden.conf" /etc/nginx/sites-available/warden.gudman.xyz.conf
ln -sfn /etc/nginx/sites-available/warden.gudman.xyz.conf /etc/nginx/sites-enabled/warden.gudman.xyz.conf
systemctl daemon-reload
nginx -t
ln -s "releases/$release" "/opt/warden/.current-rollback-$release"
mv -Tf "/opt/warden/.current-rollback-$release" /opt/warden/current
ln -s "releases/$release" "/opt/warden-site/.current-rollback-$release"
mv -Tf "/opt/warden-site/.current-rollback-$release" /opt/warden-site/current
systemctl restart warden.service
curl -fsS http://127.0.0.1:8031/health >/dev/null
systemctl reload nginx
```

The activation block invokes its internal rollback automatically if config installation, daemon reload,
nginx validation, service restart, backend health, timer enablement, or nginx reload fails after promotion.
The manual procedure above is for an operator-requested rollback after a successful activation.

## Issuer Key Rotation

The canonical, fail-closed source procedure is
[`docs/ISSUER_KEY_ROTATION.md`](../docs/ISSUER_KEY_ROTATION.md). It uses an isolated candidate database and
requires every initially eligible persisted attestation to be re-signed by the current issuer with zero
skips before any state is promoted. The older release-layout sketch below is retained as design context; do
not use it as the rotation procedure.

Rotate the issuer only as a quiesced application-and-index change. Prepare these three regular files on the
same filesystem as their final paths, owned by `root:warden` and mode `0640`, without putting secret values
in shell history:

- `/opt/warden/.env.rotation` is a complete replacement application environment. It contains the new
  `WARDEN_ISSUER_KEY`, a unique new `WARDEN_ISSUER_KID`, and
  `WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history.json`.
- `/opt/warden/index.env.rotation` is a complete three-assignment replacement containing the unchanged
  badge secret, the new derived `WARDEN_ISSUER_PUBLIC_KEY`, and the same canonical history path. It must not
  contain the issuer seed.
- `/opt/warden/issuer-history.json.rotation` contains only retired public keys. Add the former current key
  with a finite retirement cutoff equal to the planned cutover time; never use the current-key sentinel for
  a history entry.

An attestation has an exact one-hour lifetime. A record signed immediately before a retired key's cutoff can
therefore remain valid for a bounded one-hour post-retirement grace window; the cutoff prevents a stolen old
key from backdating a longer-lived record. Keep the public retired key through that window and for as long as
historical attestations need to remain verifiable. The three replacements are not a multi-file filesystem
transaction: the procedure stops every reader first, uses same-filesystem atomic renames, rebuilds the index,
and rolls every file and the index link back before readers restart if any validation fails. Never print,
`cat`, log, or pass the issuer seed as a command-line argument.

Run from the active reviewed release:

```bash
set -euo pipefail
app=/opt/warden/current
candidate_app_env=/opt/warden/.env.rotation
candidate_index_env=/opt/warden/index.env.rotation
candidate_history=/opt/warden/issuer-history.json.rotation
backup_dir=""
previous_index_target=""
rotation_committed=0

reject_symlink() {
  if test -L "$1"; then echo "Refusing symlinked issuer configuration: $1" >&2; exit 1; fi
}
for path in /opt/warden/.env /opt/warden/index.env /opt/warden/issuer-history.json; do
  reject_symlink "$path"
  test -f "$path"
done
reject_symlink /opt/warden/.env.rotation
reject_symlink /opt/warden/index.env.rotation
reject_symlink /opt/warden/issuer-history.json.rotation
for path in "$candidate_app_env" "$candidate_index_env" "$candidate_history"; do
  test -f "$path"
  test "$(stat -c '%U:%G' "$path")" = root:warden
  test "$(stat -c '%a' "$path")" = 640
done
test -x "$app/.venv/bin/python"
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_KEY=' "$candidate_app_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_KID=' "$candidate_app_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history\.json[[:space:]]*$' "$candidate_app_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' "$candidate_index_env")" -eq 3
test "$(grep -Ec '^[[:space:]]*WARDEN_BADGE_SECRET=.{20,}$' "$candidate_index_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_PUBLIC_KEY=ed25519:[A-Za-z0-9_-]{43}[[:space:]]*$' "$candidate_index_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history\.json[[:space:]]*$' "$candidate_index_env")" -eq 1
test "$(grep -Ec '^[[:space:]]*WARDEN_ISSUER_KEY=' "$candidate_index_env")" -eq 0

validate_rotation_material() {
  runuser -u warden -- env -i APP="$app" APP_ENV="$1" INDEX_ENV="$2" HISTORY="$3" HOME=/opt/warden-index PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" bash -c 'set -euo pipefail; set -a; . "$APP_ENV"; set +a; app_history="$WARDEN_ISSUER_HISTORY"; app_badge_secret="$WARDEN_BADGE_SECRET"; set -a; . "$INDEX_ENV"; set +a; test "$app_history" = /opt/warden/issuer-history.json; test "$WARDEN_ISSUER_HISTORY" = /opt/warden/issuer-history.json; test "$app_badge_secret" = "$WARDEN_BADGE_SECRET"; export WARDEN_ISSUER_HISTORY="$HISTORY"; exec "$APP/.venv/bin/python" -c "$1"' _ 'import os; from pathlib import Path; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from scripts.build_index import MAX_SAFE_UNIX_SECONDS, load_apa_issuer_history; from warden import protection; from warden.badges import b64u_decode, b64u_encode; seed = b64u_decode(os.environ["WARDEN_ISSUER_KEY"]); assert len(seed) == 32; current_pub = b64u_encode(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw(), "ed25519"); assert current_pub == os.environ["WARDEN_ISSUER_PUBLIC_KEY"]; history = load_apa_issuer_history(Path(os.environ["WARDEN_ISSUER_HISTORY"]), current_pub); expected = [(os.environ["WARDEN_ISSUER_KID"], current_pub, MAX_SAFE_UNIX_SECONDS), *((key.kid, key.pub, key.not_after) for key in history)]; document = protection.issuer_document(); assert set(document) == {"issuer", "keys"} and isinstance(document["keys"], list); assert all(isinstance(key, dict) and set(key) == {"kid", "pub", "not_after"} for key in document["keys"]); actual = [(key["kid"], key["pub"], key["not_after"]) for key in document["keys"]]; assert document["issuer"] == "warden" and actual == expected, "issuer document does not match index verification keys"'
}

validate_rotation_material "$candidate_app_env" "$candidate_index_env" "$candidate_history"
systemctl is-active --quiet warden.service
systemctl is-active --quiet warden-index.timer
systemctl is-active --quiet warden-apa-reprobe.timer
test -L /opt/warden-index/current
previous_index_release="$(readlink -f -- /opt/warden-index/current)"
test "$(dirname -- "$previous_index_release")" = /opt/warden-index/releases
previous_index_target="$(readlink -- /opt/warden-index/current)"
backup_dir="$(mktemp -d /opt/warden/.issuer-rotation-backup.XXXXXX)"
cleanup_rotation_backup() {
  status=$?
  trap - EXIT
  rm -rf -- "$backup_dir"
  exit "$status"
}
trap cleanup_rotation_backup EXIT
cp -a /opt/warden/.env "$backup_dir/app.env"
cp -a /opt/warden/index.env "$backup_dir/index.env"
cp -a /opt/warden/issuer-history.json "$backup_dir/issuer-history.json"
chmod 0700 "$backup_dir"
trap - EXIT

rollback() {
  status=$?
  trap - EXIT
  set +e
  if test "$rotation_committed" -ne 1; then
    systemctl stop warden-index.timer warden-apa-reprobe.timer
    systemctl stop warden-index.service warden-index-fetch.service warden-apa-reprobe.service
    systemctl stop warden.service
    install -o root -g warden -m 0640 "$backup_dir/app.env" /opt/warden/.env.rollback
    install -o root -g warden -m 0640 "$backup_dir/index.env" /opt/warden/index.env.rollback
    install -o root -g warden -m 0640 "$backup_dir/issuer-history.json" /opt/warden/issuer-history.json.rollback
    mv -Tf /opt/warden/.env.rollback /opt/warden/.env
    mv -Tf /opt/warden/index.env.rollback /opt/warden/index.env
    mv -Tf /opt/warden/issuer-history.json.rollback /opt/warden/issuer-history.json
    if test -n "$previous_index_target"; then
      ln -s "$previous_index_target" /opt/warden-index/.current-issuer-rollback
      mv -Tf /opt/warden-index/.current-issuer-rollback /opt/warden-index/current
    fi
    systemctl start warden.service
    systemctl start warden-index.timer warden-apa-reprobe.timer
  fi
  rm -rf -- "$backup_dir"
  exit "$status"
}
trap rollback EXIT

systemctl stop warden-index.timer warden-apa-reprobe.timer
systemctl stop warden-index.service warden-index-fetch.service warden-apa-reprobe.service
systemctl stop warden.service
mv -Tf "$candidate_app_env" /opt/warden/.env
mv -Tf "$candidate_index_env" /opt/warden/index.env
mv -Tf "$candidate_history" /opt/warden/issuer-history.json
validate_rotation_material /opt/warden/.env /opt/warden/index.env /opt/warden/issuer-history.json
runuser -u warden -- env -i HOME=/opt/warden-index PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" WARDEN_PROTECTION_DB=/opt/warden/data/protection.db bash -c 'set -euo pipefail; set -a; . /opt/warden/index.env; set +a; cd /opt/warden/current; python scripts/refresh_safety_index.py --index-root /opt/warden-index --snapshot /opt/warden-snapshot/agents-v1.jsonl --snapshot-owner warden-fetch --expected-query a'
systemctl start warden.service
curl -fsS http://127.0.0.1:8031/health >/dev/null
curl -fsS http://127.0.0.1:8031/.well-known/apa-issuer.json | runuser -u warden -- env -i APP="$app" HOME=/opt/warden-index PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" bash -c 'set -euo pipefail; set -a; . /opt/warden/index.env; set +a; exec "$APP/.venv/bin/python" -c "$1"' _ 'import json, os, sys; from pathlib import Path; from scripts.build_index import MAX_SAFE_UNIX_SECONDS, load_apa_issuer_history; document = json.load(sys.stdin); assert set(document) == {"issuer", "keys"} and isinstance(document["keys"], list); assert all(isinstance(key, dict) and set(key) == {"kid", "pub", "not_after"} for key in document["keys"]); history = load_apa_issuer_history(Path(os.environ["WARDEN_ISSUER_HISTORY"]), os.environ["WARDEN_ISSUER_PUBLIC_KEY"]); expected = [(os.environ["WARDEN_ISSUER_PUBLIC_KEY"], MAX_SAFE_UNIX_SECONDS), *((key.pub, key.not_after) for key in history)]; actual = [(key["pub"], key["not_after"]) for key in document["keys"]]; assert document["issuer"] == "warden" and actual == expected, "issuer document does not match index verification keys"'
systemctl start warden-index.timer warden-apa-reprobe.timer
rotation_committed=1
```

If the block exits before `rotation_committed=1`, its trap restores all three prior files, the previous Safety
Index link, the old signer, and both timers. After a successful rotation, retain the old public key in history
according to the bounded grace and historical-verification policy; no historical private key is retained.

## Nginx Shape

The production vhost serves real static pages from `/opt/warden-site/current`; unknown paths return 404 instead of falling back to the landing page. Each reviewed commit is extracted and validated under `/opt/warden-site/releases` before the static `current` symlink changes. The live marketplace pages and their two data feeds are the narrow exception: nginx resolves them through the independently replaced `/opt/warden-index/current` symlink. Both clean and `.html` marketplace URLs use that live index root, so stale generated files in an older static release are never served.

Before any app or static promotion, `warden-index-fetch-candidate.service` fetches a completed public snapshot
as `warden-fetch`, then `warden-index-candidate.service` consumes it into
`/opt/warden-index/candidates/<commit>` as `warden`. The runbook validates that capture, moves only its
immutable release directory under `/opt/warden-index/releases`, and validates the installed configs before
changing any live link. A fetch or validation failure leaves every served `current` link unchanged. The
`--from-committed-snapshot` mode remains an explicit offline availability tool, not the production activation
gate and not a substitute for the live candidate refresh.

Issued badges and APA attestations remain runtime state on the VPS. After the secretless fetch completes, each builder run reads `/opt/warden/badges/issued.jsonl` and the protection database with only the badge-verification secret, current public issuer key, and public-only retired-key history from `/opt/warden/index.env`, builds a complete candidate below `/opt/warden-index/releases`, validates its snapshot, pages, catalog, and v2 summary counts, then atomically replaces the index's own `current` link. A failed fetch, build, validation, or promotion leaves the prior release current. A badge is attached to an agent only when `data/marketplace/badge-links-v1.json` explicitly links its audit ID to that agent and the signed target host matches one of the agent's listed service hosts. Review each link before adding it; hostname matching alone is not ownership proof.

- `/` serves `site/index.html`.
- `/playground`, `/gauntlet`, `/hire`, `/integrate`, `/status`, `/privacy`, and `/terms` resolve to their matching `.html` files.
- `/agents` serves `/opt/warden-index/current/agents/index.html`; `/agents/{numeric_id}` serves the corresponding generated page from that same release.
- `/docs` serves the generated documentation index and `/docs/{reason_slug}` serves a generated reason-code page.
- `/badges` serves the registry from `site/badges.html`; `/badges/{audit_id}` serves the verifier from `site/badge.html`.
- Singular `GET /badge/{audit_id}` remains the FastAPI badge-verification endpoint.
- `POST /scan`, `POST /audit`, and `GET /health` proxy to `http://127.0.0.1:8031`.
- `/api/*` proxies the free demo, Gauntlet, and badge-registry APIs to `http://127.0.0.1:8031`.
- `/data/marketplace-summary.json` and `/data/warden-services.json` come from the current live-index release. Other `/assets/*`, `/data/*`, and existing static files remain under `/opt/warden-site/current`; missing files return 404.

The vhost enforces a self-only Content Security Policy. Site HTML, CSS, JavaScript, fonts, images, and browser API calls must not load from another origin. External links are navigation only.

Also serve `/.well-known/warden-consent` from `/opt/warden-site/current` when running in hard-consent mode. It should return HTTP 200 with body `warden-audit-allowed` and can be left absent when `WARDEN_REQUIRE_CONSENT=false`.

This keeps the FastAPI root JSON stub untouched while making the public root a multi-page static site.

## Live Safety Index Timer

`deploy/systemd/warden-index-fetch.service` is a secretless `warden-fetch` oneshot. It alone runs the
read-only `onchainos agent search` and atomically replaces `/opt/warden-snapshot/agents-v1.jsonl`; its unit has
no environment file and makes both Warden secret files inaccessible. `deploy/systemd/warden-index.service`
is a separate `warden`-owned oneshot that requires the fetch unit, consumes the completed snapshot, associates
signed Warden evidence, and publishes only after all release validations pass. `ProtectSystem=strict` leaves
only the fetcher's public snapshot/home writable to the fetch unit and only `/opt/warden-index` writable to
the builder. `deploy/systemd/warden-index.timer` runs on a six-hour UTC
calendar with a randomized delay and `Persistent=true`, so a missed calendar event is caught after the timer
becomes active again.

Only the builder uses `EnvironmentFile=/opt/warden/index.env`, which contains `WARDEN_BADGE_SECRET`, public
`WARDEN_ISSUER_PUBLIC_KEY`, and the path to `/opt/warden/issuer-history.json`. The history contains only
verify-only public keys with finite signed-time cutoffs; the issuer private key and payment credentials never enter either process. The builder
reads `WARDEN_PROTECTION_DB=/opt/warden/data/protection.db` under `ProtectSystem=strict` but can write only
`/opt/warden-index`. `/usr/bin/flock` serializes deploy-time and timer refreshes on
`/opt/warden-index/.refresh.lock`, so overlapping refreshes fail before either can promote a capture.

Before enabling the timer on any host, repeat the `command -v onchainos` and `onchainos --version` preflight as
the `warden-fetch` user in the exact `HOME` and `PATH` declared by the fetch service. The timer is not ready if the CLI,
its read-only authentication, the fetch-user separation, the narrow `/opt/warden/index.env`, or the pre-promotion live candidate refresh
fails. The committed seed is only an offline availability bootstrap from the disclosed capture.

Inspect the active capture and timer without changing either:

```bash
set -euo pipefail
readlink -f /opt/warden-index/current
cat /opt/warden-index/current/data/marketplace-summary.json
systemctl status warden-index-fetch.service warden-index.service warden-index.timer --no-pager
systemctl list-timers warden-index.timer --all
journalctl -u warden-index.service -n 100 --no-pager
journalctl -u warden-index-fetch.service -n 100 --no-pager
```

A successful service run logs one line with `capturedAt`, `sampled`, `expected`, `dropped`, `matched`, and
`audited`. Confirm `dropped = max(expected - sampled, 0)`; a non-zero `dropped` value is an explicit partial
capture, not a silent full-marketplace claim. If an inconsistent upstream total is below `sampled`, the
capture remains honest with `dropped = 0` and both observed values in the log.

Rollback selects a known prior directory after inspecting its summary. The temporary link and `current` must
stay on `/opt/warden-index` so the final rename is atomic:

```bash
set -euo pipefail
ls -1 /opt/warden-index/releases
cat /opt/warden-index/releases/20260716T030405Z/data/marketplace-summary.json
ln -s releases/20260716T030405Z /opt/warden-index/.current-rollback
mv -Tf /opt/warden-index/.current-rollback /opt/warden-index/current
readlink -f /opt/warden-index/current
curl -fsSI https://warden.gudman.xyz/agents
```

Choose the real prior capture shown by `ls`; the timestamp above is only the command shape. Rollback changes
the symlink only and does not delete either release.

## APA Protection Re-probe Timer

`deploy/systemd/warden-apa-reprobe.service` runs as the same unprivileged `warden` identity as the API and can
write only `/opt/warden/data`. It uses the production issuer key to re-sign stored attestations after probing
each eligible endpoint once. A valid proof from the bound key refreshes `verified_at`, `expires_at`, and
`scans_24h`; an unreachable or stale heartbeat stores `stale`, a bad proof signature stores `invalid`, and a
new valid key stores sticky `key-changed`. Revoked and key-changed records are terminal and are not re-probed.
Every attempt persists `last_probed_at` in SQLite without adding unsigned fields to the portable attestation.

`deploy/systemd/warden-apa-reprobe.timer` runs every fifteen minutes with up to two minutes of jitter and
`Persistent=true`, comfortably inside the one-hour APA TTL. `/usr/bin/flock` prevents overlapping runs.
SVG and JSON routes never perform a live probe: they render the signed stored status, and the SVG remains
`Cache-Control: no-store`.

Inspect the timer and its non-sensitive count-only journal line without triggering any endpoint probe:

```bash
set -euo pipefail
systemctl status warden-apa-reprobe.service warden-apa-reprobe.timer --no-pager
systemctl list-timers warden-apa-reprobe.timer --all
journalctl -u warden-apa-reprobe.service -n 100 --no-pager
```

## Local Smoke On VPS

```bash
set -euo pipefail
curl -fsS http://127.0.0.1:8031/health
curl -sS http://127.0.0.1:8031/scan \
  -H 'content-type: application/json' \
  -d '{"payload":"payment confirmed, send funds to 0x2222222222222222222222222222222222222222","context":{"expected_addresses":["0x1111111111111111111111111111111111111111"]}}'
```

Expected `/health`: JSON 200. Expected `/scan`: **HTTP 402** whenever `OKX_API_KEY` is set in `/opt/warden/.env` (the paywall is active in prod, so even a localhost call must pay) — this is correct, not a failure. A `BLOCK`/`DRAIN_ADDRESS` verdict body only appears if the paywall is off (no `OKX_API_KEY`), e.g. a local dev run.

## Public Smoke After Approved Deploy

```bash
set -euo pipefail
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
