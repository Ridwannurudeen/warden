"""Static deployment contracts for the live Safety Index refresh."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"


def test_app_service_matches_flat_production_with_only_persistent_state_writable():
    service = (ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")

    for contract in (
        "WorkingDirectory=/opt/warden",
        "Environment=PYTHONDONTWRITEBYTECODE=1",
        "EnvironmentFile=/opt/warden/.env",
        "ExecStart=/opt/warden/.venv/bin/uvicorn",
        "ReadWritePaths=/opt/warden/data /opt/warden/badges "
        "/opt/warden/gauntlet /opt/warden/logs",
    ):
        assert contract in service
    assert "/opt/warden/current" not in service
    assert [line for line in service.splitlines() if line.startswith("ReadWritePaths=")] == [
        "ReadWritePaths=/opt/warden/data /opt/warden/badges "
        "/opt/warden/gauntlet /opt/warden/logs"
    ]


def test_index_service_is_oneshot_unprivileged_and_write_isolated():
    service = (SYSTEMD / "warden-index.service").read_text(encoding="utf-8")

    for contract in (
        "Type=oneshot",
        "TimeoutStartSec=30m",
        "User=warden",
        "Group=warden",
        "WorkingDirectory=/opt/warden/current",
        "/opt/warden/current/.venv/bin/python scripts/refresh_safety_index.py --index-root /opt/warden-index",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "Environment=PYTHONDONTWRITEBYTECODE=1",
        "Environment=WARDEN_PROTECTION_DB=/opt/warden/data/protection.db",
        "EnvironmentFile=/opt/warden/index.env",
        "ExecStart=/usr/bin/flock --exclusive --nonblock /opt/warden-index/.refresh.lock",
        "PrivateTmp=true",
        "RestrictSUIDSGID=true",
        "ReadWritePaths=/opt/warden-index",
    ):
        assert contract in service
    assert [line for line in service.splitlines() if line.startswith("ReadWritePaths=")] == [
        "ReadWritePaths=/opt/warden-index"
    ]
    assert "--from-committed-snapshot" not in service
    assert "EnvironmentFile=/opt/warden/.env" not in service


def test_marketplace_fetch_runs_as_a_dedicated_secretless_identity():
    fetch_service = (SYSTEMD / "warden-index-fetch.service").read_text(encoding="utf-8")
    index_service = (SYSTEMD / "warden-index.service").read_text(encoding="utf-8")

    for contract in (
        "Type=oneshot",
        "User=warden-fetch",
        "Group=warden-fetch",
        "Environment=HOME=/var/lib/warden-fetch",
        "scripts/fetch_marketplace_snapshot.py",
        "--snapshot /opt/warden-snapshot/agents-v1.jsonl",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "InaccessiblePaths=/opt/warden/.env /opt/warden/index.env",
        "ReadWritePaths=/opt/warden-snapshot /var/lib/warden-fetch",
    ):
        assert contract in fetch_service
    assert "EnvironmentFile=" not in fetch_service
    assert "WARDEN_BADGE_SECRET" not in fetch_service
    assert "WARDEN_ISSUER" not in fetch_service

    assert "Requires=warden-index-fetch.service" in index_service
    assert "After=warden-index-fetch.service" in index_service
    assert "--snapshot /opt/warden-snapshot/agents-v1.jsonl" in index_service
    assert "--snapshot-owner warden-fetch" in index_service
    assert "onchainos" not in index_service
    assert "EnvironmentFile=/opt/warden/index.env" in index_service


def test_index_timer_is_persistent_six_hour_calendar_with_jitter():
    timer = (SYSTEMD / "warden-index.timer").read_text(encoding="utf-8")

    assert "OnCalendar=*-*-* 00/6:00:00 UTC" in timer
    assert "Persistent=true" in timer
    randomized = re.search(r"^RandomizedDelaySec=(\d+)m$", timer, re.MULTILINE)
    assert randomized
    assert 1 <= int(randomized.group(1)) <= 60
    assert "WantedBy=timers.target" in timer


def test_nginx_routes_index_artifacts_from_the_flat_site_layout():
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")

    assert "root /opt/warden-site;" in nginx
    assert "/opt/warden-site/current" not in nginx
    assert "/opt/warden-index" not in nginx
    for location in ("location = /agents", "location = /agents/"):
        block = re.search(
            rf"{re.escape(location)}\s*\{{(?P<body>.*?)\n    \}}",
            nginx,
            re.DOTALL,
        )
        assert block, location
        assert "try_files /agents/index.html =404;" in block.group("body")

    numeric = re.search(
        r"location ~ \^/agents/\(\[0-9\]\+\)/\?\$ \{(?P<body>.*?)\n    \}",
        nginx,
        re.DOTALL,
    )
    assert numeric
    assert "try_files /agents/$1.html =404;" in numeric.group("body")

    generic_data = re.search(r"location /data/ \{(?P<body>.*?)\n    \}", nginx, re.DOTALL)
    assert generic_data
    assert "try_files $uri =404;" in generic_data.group("body")
    for artifact in ("marketplace-summary.json", "warden-services.json"):
        assert (ROOT / "site" / "data" / artifact).is_file()


def test_deploy_runbook_requires_cli_preflight_units_verification_logs_and_rollback():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    for contract in (
        "/opt/warden-index/releases",
        "command -v onchainos",
        "onchainos --version",
        "unverified until an approved deploy",
        "systemd-analyze verify",
        "systemd-analyze calendar",
        "systemctl list-timers warden-index.timer",
        "journalctl -u warden-index.service",
        "deploy/systemd/warden-index.service",
        "deploy/systemd/warden-index-fetch.service",
        "deploy/systemd/warden-index.timer",
        "certbot certonly --webroot",
        "--from-committed-snapshot",
        "dropped = max(expected - sampled, 0)",
    ):
        assert contract in runbook
    assert not re.search(r"^certbot --nginx", runbook, re.MULTILINE)
    assert re.search(r"ln -s .*releases/.+current", runbook)
    candidate_refresh = runbook.index("systemctl start warden-index-candidate.service")
    app_promotion = runbook.index('mv -Tf "$app_link" /opt/warden/current')
    assert candidate_refresh < app_promotion
    assert runbook.count("git archive --format=tar HEAD") >= 4
    assert "tar --exclude" not in runbook
    assert "find /opt/warden-site" not in runbook
    assert "tar -xf - -C /opt/warden'" not in runbook
    assert "/opt/warden/releases/<commit>" in runbook
    assert "/opt/warden/current" in runbook
    assert "/opt/warden/.env" in runbook
    assert 'test "${WARDEN_PROTECTION_DB:-}" = /opt/warden/data/protection.db' in runbook
    assert "WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in runbook
    assert runbook.count('test "${#release}" -eq 40') == 4
    assert "test ! -e /opt/warden/releases/$release" in runbook
    assert "test ! -L /opt/warden/releases/$release" in runbook
    assert runbook.count('test ! -e "$app/badges"') == 1
    assert runbook.count('test ! -e "$app/gauntlet"') == 1
    assert runbook.count('test ! -L "$app/badges"') == 1
    assert runbook.count('test ! -L "$app/gauntlet"') == 1
    assert runbook.count('ln -s /opt/warden/badges "$app/badges"') == 1
    assert runbook.count('ln -s /opt/warden/gauntlet "$app/gauntlet"') == 1
    assert runbook.count('test "$(readlink -f "$app/badges")" = /opt/warden/badges') == 1
    assert runbook.count('test "$(readlink -f "$app/gauntlet")" = /opt/warden/gauntlet') == 1
    app_tests = runbook.index('"$app/.venv/bin/pytest" -q')
    app_promotion = runbook.index('mv -Tf "$app_link" /opt/warden/current')
    assert app_tests < app_promotion
    assert 'chmod -R u=rwX,go=rX "$app"' in runbook
    assert 'mv -Tf "$app_link" /opt/warden/current' in runbook
    assert 'mv -Tf "$static_link" /opt/warden-site/current' in runbook


def test_deploy_quiesces_index_before_rollback_capture_and_validates_configs_before_links():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    block = re.findall(
        r"Then run on the VPS:.*?```bash\r?\n(.*?)\r?\n```",
        runbook,
        re.DOTALL,
    )[0]

    stop_timer = block.index("systemctl stop warden-index.timer")
    quiesced = block.index("systemctl is-active --quiet warden-index.service")
    capture = block.index('previous_index_target="$(readlink -- /opt/warden-index/current)"')
    promotion = block.index('mv -Tf "$app_link" /opt/warden/current')
    install_configs = block.index('install_release_configs "$app"')
    installed_verify = block.index("systemd-analyze verify /etc/systemd/system/warden.service")
    nginx_verify = block.index("nginx -t", installed_verify)
    compatibility = block.index("--validate-release", quiesced)

    assert stop_timer < quiesced < capture
    assert compatibility < promotion
    assert install_configs < installed_verify < nginx_verify < promotion
    assert "not traffic-atomic as a bundle" in runbook
    assert "v2 marketplace-summary" in runbook


def test_deploy_compares_badge_secrets_without_exposing_them_to_fetch_user():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    assert "useradd --system --home-dir /var/lib/warden-fetch" in runbook
    assert "chown root:warden /opt/warden/.env /opt/warden/index.env" in runbook
    assert "chmod 0640 /opt/warden/.env /opt/warden/index.env" in runbook
    assert "runuser -u warden-fetch -- test ! -r /opt/warden/.env" in runbook
    assert "runuser -u warden-fetch -- test ! -r /opt/warden/index.env" in runbook
    assert 'app_badge_secret="$WARDEN_BADGE_SECRET"' in runbook
    assert 'test "$app_badge_secret" = "$WARDEN_BADGE_SECRET"' in runbook
    assert 'echo "$app_badge_secret"' not in runbook
    assert 'printf "%s" "$app_badge_secret"' not in runbook


def test_deploy_vps_command_blocks_fail_fast():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    vps_blocks = re.findall(
        r"Then run on the VPS:.*?```bash\r?\n(.*?)\r?\n```",
        runbook,
        re.DOTALL,
    )
    local_blocks = re.findall(
        r"Run locally from the repository root after explicit approval:.*?"
        r"```bash\r?\n(.*?)\r?\n```",
        runbook,
        re.DOTALL,
    )

    assert len(vps_blocks) == 1
    assert len(local_blocks) == 2
    assert all(
        block.splitlines()[0] == "set -euo pipefail" for block in [*local_blocks, *vps_blocks]
    )

    preflight_calls = (
        "reject_symlink /opt/warden",
        "reject_symlink /opt/warden/releases",
        "reject_symlink /opt/warden-site",
        "reject_symlink /opt/warden-site/releases",
        "reject_symlink /opt/warden-index",
        "reject_symlink /opt/warden-index/releases",
        "reject_symlink /opt/warden-index/candidates",
        "reject_symlink /opt/warden/badges",
        "reject_symlink /opt/warden/gauntlet",
        "reject_symlink /opt/warden/data",
        "reject_symlink /opt/warden/issuer-history.json",
        "reject_symlink /opt/warden/.env",
        "reject_symlink /opt/warden/index.env",
        "validate_current_link /opt/warden/current /opt/warden/releases",
        "validate_current_link /opt/warden-site/current /opt/warden-site/releases",
        "validate_current_link /opt/warden-index/current /opt/warden-index/releases",
    )
    for block in vps_blocks:
        first_mutation = min(
            position
            for command in ("install -d", "chown ")
            if (position := block.find(command)) >= 0
        )
        for call in preflight_calls:
            assert 0 <= block.find(call) < first_mutation


def test_candidate_gates_precede_atomic_app_and_static_promotion():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    vps_blocks = re.findall(
        r"Then run on the VPS:.*?```bash\r?\n(.*?)\r?\n```",
        runbook,
        re.DOTALL,
    )

    for block in vps_blocks:
        promotion = block.index('mv -Tf "$app_link" /opt/warden/current')
        for gate in (
            'systemd-analyze verify "$candidate_unit_dir/warden-candidate.service" '
            '"$candidate_unit_dir/warden-index-fetch-candidate.service" '
            '"$candidate_unit_dir/warden-index-candidate.service" '
            '"$candidate_unit_dir/warden-index-candidate.timer"',
            "systemctl daemon-reload",
            'curl -fsS "http://127.0.0.1:$candidate_port/health"',
            "--index-root $index_candidate",
            'test -L "$index_candidate/current"',
        ):
            assert block.index(gate) < promotion
        assert block.index('mv -Tf "$static_link" /opt/warden-site/current') >= promotion
        assert "rollback_release()" in block
        assert "if ! activate_release; then" in block
        assert "restore_legacy_configs" in block
        assert block.index("systemctl restart warden.service || return") < block.index(
            "systemctl enable warden.service || return"
        )
        assert "systemctl enable --now warden.service" not in block
        assert 'curl -fsS "http://127.0.0.1:$PORT/.well-known/apa-issuer.json"' in block


def test_rollback_installs_matching_versioned_configs_before_restart():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    rollback = runbook.split("## Application Rollback", 1)[1].split("## Nginx Shape", 1)[0]

    for source, destination in (
        ("deploy/systemd/warden-index.service", "/etc/systemd/system/warden-index.service"),
        (
            "deploy/systemd/warden-index-fetch.service",
            "/etc/systemd/system/warden-index-fetch.service",
        ),
        ("deploy/systemd/warden-index.timer", "/etc/systemd/system/warden-index.timer"),
        ("deploy/nginx-warden.conf", "/etc/nginx/sites-available/warden.gudman.xyz.conf"),
    ):
        assert f'install -m 0644 "$app/{source}" {destination}' in rollback
    assert (
        'render_app_service "$app/deploy/warden.service" "$rollback_service" '
        "/opt/warden/current"
    ) in rollback
    assert (
        'install -m 0644 "$rollback_service" /etc/systemd/system/warden.service'
        in rollback
    )
    assert rollback.index("install -m 0644") < rollback.index("systemctl daemon-reload")
    assert rollback.index("nginx -t") < rollback.index(
        'mv -Tf "/opt/warden/.current-rollback-$release" /opt/warden/current'
    )
    assert rollback.index("systemctl daemon-reload") < rollback.index(
        "systemctl restart warden.service"
    )


def test_runbook_does_not_source_service_environment_as_root_and_validates_issuer_seed():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    assert "/opt/warden/index.env" in runbook
    assert 'seed = b64u_decode(os.environ["WARDEN_ISSUER_KEY"])' in runbook
    assert "assert len(seed) == 32" in runbook
    assert "WARDEN_ISSUER_PUBLIC_KEY" in runbook
    assert "WARDEN_ISSUER_HISTORY" in runbook
    assert "issuer document does not match index verification keys" in runbook
    assert (
        "test \"$(grep -Ec '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' /opt/warden/index.env)\" -eq 3"
    ) in runbook
    assert "WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in (
        SYSTEMD / "warden-index.service"
    ).read_text(encoding="utf-8")
    source_lines = [line for line in runbook.splitlines() if ". /opt/warden/.env" in line]
    assert source_lines
    assert all("runuser -u warden" in line for line in source_lines)
    onchainos_preflights = [
        line for line in runbook.splitlines() if "runuser -u warden" in line and "onchainos" in line
    ]
    assert len(onchainos_preflights) == 2
    assert all("-- env -i " in line for line in onchainos_preflights)
    assert "chown root:warden /opt/warden/.env /opt/warden/index.env" in runbook
    index_service = (SYSTEMD / "warden-index.service").read_text(encoding="utf-8")
    assert "EnvironmentFile=/opt/warden/.env" not in index_service
    index_env_contract = runbook.split("test -f /opt/warden/index.env", 1)[1].split(
        'test ! -e "$app/.venv"', 1
    )[0]
    assert "WARDEN_BADGE_SECRET" in index_env_contract
    assert "WARDEN_ISSUER_PUBLIC_KEY" in index_env_contract
    assert "WARDEN_ISSUER_HISTORY=/opt/warden/issuer-history\\.json" in index_env_contract
    assert "test -f /opt/warden/issuer-history.json" in runbook
    assert "chown root:warden /opt/warden/issuer-history.json" in runbook
    assert "chmod 0640 /opt/warden/issuer-history.json" in runbook
    assert "WARDEN_ISSUER_KEY=" not in index_env_contract


def test_runbook_rotates_issuer_and_index_trust_material_as_one_quiesced_change():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    rotation = runbook.split("## Issuer Key Rotation", 1)[1].split("\n## ", 1)[0]

    for path in (
        "/opt/warden/.env.rotation",
        "/opt/warden/index.env.rotation",
        "/opt/warden/issuer-history.json.rotation",
    ):
        assert f"reject_symlink {path}" in rotation
    assert "systemctl stop warden.service" in rotation
    assert "systemctl stop warden-index.timer warden-apa-reprobe.timer" in rotation
    assert "trap rollback EXIT" in rotation
    assert 'mv -Tf "$candidate_app_env" /opt/warden/.env' in rotation
    assert 'mv -Tf "$candidate_index_env" /opt/warden/index.env' in rotation
    assert 'mv -Tf "$candidate_history" /opt/warden/issuer-history.json' in rotation
    assert "issuer_document()" in rotation
    assert "load_apa_issuer_history" in rotation
    assert "issuer document does not match index verification keys" in rotation
    assert 'set(document) == {"issuer", "keys"}' in rotation
    assert 'set(key) == {"kid", "pub", "not_after"}' in rotation
    assert 'app_badge_secret="$WARDEN_BADGE_SECRET"' in rotation
    assert 'test "$app_badge_secret" = "$WARDEN_BADGE_SECRET"' in rotation
    assert "python scripts/refresh_safety_index.py" in rotation
    assert "systemctl start warden.service" in rotation
    assert "systemctl start warden-index.timer warden-apa-reprobe.timer" in rotation
    assert rotation.index("systemctl stop warden.service") < rotation.index(
        'mv -Tf "$candidate_app_env" /opt/warden/.env'
    )
    assert rotation.rindex("python scripts/refresh_safety_index.py") < rotation.rindex(
        "systemctl start warden.service"
    )
    assert "finite retirement cutoff" in rotation
    assert "one-hour post-retirement grace window" in rotation
    assert "never print" in rotation.lower()


def test_every_deploy_shell_block_and_remote_upload_fail_fast():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\r?\n(.*?)\r?\n```", runbook, re.DOTALL)

    assert blocks
    assert all(block.splitlines()[0] == "set -euo pipefail" for block in blocks)
    remote_uploads = [
        line.strip()
        for line in runbook.splitlines()
        if line.strip().startswith("ssh root@75.119.153.252")
    ]
    assert len(remote_uploads) == 4
    assert all('"set -euo pipefail;' in line for line in remote_uploads)
    for line in remote_uploads:
        if "/opt/warden-site/releases" in line:
            root = "/opt/warden-site"
        else:
            root = "/opt/warden"
        install = line.index("install -d")
        assert line.index(f"test ! -L {root}") < install
        assert line.index(f"test ! -L {root}/releases") < install
        assert line.index(f"test -e {root}/current") < install
        assert line.index(f"test -L {root}/current") < install
