"""Deployment contracts for scheduled monitoring and public checkpoint publication."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"


def test_application_metrics_database_uses_the_persistent_data_boundary():
    service = (ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")

    assert "Environment=WARDEN_METRICS_DB=/opt/warden/data/runtime-metrics.db" in service
    assert "Environment=WARDEN_RATE_LIMIT_DB=/opt/warden/data/rate-limit.db" in service
    assert "Environment=WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in service
    assert "/opt/warden/data" in next(
        line for line in service.splitlines() if line.startswith("ReadWritePaths=")
    )


def test_application_runs_two_workers_only_with_shared_mutable_safety_boundaries():
    service = (ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")
    observability = (ROOT / "deploy" / "OBSERVABILITY.md").read_text(encoding="utf-8")
    reprobe = (SYSTEMD / "warden-apa-reprobe.service").read_text(encoding="utf-8")

    exec_start = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert exec_start.endswith("--workers 2")
    assert "Production runs two Uvicorn workers" in observability
    assert "runtime metrics and rate limits" in observability
    assert "APA protection records" in observability
    assert "Gauntlet and feedback records" in observability
    assert "legacy badge registry" in observability
    assert "at most four probes across all processes" in observability
    assert "orphaned leases expire after ten seconds" in observability
    assert "fails closed before network access" in observability
    assert "scheduled re-probe process" in observability
    assert "EnvironmentFile=/opt/warden/.env" in reprobe
    assert "Environment=WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in reprobe


def test_monitor_service_records_application_and_unsigned_challenge_then_notifies():
    service = (SYSTEMD / "warden-monitor.service").read_text(encoding="utf-8")
    timer = (SYSTEMD / "warden-monitor.timer").read_text(encoding="utf-8")

    assert "EnvironmentFile=-/opt/warden/monitor-alert.env" in service
    assert "WorkingDirectory=/opt/warden" in service
    assert "/opt/warden/current" not in service
    assert "/opt/warden-monitor" not in service
    assert "/opt/warden/scripts/monitor_readiness.py" in service
    assert "--url http://127.0.0.1:8031/health/ready" in service
    assert "--paid-url http://127.0.0.1:8031/scan" in service
    assert "--expected-resource-url https://warden.gudman.xyz/scan" in service
    assert "--output /opt/warden/monitor/service-monitor.json" in service
    assert "ExecStartPre=/opt/warden/.venv/bin/python" in service
    assert "ExecStartPost=" in service
    assert "/opt/warden/scripts/notify_service_transition.py" in service
    assert "--state /opt/warden/monitor/notifier-state.json" in service
    assert "WARDEN_ALERT_WEBHOOK_URL" not in service
    assert "ReadWritePaths=/opt/warden/monitor" in service
    assert "InaccessiblePaths=/opt/warden/.env" in service
    for directive in (
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "RestrictSUIDSGID=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    ):
        assert directive in service

    assert "OnCalendar=*-*-* *:00/5:00 UTC" in timer
    assert "Persistent=true" in timer
    assert "Unit=warden-monitor.service" in timer


def test_anchor_publisher_has_no_private_signing_environment_and_is_scheduled():
    service = (SYSTEMD / "warden-anchor-publish.service").read_text(encoding="utf-8")
    timer = (SYSTEMD / "warden-anchor-publish.timer").read_text(encoding="utf-8")

    assert "EnvironmentFile=" not in service
    assert "WorkingDirectory=/opt/warden" in service
    assert "/opt/warden/current" not in service
    assert "/opt/warden-anchor" not in service
    assert "Environment=WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in service
    assert "/opt/warden/scripts/publish_log_checkpoint.py" in service
    assert "--output /opt/warden/anchor/apa-log-anchor.json" in service
    assert "--history-output /opt/warden/anchor/apa-log-anchor-history.json" in service
    assert "ReadOnlyPaths=/opt/warden/data/protection.db" in service
    assert "ReadWritePaths=/opt/warden/anchor" in service
    assert "InaccessiblePaths=/opt/warden/.env" in service
    assert "/opt/warden/index.env" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "OnCalendar=*-*-* *:00/15:00 UTC" in timer
    assert "Persistent=true" in timer
    assert "Unit=warden-anchor-publish.service" in timer


def test_nginx_serves_runtime_evidence_from_exact_read_only_aliases():
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")
    generic_data = nginx.index("location /data/")

    aliases = {
        "/data/service-monitor.json": "/opt/warden/monitor/service-monitor.json",
        "/data/apa-log-anchor.json": "/opt/warden/anchor/apa-log-anchor.json",
        "/data/apa-log-anchor-history.json": ("/opt/warden/anchor/apa-log-anchor-history.json"),
    }
    for route, path in aliases.items():
        location = f"location = {route}"
        assert location in nginx
        assert f"alias {path};" in nginx
        assert nginx.index(location) < generic_data


def test_flat_deploy_runbook_verifies_installs_starts_and_can_restore_scheduled_units():
    runbook = (ROOT / "deploy" / "TRUST-LAYER-DEPLOY.md").read_text(encoding="utf-8")
    units = (
        "warden-monitor.service",
        "warden-monitor.timer",
        "warden-anchor-publish.service",
        "warden-anchor-publish.timer",
    )

    candidate_verify = runbook.index(
        "systemd-analyze verify \\\n  /opt/warden/deploy/warden.service"
    )
    captured_active_state = runbook.index(
        'systemctl is-active "$unit" > "$unit_backup/$unit.active"'
    )
    quiesce = runbook.index("systemctl stop warden.service")
    first_install = runbook.index(
        "install -m 0644 /opt/warden/deploy/systemd/warden-monitor.service"
    )
    installed_verify = runbook.index(
        "systemd-analyze verify \\\n  /etc/systemd/system/warden.service"
    )
    enable = runbook.index(
        "systemctl enable --now warden-monitor.timer warden-anchor-publish.timer"
    )
    assert captured_active_state < quiesce < candidate_verify < first_install
    assert first_install < installed_verify < enable

    for unit in units:
        assert f"/opt/warden/deploy/systemd/{unit}" in runbook
        assert f"/etc/systemd/system/{unit}" in runbook
    assert '"$backup/$unit"' in runbook
    assert "/opt/warden/monitor /opt/warden/anchor" in runbook
    assert "systemctl start warden-monitor.service" in runbook
    assert "systemctl start warden-anchor-publish.service" in runbook
    assert "systemctl disable --now warden-monitor.timer warden-anchor-publish.timer" in runbook
    assert "systemctl daemon-reload" in runbook
    assert (
        "Runtime JSON under `/opt/warden/monitor` and `/opt/warden/anchor` is retained" in runbook
    )
    assert "/data/service-monitor.json` → `/opt/warden/monitor/service-monitor.json" in runbook
    assert "/data/apa-log-anchor.json` → `/opt/warden/anchor/apa-log-anchor.json" in runbook
    assert (
        "/data/apa-log-anchor-history.json` → `/opt/warden/anchor/apa-log-anchor-history.json"
    ) in runbook
