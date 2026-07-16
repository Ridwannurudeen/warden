"""Regression contracts for the flat app unit and checkpoint-aware deploy gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_flat_app_service_can_write_only_persistent_runtime_state() -> None:
    service = (ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")

    assert "WorkingDirectory=/opt/warden\n" in service
    assert "ExecStart=/opt/warden/.venv/bin/uvicorn" in service
    assert "/opt/warden/current" not in service
    assert [line for line in service.splitlines() if line.startswith("ReadWritePaths=")] == [
        "ReadWritePaths=/opt/warden/data /opt/warden/badges "
        "/opt/warden/gauntlet /opt/warden/logs"
    ]
    assert "ReadWritePaths=/opt/warden\n" not in service


def test_flat_upgrade_quiesces_writers_before_guarded_checkpoint_migration() -> None:
    runbook = (ROOT / "deploy" / "TRUST-LAYER-DEPLOY.md").read_text(encoding="utf-8")

    stop = runbook.index("systemctl stop warden.service")
    migration = runbook.index("migrate_log_checkpoint()")
    start = runbook.index("systemctl start warden.service", migration)

    assert stop < migration < start
    assert "! systemctl is-active --quiet warden.service" in runbook[stop:migration]
    assert ". /opt/warden/.env" in runbook[stop:migration]
    assert "SELECT name FROM sqlite_master" in runbook[stop:migration]
    assert "verify_log_chain(entries, checkpoint)" in runbook[stop:start]
    assert (
        "install -d -o warden -g warden -m 0750 /opt/warden/data "
        "/opt/warden/badges /opt/warden/gauntlet /opt/warden/logs"
    ) in runbook
    assert "chown -R root:root /opt/warden/warden" in runbook
    assert "/opt/warden/deploy /opt/warden/.venv" in runbook
    assert (
        "install -m 0644 /opt/warden/deploy/warden.service "
        "/etc/systemd/system/warden.service"
    ) in runbook


def test_blue_green_runbook_rewrites_only_flat_unit_code_paths() -> None:
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    assert runbook.count("reject_symlink /opt/warden/logs") == 2
    assert (
        "install -d -o warden -g warden -m 0750 /opt/warden/badges "
        "/opt/warden/gauntlet /opt/warden/data /opt/warden/logs"
    ) in runbook
    assert (
        "chown -hR warden:warden /opt/warden/badges /opt/warden/gauntlet "
        "/opt/warden/data /opt/warden/logs"
    ) in runbook
    assert 's#^WorkingDirectory=/opt/warden\\$#WorkingDirectory=$app_root#' in runbook
    assert 's#^ExecStart=/opt/warden/.venv/#ExecStart=$app_root/.venv/#' in runbook
    renderer = runbook[runbook.index("render_app_service() {") :]
    renderer = renderer[: renderer.index("candidate_service=")]
    assert "s#/opt/warden/current#" not in renderer
    assert 'render_app_service "$app/deploy/warden.service" "$candidate_service" "$app"' in runbook

    rollback = runbook[runbook.index("## Application Rollback") :]
    assert 'render_app_service "$app/deploy/warden.service" "$rollback_service" /opt/warden/current' in rollback
    assert (
        'install -m 0644 "$rollback_service" /etc/systemd/system/warden.service'
        in rollback
    )
    assert (
        'install -m 0644 "$app/deploy/warden.service" /etc/systemd/system/warden.service'
        not in rollback
    )
