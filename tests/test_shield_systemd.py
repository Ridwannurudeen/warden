"""Source-ready Warden Shield operator and systemd contracts."""

from pathlib import Path

import pytest

from scripts import run_shield
from warden import auditor, shield

ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"


def test_shield_service_is_daily_hardened_bounded_and_uses_a_narrow_environment():
    service = (SYSTEMD / "warden-shield.service").read_text(encoding="utf-8")
    timer = (SYSTEMD / "warden-shield.timer").read_text(encoding="utf-8")

    for contract in (
        "Type=oneshot",
        "TimeoutStartSec=20m",
        "WorkingDirectory=/opt/warden",
        "EnvironmentFile=/opt/warden/shield.env",
        "ExecStart=/usr/bin/flock --exclusive --nonblock /opt/warden/data/shield/.runner.lock",
        "/opt/warden/scripts/run_shield.py "
        "--config /opt/warden/shield-targets.json "
        "--state /opt/warden/data/shield/lifecycle.json",
        "User=warden",
        "Group=warden",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "RestrictSUIDSGID=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "ReadOnlyPaths=/opt/warden/shield-targets.json",
        "ReadWritePaths=/opt/warden/data /opt/warden/badges",
        "InaccessiblePaths=/opt/warden/.env -/opt/warden/index.env",
    ):
        assert contract in service
    assert "SuccessExitStatus=" not in service
    assert "EnvironmentFile=/opt/warden/.env" not in service
    assert "OnCalendar=*-*-* 02:40:00 UTC" in timer
    assert "RandomizedDelaySec=15m" in timer
    assert "Persistent=true" in timer
    assert "Unit=warden-shield.service" in timer


def test_shield_runner_uses_the_existing_consented_fixed_battery_auditor():
    source = (ROOT / "warden" / "shield.py").read_text(encoding="utf-8")
    script = (ROOT / "scripts" / "run_shield.py").read_text(encoding="utf-8")

    assert "AgentAuditor()" in source
    assert "await audit_client.audit(target.target_url)" in source
    assert "sample_prompts" not in source
    assert "publish_from_badge(badge)" in source
    assert auditor.AUDIT_TOTAL_TIMEOUT_SECONDS == 30.0
    assert shield.MAX_TARGETS == 32
    assert shield.MAX_EVENTS == 1_000
    assert "_require_production_environment()" in script


def test_shield_runner_requires_production_consent_and_signing_state(monkeypatch):
    required = {
        "WARDEN_ENVIRONMENT": "production",
        "WARDEN_REQUIRE_CONSENT": "true",
        "WARDEN_BADGE_SECRET": "test-badge-secret",
        "WARDEN_ISSUER_KEY": "ed25519-seed:test",
        "WARDEN_PROTECTION_DB": "/opt/warden/data/protection.db",
    }
    for name, value in required.items():
        monkeypatch.setenv(name, value)
    run_shield._require_production_environment()

    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "false")
    with pytest.raises(ValueError, match="hard target consent"):
        run_shield._require_production_environment()


def test_example_config_and_operator_document_are_explicit_and_honest():
    example = (ROOT / "deploy" / "shield-targets.example.json").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "SHIELD_LIFECYCLE.md").read_text(encoding="utf-8")
    normalized_runbook = " ".join(runbook.split())

    for contract in (
        '"owner_enrolled": true',
        '"enrollment_revision": 1',
        f'"sha256": "{auditor.AUDIT_BATTERY_SHA256}"',
    ):
        assert contract in example
    for statement in (
        "source-ready, not deployed",
        "point-in-time evidence",
        "does not create a contractual SLA",
        "same battery ID, version, and SHA-256",
        "does not store probe payloads",
        "systemctl enable --now warden-shield.timer",
    ):
        assert statement in normalized_runbook
