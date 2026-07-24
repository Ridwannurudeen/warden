"""Deployment contracts for the productized fail-closed Warden Gateway."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_gateway_container_has_non_root_health_and_graceful_stop_contracts():
    dockerfile = (ROOT / "deploy" / "Dockerfile.gateway").read_text(encoding="utf-8")

    assert "USER warden-gateway" in dockerfile
    assert "HEALTHCHECK " in dockerfile
    assert "http://127.0.0.1:8787/healthz" in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert 'ENTRYPOINT ["warden-gateway"]' in dockerfile
    assert "WARDEN_GUARD_KEY=/var/lib/warden-gateway/guard_key" in dockerfile
    assert "WARDEN_GUARD_STATE=/var/lib/warden-gateway/state.json" in dockerfile


def test_gateway_systemd_unit_is_local_fail_closed_and_hardened():
    service = (ROOT / "deploy" / "systemd" / "warden-gateway.service").read_text(encoding="utf-8")

    assert "User=warden-gateway" in service
    assert "Group=warden-gateway" in service
    assert "StateDirectory=warden-gateway" in service
    assert "StateDirectoryMode=0700" in service
    assert "EnvironmentFile=" not in service
    assert "Environment=WARDEN_GUARD_KEY=/var/lib/warden-gateway/guard_key" in service
    assert "Environment=WARDEN_GUARD_STATE=/var/lib/warden-gateway/state.json" in service
    assert "--upstream http://127.0.0.1:8000" in service
    assert "--mode local" in service
    assert "--listen 127.0.0.1" in service
    assert "TimeoutStopSec=30s" in service
    for directive in (
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "RestrictSUIDSGID=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
    ):
        assert directive in service


def test_gateway_compose_sidecar_has_explicit_network_and_state_boundaries():
    compose = (ROOT / "deploy" / "docker-compose.gateway.yml").read_text(encoding="utf-8")

    assert "${WARDEN_AGENT_IMAGE:?Set WARDEN_AGENT_IMAGE}" in compose
    assert "127.0.0.1:8787:8787" in compose
    assert "http://protected-agent:8000" in compose
    assert "internal: true" in compose
    gateway = compose[compose.index("  warden-gateway:") :]
    gateway = gateway[: gateway.index("\nvolumes:")]
    assert "agent-egress" not in gateway
    assert "gateway-boundary" in gateway
    assert "warden-gateway-state:/var/lib/warden-gateway" in gateway
    assert "read_only: true" in gateway
    assert "no-new-privileges:true" in gateway
    assert "cap_drop:" in gateway
    assert "- ALL" in gateway
    assert "stop_grace_period: 30s" in gateway


def test_gateway_runbook_covers_fail_closed_metrics_lifecycle_and_rollback():
    runbook = (ROOT / "deploy" / "GATEWAY.md").read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    for statement in (
        "scanner failure",
        "invalid UTF-8",
        "oversized request",
        "proxy loop",
        "never reaches the upstream",
        "metadata-only",
        "No payloads, headers, secrets, wallet addresses, endpoint paths, or request IDs",
        "docker compose -f deploy/docker-compose.gateway.yml",
        "systemctl enable --now warden-gateway.service",
        "curl --fail http://127.0.0.1:8787/healthz",
        "curl --fail http://127.0.0.1:8787/metrics",
        "chmod 0700 /var/lib/warden-gateway",
        "Rollback",
        "Hosted paid mode remains unsupported",
    ):
        assert statement in normalized
