"""Periodic APA heartbeat re-probe and persistence contracts."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.reprobe_protections import _endpoint_url, format_summary_log, reprobe_protections
from warden import protection, protection_store
from warden.badges import b64u_encode

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _apa_environment(tmp_path, monkeypatch):
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )


def _public_key() -> str:
    key = Ed25519PrivateKey.generate()
    return b64u_encode(key.public_key().public_bytes_raw(), "ed25519")


def _store_record(
    endpoint_host: str,
    pub: str,
    *,
    status: str = "active",
    bind: bool = False,
) -> dict[str, object]:
    record = protection.issue_attestation(endpoint_host, pub, 41_207, status=status)
    protection_store.commit_attestation_events(
        [("issued", record)],
        new_binding=(endpoint_host, pub) if bind else None,
    )
    return record


def test_existing_database_migrates_last_probed_at_without_losing_attestations(tmp_path):
    path = tmp_path / "protection.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE attestations ("
            "attestation_id TEXT PRIMARY KEY, endpoint_host TEXT NOT NULL, "
            "status TEXT NOT NULL, record_json TEXT NOT NULL, created_at INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO attestations VALUES ('existing', 'asp.example.org', 'active', '{}', 7)"
        )

    with protection_store._connect() as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(attestations)").fetchall()
        }
        stored = connection.execute(
            "SELECT attestation_id, created_at, last_probed_at FROM attestations"
        ).fetchone()

    assert "last_probed_at" in columns
    assert stored == ("existing", 7, None)
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_ipv6_endpoint_identity_is_canonical_for_registration_and_reprobe():
    endpoint_host = protection._canonical_endpoint_host(
        "2001:4860:4860::8888",
        scheme="https",
        port=8443,
    )

    assert endpoint_host == "[2001:4860:4860::8888]:8443"
    assert _endpoint_url(endpoint_host) == "https://[2001:4860:4860::8888]:8443"


@pytest.mark.asyncio
async def test_fetch_proof_normalizes_http_transport_failure(monkeypatch):
    async def validate(endpoint: str):
        return "https://203.0.113.10", "offline.example.org", urlsplit(endpoint)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        def stream(self, method, url, **kwargs):
            raise httpx.ConnectError(f"offline: {method} {url}")

    monkeypatch.setattr(protection, "validate_public_http_url", validate)
    monkeypatch.setattr(protection.httpx, "AsyncClient", lambda **kwargs: Client())

    with pytest.raises(protection.ProtectionProbeUnavailable, match="request failed"):
        await protection._fetch_proof("https://offline.example.org")


def test_reprobe_targets_are_ordered_unprobed_then_oldest():
    pubs = {
        host: _public_key() for host in ("new.example.org", "old.example.org", "never.example.org")
    }
    for host, pub in pubs.items():
        _store_record(host, pub, bind=True)

    with protection_store._connect() as connection:
        connection.execute(
            "UPDATE attestations SET last_probed_at = NULL WHERE endpoint_host = ?",
            ("never.example.org",),
        )
        connection.execute(
            "UPDATE attestations SET last_probed_at = 20 WHERE endpoint_host = ?",
            ("new.example.org",),
        )
        connection.execute(
            "UPDATE attestations SET last_probed_at = 10 WHERE endpoint_host = ?",
            ("old.example.org",),
        )

    assert [target["endpoint_host"] for target in protection_store.list_reprobe_targets()] == [
        "never.example.org",
        "old.example.org",
        "new.example.org",
    ]


@pytest.mark.asyncio
async def test_reprobe_has_a_whole_probe_deadline():
    endpoint_host = "slow.example.org"
    pub = _public_key()
    record = _store_record(endpoint_host, pub, bind=True)

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        await asyncio.Event().wait()
        raise AssertionError(f"unreachable after timeout: {endpoint}")

    summary = await reprobe_protections(
        probe_guard=probe_guard,
        now=1_900_000_050,
        probe_timeout_seconds=0.01,
    )

    stored = protection_store.get_attestation(str(record["attestation_id"]))
    assert stored is not None and stored["status"] == "stale"
    assert summary["stale"] == 1


@pytest.mark.asyncio
async def test_reprobe_uses_bounded_endpoint_concurrency_in_fair_order():
    hosts = [
        "never.example.org",
        "oldest.example.org",
        "middle.example.org",
        "newest.example.org",
    ]
    pubs = {host: _public_key() for host in hosts}
    for host, pub in pubs.items():
        _store_record(host, pub, bind=True)
    with protection_store._connect() as connection:
        connection.execute(
            "UPDATE attestations SET last_probed_at = NULL WHERE endpoint_host = ?",
            (hosts[0],),
        )
        for last_probed_at, host in enumerate(hosts[1:], start=10):
            connection.execute(
                "UPDATE attestations SET last_probed_at = ? WHERE endpoint_host = ?",
                (last_probed_at, host),
            )

    active = 0
    maximum_active = 0
    starts: list[str] = []

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        nonlocal active, maximum_active
        host = endpoint.removeprefix("https://")
        starts.append(host)
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return host, pubs[host], 5

    summary = await reprobe_protections(
        probe_guard=probe_guard,
        now=1_900_000_075,
        max_concurrency=2,
    )

    assert starts == hosts
    assert maximum_active == 2
    assert summary["active"] == len(hosts)


@pytest.mark.asyncio
async def test_reprobe_groups_attestations_and_refreshes_signed_freshness():
    endpoint_host = "asp.example.org"
    pub = _public_key()
    records = (
        _store_record(endpoint_host, pub, bind=True),
        _store_record(endpoint_host, pub),
    )
    calls: list[str] = []

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        calls.append(endpoint)
        return endpoint_host, pub, 52_001

    probed_at = 1_900_000_000
    summary = await reprobe_protections(probe_guard=probe_guard, now=probed_at)

    assert calls == ["https://asp.example.org"]
    assert summary == {
        "targets": 2,
        "endpoints": 1,
        "active": 2,
        "stale": 0,
        "invalid": 0,
        "key_changed": 0,
        "skipped": 0,
    }
    assert format_summary_log(summary) == (
        "targets=2 endpoints=1 active=2 stale=0 invalid=0 key_changed=0 skipped=0"
    )
    for original in records:
        refreshed = protection_store.get_attestation(str(original["attestation_id"]))
        assert refreshed is not None
        assert refreshed["status"] == "active"
        assert refreshed["scans_24h"] == 52_001
        assert refreshed["verified_at"] == probed_at
        assert refreshed["expires_at"] == probed_at + protection.ATTESTATION_TTL_SECONDS
        assert protection.verify_attestation_record(refreshed) is True

    targets = protection_store.list_reprobe_targets()
    assert {target["last_probed_at"] for target in targets} == {probed_at}
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "issued",
        "reprobed",
        "reprobed",
    ]


@pytest.mark.asyncio
async def test_unreachable_guard_persists_signed_stale_status_and_probe_time():
    endpoint_host = "offline.example.org"
    pub = _public_key()
    record = _store_record(endpoint_host, pub, bind=True)

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        raise httpx.ConnectError(f"offline: {endpoint}")

    probed_at = 1_900_000_100
    summary = await reprobe_protections(probe_guard=probe_guard, now=probed_at)

    stale = protection_store.get_attestation(str(record["attestation_id"]))
    assert stale is not None
    assert stale["status"] == "stale"
    assert stale["verified_at"] == record["verified_at"]
    assert stale["expires_at"] == record["expires_at"]
    assert protection.verify_attestation_record(stale) is True
    assert summary["stale"] == 1
    with protection_store._connect() as connection:
        last_probed_at = connection.execute(
            "SELECT last_probed_at FROM attestations WHERE attestation_id = ?",
            (record["attestation_id"],),
        ).fetchone()[0]
    assert last_probed_at == probed_at
    assert protection_store.read_log()[-1]["event"] == "stale"


@pytest.mark.asyncio
async def test_bad_signature_persists_invalid_instead_of_stale():
    endpoint_host = "invalid.example.org"
    pub = _public_key()
    record = _store_record(endpoint_host, pub, bind=True)

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        raise protection.ProtectionProofInvalid(f"bad signed proof from {endpoint}")

    summary = await reprobe_protections(probe_guard=probe_guard, now=1_900_000_200)

    invalid = protection_store.get_attestation(str(record["attestation_id"]))
    assert invalid is not None
    assert invalid["status"] == "invalid"
    assert protection.verify_attestation_record(invalid) is True
    assert summary["invalid"] == 1
    assert protection_store.read_log()[-1]["event"] == "invalid"


@pytest.mark.asyncio
async def test_probe_guard_raises_structured_invalid_error_for_malformed_proof(monkeypatch):
    async def fetch_proof(endpoint: str) -> tuple[str, dict[str, object]]:
        return "malformed.example.org", {"endpoint": endpoint}

    monkeypatch.setattr(protection, "_fetch_proof", fetch_proof)
    with pytest.raises(protection.ProtectionProofInvalid, match="missing 'pub'"):
        await protection.probe_guard("https://malformed.example.org")


@pytest.mark.asyncio
async def test_changed_key_is_sticky_and_terminal_records_are_not_reprobed():
    endpoint_host = "rotated.example.org"
    bound_pub = _public_key()
    changed_pub = _public_key()
    active = _store_record(endpoint_host, bound_pub, bind=True)
    revoked = _store_record(endpoint_host, bound_pub, status="revoked")

    async def changed_probe(endpoint: str) -> tuple[str, str, int | None]:
        return endpoint_host, changed_pub, 12

    summary = await reprobe_protections(probe_guard=changed_probe, now=1_900_000_300)

    changed = protection_store.get_attestation(str(active["attestation_id"]))
    still_revoked = protection_store.get_attestation(str(revoked["attestation_id"]))
    assert changed is not None and changed["status"] == "key-changed"
    assert still_revoked is not None and still_revoked["status"] == "revoked"
    assert protection_store.get_binding(endpoint_host)["key_changed"] is True
    assert summary["key_changed"] == 1

    async def unexpected_probe(endpoint: str) -> tuple[str, str, int | None]:
        raise AssertionError(f"terminal binding must not be probed: {endpoint}")

    next_summary = await reprobe_protections(
        probe_guard=unexpected_probe,
        now=1_900_000_400,
    )
    assert next_summary["targets"] == 0
    assert next_summary["endpoints"] == 0


@pytest.mark.asyncio
async def test_inflight_reprobe_does_not_overwrite_a_concurrent_revocation():
    endpoint_host = "revoked-during-probe.example.org"
    pub = _public_key()
    active = _store_record(endpoint_host, pub, bind=True)

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        assert endpoint == f"https://{endpoint_host}"
        revoked = protection.resign_attestation_status(active, "revoked")
        protection_store.commit_attestation_events([("revoked", revoked)])
        return endpoint_host, pub, 52_001

    summary = await reprobe_protections(probe_guard=probe_guard, now=1_900_000_500)

    stored = protection_store.get_attestation(str(active["attestation_id"]))
    assert stored is not None and stored["status"] == "revoked"
    assert summary["active"] == 0
    assert summary["skipped"] == 1
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "revoked",
    ]


def test_reprobe_systemd_service_is_periodic_unprivileged_and_state_isolated():
    service = (ROOT / "deploy" / "systemd" / "warden-apa-reprobe.service").read_text(
        encoding="utf-8"
    )
    timer = (ROOT / "deploy" / "systemd" / "warden-apa-reprobe.timer").read_text(encoding="utf-8")

    for contract in (
        "Type=oneshot",
        "WorkingDirectory=/opt/warden/current",
        "EnvironmentFile=/opt/warden/.env",
        "ExecStart=/usr/bin/flock --exclusive --nonblock /opt/warden/data/.apa-reprobe.lock",
        "/opt/warden/current/.venv/bin/python scripts/reprobe_protections.py",
        "User=warden",
        "Group=warden",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ReadWritePaths=/opt/warden/data",
    ):
        assert contract in service
    assert "EnvironmentFile=/opt/warden/index.env" not in service
    assert "OnCalendar=*-*-* *:00/15:00 UTC" in timer
    assert "RandomizedDelaySec=2m" in timer
    assert "Persistent=true" in timer
    assert "Unit=warden-apa-reprobe.service" in timer


def test_deploy_installs_verifies_enables_and_rolls_back_reprobe_units():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    for source, destination in (
        (
            "deploy/systemd/warden-apa-reprobe.service",
            "/etc/systemd/system/warden-apa-reprobe.service",
        ),
        (
            "deploy/systemd/warden-apa-reprobe.timer",
            "/etc/systemd/system/warden-apa-reprobe.timer",
        ),
    ):
        assert f'install -m 0644 "$source_app/{source}" {destination}' in runbook
        assert f'install -m 0644 "$app/{source}" {destination}' in runbook

    promotion = runbook.index('mv -Tf "$app_link" /opt/warden/current')
    candidate_verify = (
        '"$candidate_unit_dir/warden-apa-reprobe-candidate.service" '
        '"$candidate_unit_dir/warden-apa-reprobe-candidate.timer"'
    )
    assert runbook.index(candidate_verify) < promotion
    assert "reprobe_timer_was_active=0" in runbook
    assert "reprobe_timer_was_enabled=0" in runbook
    assert "systemctl enable --now warden-apa-reprobe.timer || return" in runbook
    assert "systemctl disable --now warden-apa-reprobe.timer || true" in runbook
    assert "journalctl -u warden-apa-reprobe.service" in runbook
    assert "SVG and JSON routes never perform a live probe" in runbook


def test_deploy_index_public_key_preflight_is_narrow_and_nonprinting():
    runbook = (ROOT / "deploy" / "DEPLOY.md").read_text(encoding="utf-8")

    assert (
        "test \"$(grep -Ec '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' /opt/warden/index.env)\" -eq 3"
    ) in runbook
    assert "WARDEN_ISSUER_PUBLIC_KEY" in runbook
    assert "WARDEN_ISSUER_HISTORY" in runbook
    assert "issuer document does not match index verification keys" in runbook
    assert "WARDEN_PROTECTION_DB=/opt/warden/data/protection.db" in runbook
