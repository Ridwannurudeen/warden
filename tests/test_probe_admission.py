"""Cross-process contracts for outbound APA probe admission."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from warden import protection, protection_store


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _shared_protection_database(tmp_path, monkeypatch):
    database = tmp_path / "protection.db"
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(database))
    return database


def test_probe_capacity_is_atomic_across_processes_and_orphans_expire(
    _shared_protection_database,
):
    database = _shared_protection_database
    with protection_store._connect():
        pass
    worker = """
import json
import os
import sys
from warden import protection, protection_store

acquired = protection_store.acquire_probe_lease(
    sys.argv[1],
    now=100.0,
    ttl_seconds=protection.PROBE_LEASE_TTL_SECONDS,
    max_leases=protection.MAX_CONCURRENT_PROBES,
)
sys.stdout.write(json.dumps(acquired) + "\\n")
sys.stdout.flush()
os._exit(0)
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", worker, f"orphan-{index}"],
            cwd=ROOT,
            env={**os.environ, "WARDEN_PROTECTION_DB": str(database)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(8)
    ]

    acquired: list[bool] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stdout + stderr
        acquired.append(json.loads(stdout))

    assert acquired.count(True) == protection.MAX_CONCURRENT_PROBES
    assert acquired.count(False) == len(processes) - protection.MAX_CONCURRENT_PROBES
    assert (
        protection_store.acquire_probe_lease(
            "blocked",
            now=105.0,
            ttl_seconds=protection.PROBE_LEASE_TTL_SECONDS,
            max_leases=protection.MAX_CONCURRENT_PROBES,
        )
        is False
    )
    assert (
        protection_store.acquire_probe_lease(
            "replacement",
            now=111.0,
            ttl_seconds=protection.PROBE_LEASE_TTL_SECONDS,
            max_leases=protection.MAX_CONCURRENT_PROBES,
        )
        is True
    )

    with sqlite3.connect(database) as connection:
        columns = [
            row[1] for row in connection.execute("PRAGMA table_info(probe_leases)").fetchall()
        ]
        rows = connection.execute("SELECT lease_id, expires_at FROM probe_leases").fetchall()
    assert columns == ["lease_id", "expires_at"]
    assert rows == [("replacement", 121.0)]


@pytest.mark.asyncio
async def test_cancelled_probe_releases_its_shared_lease(_shared_protection_database):
    database = _shared_protection_database
    entered = asyncio.Event()

    async def hold_probe() -> None:
        async with protection._probe_admission():
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(hold_probe())
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with sqlite3.connect(database) as connection:
        active = connection.execute("SELECT COUNT(*) FROM probe_leases").fetchone()[0]
    assert active == 0


@pytest.mark.asyncio
async def test_configured_probe_admission_fails_closed_before_network(
    tmp_path,
    monkeypatch,
):
    invalid_database = tmp_path / "not-a-database"
    invalid_database.mkdir()
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(invalid_database))

    async def unexpected_validation(endpoint: str):
        raise AssertionError(
            f"must not validate or fetch while admission is unavailable: {endpoint}"
        )

    monkeypatch.setattr(protection, "validate_public_http_url", unexpected_validation)

    with pytest.raises(
        protection.ProtectionProbeUnavailable,
        match="shared protection probe admission is unavailable",
    ):
        await protection._fetch_proof("https://asp.example.org")


@pytest.mark.asyncio
async def test_unconfigured_local_development_uses_the_process_backstop(monkeypatch):
    monkeypatch.delenv("WARDEN_PROTECTION_DB", raising=False)

    def unexpected_acquire(*args, **kwargs):
        raise AssertionError(f"local mode must not acquire a shared lease: {args} {kwargs}")

    monkeypatch.setattr(protection_store, "acquire_probe_lease", unexpected_acquire)

    async with protection._probe_admission():
        pass


def test_probe_admission_database_wait_is_bounded(_shared_protection_database):
    database = _shared_protection_database
    with protection_store._connect():
        pass
    blocker = sqlite3.connect(database)
    blocker.execute("BEGIN IMMEDIATE")
    started = time.perf_counter()
    try:
        with pytest.raises(protection_store.ProbeAdmissionStorageUnavailable):
            protection_store.acquire_probe_lease(
                "contended",
                now=100.0,
                ttl_seconds=protection.PROBE_LEASE_TTL_SECONDS,
                max_leases=protection.MAX_CONCURRENT_PROBES,
            )
    finally:
        blocker.rollback()
        blocker.close()

    assert time.perf_counter() - started < 2
