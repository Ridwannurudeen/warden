"""Rate limiting middleware behavior tests."""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app


@pytest.fixture(autouse=True)
def _isolated_rate_limit_database(tmp_path, monkeypatch):
    database = tmp_path / "rate-limit.db"
    monkeypatch.setenv("WARDEN_RATE_LIMIT_DB", str(database))
    ratelimit._reset_state()
    yield database
    monkeypatch.setenv("WARDEN_RATE_LIMIT_DB", str(database))
    ratelimit._reset_state()


def _request_with_client_ip(ip: str):
    return SimpleNamespace(
        headers={"x-real-ip": ip},
        client=SimpleNamespace(host="proxy.example"),
    )


def test_check_rate_limit_enforced_per_ip():
    ratelimit._reset_state()

    request = _request_with_client_ip("203.0.113.21")
    assert ratelimit.check_rate_limit(request, 3) is False
    assert ratelimit.check_rate_limit(request, 3) is False
    assert ratelimit.check_rate_limit(request, 3) is False
    assert ratelimit.check_rate_limit(request, 3) is True


def test_check_rate_limit_window_resets_on_boundary(monkeypatch):
    ratelimit._reset_state()
    timestamps = iter([10, 11, 12, 75])
    monkeypatch.setattr(ratelimit, "_time_now", lambda: next(timestamps))

    request = _request_with_client_ip("198.51.100.7")
    assert ratelimit.check_rate_limit(request, 2) is False
    assert ratelimit.check_rate_limit(request, 2) is False
    assert ratelimit.check_rate_limit(request, 2) is True
    assert ratelimit.check_rate_limit(request, 2) is False


def test_xff_spoof_does_not_create_new_buckets():
    ratelimit._reset_state()

    for index in range(2):
        request = SimpleNamespace(
            headers={
                "x-real-ip": "203.0.113.9",
                "x-forwarded-for": f"198.51.100.{index}",
            },
            client=SimpleNamespace(host="proxy.example"),
        )
        assert ratelimit.check_rate_limit(request, 2) is False

    request = SimpleNamespace(
        headers={
            "x-real-ip": "203.0.113.9",
            "x-forwarded-for": "198.51.100.200",
        },
        client=SimpleNamespace(host="proxy.example"),
    )
    assert ratelimit.check_rate_limit(request, 2) is True


def test_state_evicts_stale_windows(monkeypatch):
    ratelimit._reset_state()
    timestamps = iter([10, 75])
    monkeypatch.setattr(ratelimit, "_time_now", lambda: next(timestamps))

    old_request = SimpleNamespace(
        headers={"x-real-ip": "198.51.100.10"},
        client=SimpleNamespace(host="198.51.100.10"),
    )
    current_request = SimpleNamespace(
        headers={"x-real-ip": "198.51.100.11"},
        client=SimpleNamespace(host="198.51.100.11"),
    )

    assert ratelimit.check_rate_limit(old_request, 10) is False
    assert ratelimit.check_rate_limit(current_request, 10) is False
    with sqlite3.connect(os.environ["WARDEN_RATE_LIMIT_DB"]) as connection:
        rows = connection.execute(
            "SELECT scope, client, window_id, count FROM rate_windows"
        ).fetchall()
    assert rows == [
        ("paid", "198.51.100.10", 0, 1),
        ("paid", "198.51.100.11", 1, 1),
    ]


def test_retry_after_seconds_bounds():
    assert 1 <= ratelimit.retry_after_seconds() <= 60


def test_http_scan_route_honors_rate_limit(monkeypatch):
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()
    with TestClient(app) as client:
        assert client.post("/scan", json={"payload": "normal settlement note"}).status_code == 200
        assert client.post("/scan", json={"payload": "normal settlement note"}).status_code == 200
        exceeded = client.post("/scan", json={"payload": "normal settlement note"})
    assert exceeded.status_code == 429
    assert exceeded.json()["detail"] == "Rate limit exceeded"
    assert exceeded.headers.get("Retry-After") is not None


def test_http_scan_route_skips_when_disabled(monkeypatch):
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    ratelimit._reset_state()
    with TestClient(app) as client:
        responses = [
            client.post("/scan", json={"payload": "normal settlement note"}) for _ in range(5)
        ]
    assert all(response.status_code == 200 for response in responses)


def test_default_local_store_keeps_an_unconfigured_testclient_operational(monkeypatch):
    monkeypatch.delenv("WARDEN_RATE_LIMIT_DB", raising=False)
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()

    with TestClient(app) as client:
        first = client.post("/scan", json={"payload": "normal settlement note"})
        second = client.post("/scan", json={"payload": "normal settlement note"})
        exceeded = client.post("/scan", json={"payload": "normal settlement note"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert exceeded.status_code == 429
    assert ratelimit._db_path() == ratelimit._LOCAL_DATABASE_PATH


def test_forged_payment_header_gets_ordinary_bucket(monkeypatch):
    # A forged/unverified payment header must NOT unlock the elevated bucket before
    # x402 settlement is verified. It falls through to the ordinary per-client limit.
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "1")
    ratelimit._reset_state()
    client = TestClient(app)

    headers = {"payment-signature": "forged"}
    assert client.post("/scan", json={"payload": "x"}, headers=headers).status_code == 200
    assert client.post("/scan", json={"payload": "x"}, headers=headers).status_code == 429


def test_verified_payer_gets_elevated_bucket(monkeypatch):
    # Once a client has completed a verified settlement, its replays use the
    # elevated payment bucket even past the ordinary limit.
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("WARDEN_PAYMENT_RATE_LIMIT_PER_MIN", "600")
    ratelimit._reset_state()
    ratelimit.mark_verified_payer(
        SimpleNamespace(headers={}, client=SimpleNamespace(host="testclient"))
    )

    client = TestClient(app)
    headers = {"payment-signature": "verified"}
    for _ in range(3):
        assert client.post("/scan", json={"payload": "x"}, headers=headers).status_code != 429


def test_rate_limit_is_atomic_across_processes(
    _isolated_rate_limit_database,
):
    database = _isolated_rate_limit_database
    worker = """
import json
from types import SimpleNamespace
from warden import ratelimit

ratelimit._time_now = lambda: 100.0
request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.40"))
results = [ratelimit.check_rate_limit(request, 50) for _ in range(25)]
print(json.dumps(results))
"""
    environment = {**os.environ, "WARDEN_RATE_LIMIT_DB": str(database)}
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", worker],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]

    results: list[bool] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stdout + stderr
        results.extend(json.loads(stdout))

    assert results.count(False) == 50
    assert results.count(True) == 50


def test_verified_payer_grant_is_visible_across_processes(
    _isolated_rate_limit_database,
):
    database = _isolated_rate_limit_database
    worker = """
from types import SimpleNamespace
from warden import ratelimit

request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.41"))
ratelimit.mark_verified_payer(request)
"""
    completed = subprocess.run(
        [sys.executable, "-c", worker],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "WARDEN_RATE_LIMIT_DB": str(database)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.41"))
    assert ratelimit.is_verified_payer(request) is True


def test_rate_limit_storage_failure_is_fail_closed(tmp_path, monkeypatch):
    invalid_database = tmp_path / "not-a-database"
    invalid_database.mkdir()
    monkeypatch.setenv("WARDEN_RATE_LIMIT_DB", str(invalid_database))
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.42"))

    assert ratelimit.check_rate_limit(request, 60) is True
    ratelimit.mark_verified_payer(request)
    assert ratelimit.is_verified_payer(request) is False


def test_http_route_returns_429_when_shared_rate_limit_store_is_unavailable(
    tmp_path,
    monkeypatch,
):
    invalid_database = tmp_path / "not-a-database"
    invalid_database.mkdir()
    monkeypatch.setenv("WARDEN_RATE_LIMIT_DB", str(invalid_database))
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "60")

    with TestClient(app) as client:
        response = client.post("/scan", json={"payload": "normal settlement note"})

    assert response.status_code == 429
    assert response.json() == {"detail": "Rate limit exceeded"}
    assert response.headers["Retry-After"]


def test_rate_limit_cleanup_bounds_expired_shared_state(monkeypatch):
    timestamps = iter([10, 10, 700, 700])
    monkeypatch.setattr(ratelimit, "_time_now", lambda: next(timestamps))
    old_request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.43"))
    current_request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.44"))

    assert ratelimit.check_rate_limit(old_request, 60) is False
    ratelimit.mark_verified_payer(old_request)
    assert ratelimit.check_rate_limit(current_request, 60) is False
    assert ratelimit.is_verified_payer(current_request) is False

    with sqlite3.connect(os.environ["WARDEN_RATE_LIMIT_DB"]) as connection:
        rate_rows = connection.execute(
            "SELECT client, window_id FROM rate_windows ORDER BY client"
        ).fetchall()
        payer_rows = connection.execute(
            "SELECT client FROM verified_payers ORDER BY client"
        ).fetchall()
    assert rate_rows == [("203.0.113.44", 11)]
    assert payer_rows == []
