"""Rate limiting middleware behavior tests."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app


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
    assert len(ratelimit._STATE) == 1
    assert ratelimit._STATE["198.51.100.11"] == (1, 1)


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
