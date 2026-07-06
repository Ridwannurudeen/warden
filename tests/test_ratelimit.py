"""Rate limiting middleware behavior tests."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app


def _request_with_client_ip(ip: str):
    return SimpleNamespace(
        headers={"x-forwarded-for": ip},
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


def test_retry_after_seconds_bounds():
    assert 1 <= ratelimit.retry_after_seconds() <= 60


def test_http_scan_route_honors_rate_limit(monkeypatch):
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()
    with TestClient(app) as client:
        assert (
            client.post("/scan", json={"payload": "normal settlement note"}).status_code == 200
        )
        assert (
            client.post("/scan", json={"payload": "normal settlement note"}).status_code == 200
        )
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
