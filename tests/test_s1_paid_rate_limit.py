"""Regression coverage for payment-header rate limiting."""

from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app


def test_payment_header_requests_use_a_bounded_separate_bucket(monkeypatch):
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("WARDEN_PAYMENT_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()

    with TestClient(app) as client:
        headers = {"payment-signature": "forged"}
        first = client.post("/scan", json={"payload": "normal note"}, headers=headers)
        second = client.post("/scan", json={"payload": "normal note"}, headers=headers)
        exceeded = client.post("/scan", json={"payload": "normal note"}, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert exceeded.status_code == 429
    assert exceeded.json() == {"detail": "Rate limit exceeded"}
    assert exceeded.headers.get("Retry-After") is not None
