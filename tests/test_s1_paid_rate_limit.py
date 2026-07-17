"""Regression coverage for payment-header rate limiting."""

from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app


def test_unverified_payment_header_uses_ordinary_bucket(monkeypatch):
    # Until an x402 settlement is verified, a payment header does not unlock the
    # elevated bucket: it is capped at the ordinary per-client limit so a forged
    # header cannot inflate facilitator-verification work.
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("WARDEN_PAYMENT_RATE_LIMIT_PER_MIN", "600")
    ratelimit._reset_state()

    with TestClient(app) as client:
        headers = {"payment-signature": "forged"}
        first = client.post("/scan", json={"payload": "normal note"}, headers=headers)
        exceeded = client.post("/scan", json={"payload": "normal note"}, headers=headers)

    assert first.status_code == 200
    assert exceeded.status_code == 429
    assert exceeded.json() == {"detail": "Rate limit exceeded"}
    assert exceeded.headers.get("Retry-After") is not None
