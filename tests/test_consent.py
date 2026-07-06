"""Consent gate tests for the audit endpoint."""

from urllib.parse import urlparse

from fastapi.testclient import TestClient

from warden.api import app


class _ConsentResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": "text/plain"}

    def json(self):
        raise ValueError("invalid json")


class _FakeAsyncClient:
    def __init__(self, response: _ConsentResponse):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, *args, **kwargs):
        return self.response


def _stubbed_audit_requests(monkeypatch, response: _ConsentResponse):
    async def _validate_public_http_url(self, target_url: str):
        return (
            "http://127.0.0.1:8000",
            "api.example.org",
            urlparse(target_url),
        )

    async def _target_blocks_payload(self, *args, **kwargs):
        return False

    monkeypatch.setattr(
        "warden.auditor.AgentAuditor._validate_public_http_url",
        _validate_public_http_url,
    )
    monkeypatch.setattr(
        "warden.auditor.AgentAuditor._load_representative_attacks",
        lambda self: [{"id": "t1", "category": "TEST", "payload": "payload"}],
    )
    monkeypatch.setattr(
        "warden.auditor.AgentAuditor._target_blocks_payload",
        _target_blocks_payload,
    )
    monkeypatch.setattr(
        "warden.auditor.httpx.AsyncClient",
        lambda *args, **kwargs: _FakeAsyncClient(response),
    )
    monkeypatch.setattr("warden.auditor.record_badge", lambda badge: None)


def test_audit_requires_no_hard_block_when_consent_missing_and_soft(monkeypatch):
    _stubbed_audit_requests(monkeypatch, _ConsentResponse(status_code=404, text="missing"))
    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "false")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    with TestClient(app) as client:
        response = client.post("/audit", json={"target_url": "https://example.org/scan"})
    assert response.status_code == 200
    assert response.json()["consent_verified"] is False


def test_audit_requires_consent_when_enabled(monkeypatch):
    _stubbed_audit_requests(monkeypatch, _ConsentResponse(status_code=404, text="missing"))
    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "true")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    with TestClient(app) as client:
        response = client.post("/audit", json={"target_url": "https://example.org/scan"})
    assert response.status_code == 400
    assert response.json()["detail"] == "target_url did not pass consent check"


def test_audit_passes_with_consent_file(monkeypatch):
    _stubbed_audit_requests(
        monkeypatch,
        _ConsentResponse(status_code=200, text="warden-audit-allowed"),
    )
    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "true")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    with TestClient(app) as client:
        response = client.post("/audit", json={"target_url": "https://example.org/scan"})
    assert response.status_code == 200
    assert response.json()["consent_verified"] is True
