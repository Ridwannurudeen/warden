"""Regression coverage for the dedicated badge signing secret."""

import pytest

from warden.badges import issue_badge, verify_badge


def _issue(*, secret: str | None = None) -> dict[str, object]:
    return issue_badge(
        target_host="api.example.org",
        score=100,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-16",
        secret=secret,
    )


def test_badge_issuance_requires_dedicated_secret_even_with_okx_key(monkeypatch):
    monkeypatch.delenv("WARDEN_BADGE_SECRET", raising=False)
    monkeypatch.setenv("OKX_API_KEY", "unrelated-api-key")

    with pytest.raises(RuntimeError, match="WARDEN_BADGE_SECRET"):
        _issue()


def test_explicit_badge_secret_is_testable_and_has_no_default(monkeypatch):
    monkeypatch.delenv("WARDEN_BADGE_SECRET", raising=False)

    badge = _issue(secret="explicit-test-secret")

    assert verify_badge(badge, secret="explicit-test-secret") is True
    assert verify_badge(badge, secret="different-test-secret") is False
    with pytest.raises(RuntimeError, match="WARDEN_BADGE_SECRET"):
        verify_badge(badge)
