"""Badge issuance, verification, and lookup tests."""

from fastapi.testclient import TestClient

from warden.api import app
from warden.badge_store import get_badge, record_badge
from warden.badges import issue_badge, verify_badge


def test_issue_badge_verify_round_trip():
    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )

    assert verify_badge(badge)


def test_tampered_badge_fails_verification():
    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    badge["score"] = 12.5

    assert not verify_badge(badge)


def test_audit_id_deterministic_for_same_inputs():
    first = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    second = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )

    assert first["audit_id"] == second["audit_id"]


def test_badge_store_round_trip(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    record_badge(badge)

    assert get_badge(badge["audit_id"]) == badge


def test_badge_lookup_route_returns_verified(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    record_badge(badge)

    with TestClient(app) as client:
        response = client.get(f"/badge/{badge['audit_id']}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["verified"] is True
    assert payload["badge"]["audit_id"] == badge["audit_id"]


def test_badge_lookup_unknown_id_returns_404():
    with TestClient(app) as client:
        response = client.get("/badge/does-not-exist")

    assert response.status_code == 404
    assert response.json()["detail"] == "Badge not found"
