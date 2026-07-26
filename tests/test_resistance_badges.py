"""Resistance badges: qualification, determinism, tamper rejection, expiry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import resistance_badges, variant_audit
from warden.api import app
from warden.auditor import AuditOutcome
from warden.badges import b64u_encode
from warden.resistance_badges import (
    BADGE_FIELDS,
    BADGE_TTL_SECONDS,
    effective_status,
    issue_badge,
    render_badge_svg,
    verify_badge,
)
from warden.variant_audit import run_variant_audit

from tests.test_variant_audit import _StubTarget, _install_target

client = TestClient(app)

_TARGET_URL = "https://target.example/scan"


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "reports.jsonl"
    monkeypatch.setenv("WARDEN_VARIANT_AUDIT_STORE", str(store))
    return store


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)
    monkeypatch.delenv("WARDEN_REQUIRE_CONSENT", raising=False)
    monkeypatch.delenv("WARDEN_ENVIRONMENT", raising=False)


async def _report(monkeypatch: pytest.MonkeyPatch, outcome) -> dict[str, object]:
    _install_target(monkeypatch, _StubTarget(outcome=outcome))
    return await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
    )


async def test_a_graded_report_earns_a_verifiable_badge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)

    badge = issue_badge(report)

    assert set(badge) == BADGE_FIELDS
    assert verify_badge(badge) is True
    assert badge["grade"] == "A"
    assert badge["detection_rate"] == 100.0
    assert badge["report_id"] == report["report_id"]
    assert badge["target_host"] == "target.example"
    assert badge["expires_at"] == int(report["issued_at"]) + BADGE_TTL_SECONDS


async def test_the_badge_is_a_deterministic_function_of_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No badge store can drift, because re-deriving gives the same bytes."""
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)

    assert issue_badge(report) == issue_badge(report)


async def test_an_ungraded_run_earns_no_badge(monkeypatch: pytest.MonkeyPatch) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.INCONCLUSIVE)

    assert report["totals"]["grade"] == "INCONCLUSIVE"
    assert resistance_badges.qualifies(report) is False
    with pytest.raises(ValueError, match="conclusive, consented, graded"):
        issue_badge(report)


async def test_a_failing_grade_still_earns_its_honest_badge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F is a measurement, not a disqualification; hiding it would be the lie."""
    report = await _report(monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED)

    badge = issue_badge(report)

    assert badge["grade"] == "F"
    assert badge["detection_rate"] == 0.0
    assert verify_badge(badge) is True


async def test_a_report_that_does_not_verify_earns_no_badge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED)
    flattered = json.loads(json.dumps(report))
    flattered["totals"]["grade"] = "A"

    assert resistance_badges.qualifies(flattered) is False
    with pytest.raises(ValueError):
        issue_badge(flattered)


@pytest.mark.parametrize("field", sorted(BADGE_FIELDS))
async def test_mutating_any_badge_field_breaks_verification(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    badge = issue_badge(report)

    mutations: dict[str, object] = {
        "spec_version": "warden-resistance-badge/999",
        "report_id": "0" * 64,
        "target_host": "attacker.example",
        "grade": "F",
        "detection_rate": 12.5,
        "detected": 999,
        "conclusive": 999,
        "variants_sent": 999,
        "threat_classes": 999,
        "corpus_fingerprint": f"sha256:{'0' * 64}",
        "generator": "warden-adversarial-variants/999",
        "observed_at": int(badge["observed_at"]) + 1,
        "expires_at": int(badge["expires_at"]) + 1,
        "issuer": "not-warden",
        "limitations": "no limits apply",
        "issuer_sig": "sig:AAAA",
    }
    tampered = {**json.loads(json.dumps(badge)), field: mutations[field]}

    assert tampered[field] != badge[field]
    assert verify_badge(tampered) is False


async def test_a_badge_goes_stale_rather_than_silently_expiring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    badge = issue_badge(report)
    expires_at = int(badge["expires_at"])

    assert effective_status(badge, now=expires_at) == "active"
    assert effective_status(badge, now=expires_at + 1) == "stale"
    # A stale badge still verifies; staleness is about age, not integrity.
    assert verify_badge(badge) is True


async def test_the_svg_renders_the_true_state(monkeypatch: pytest.MonkeyPatch) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    badge = issue_badge(report)

    active = render_badge_svg(badge, now=int(badge["observed_at"]))
    stale = render_badge_svg(badge, now=int(badge["expires_at"]) + 1)

    assert active.startswith("<svg") and active.endswith("</svg>")
    assert "A · 100.0%" in active
    assert "stale" in stale
    assert "100.0%" not in stale
    # The caveat travels with the image.
    assert "not certification" in active


async def test_a_tampered_badge_renders_as_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED)
    badge = issue_badge(report)
    flattered = {**json.loads(json.dumps(badge)), "grade": "A"}

    svg = render_badge_svg(flattered)

    assert "invalid" in svg
    assert "A ·" not in svg


async def test_badge_routes_serve_json_and_svg(monkeypatch: pytest.MonkeyPatch) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    report_id = str(report["report_id"])

    json_response = client.get(f"/variant-audit/{report_id}/badge")
    svg_response = client.get(f"/variant-audit/{report_id}/badge.svg")

    assert json_response.status_code == 200
    assert json_response.json()["verified"] is True
    assert json_response.json()["status"] == "active"
    assert json_response.json()["badge"]["grade"] == "A"
    assert svg_response.status_code == 200
    assert svg_response.headers["content-type"].startswith("image/svg+xml")
    assert svg_response.headers["cache-control"] == "no-store"
    assert svg_response.text.startswith("<svg")


async def test_badge_routes_refuse_an_ungraded_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch, lambda payload: AuditOutcome.INCONCLUSIVE)

    response = client.get(f"/variant-audit/{report['report_id']}/badge")

    assert response.status_code == 409
    assert "graded" in response.json()["detail"]


def test_badge_routes_404_on_an_unknown_report() -> None:
    for suffix in ("badge", "badge.svg"):
        response = client.get(f"/variant-audit/{'0' * 64}/{suffix}")
        assert response.status_code == 404


async def test_a_badge_never_outlives_its_issuer_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key retired before the run means the badge does not verify."""
    report = await _report(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    badge = issue_badge(report)
    live = variant_audit.protection.issuer_keys()
    monkeypatch.setattr(
        resistance_badges.protection,
        "issuer_keys",
        lambda: [{**key, "not_after": int(badge["observed_at"]) - 1} for key in live],
    )

    assert verify_badge(badge) is False
