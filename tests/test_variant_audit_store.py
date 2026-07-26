"""Retention and retrieval of signed adversarial variant audit reports."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import variant_audit, variant_audit_store
from warden.api import app
from warden.auditor import AgentAuditor, AuditOutcome
from warden.badges import b64u_encode
from warden.variant_audit import run_variant_audit, verify_report
from warden.variant_audit_store import get_report, record_report

from tests.test_variant_audit import _StubTarget, _install_target

client = TestClient(app)

_TARGET_URL = "https://target.example/scan"


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the store at a temporary file so no test writes to the real one."""
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


async def _report(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> dict[str, object]:
    _install_target(monkeypatch, _StubTarget(**kwargs))
    return await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
    )


async def test_a_completed_audit_is_retained_and_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch)

    stored = get_report(str(report["report_id"]))

    assert stored == report
    assert verify_report(dict(stored)) is True


async def test_recording_the_same_report_twice_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    report = await _report(monkeypatch)

    record_report(report)
    record_report(report)

    lines = [line for line in _isolated_store.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 1


async def test_a_report_that_edits_its_host_never_reaches_the_id_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """target_host is signed, so re-pointing a report is a signature failure."""
    report = await _report(monkeypatch)
    forged = {**report, "target_host": "someone-else.example"}

    with pytest.raises(ValueError, match="failed signature verification"):
        record_report(forged)


async def test_a_planted_record_under_a_real_id_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    """Defence in depth against an edited store file, not against the API.

    Nothing reaching `record_report` can collide, because report_id is the hash
    of the signed content. A line written into the store by hand can.
    """
    _install_target(monkeypatch, _StubTarget())
    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
    )
    planted = {**report, "target_host": "someone-else.example"}
    _isolated_store.write_text(
        json.dumps(planted, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="conflicts with an existing record"):
        record_report(report)


async def test_an_unsigned_report_is_never_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch)
    assert report["totals"]["grade"] == "A"
    tampered = json.loads(json.dumps(report))
    tampered["totals"]["grade"] = "F"

    with pytest.raises(ValueError, match="failed signature verification"):
        record_report(tampered)

    assert get_report(str(tampered["report_id"])) == report


@pytest.mark.parametrize(
    "report_id",
    ["", "not-hex", "A" * 64, "0" * 63, "0" * 65],
)
def test_a_malformed_report_id_is_not_looked_up(report_id: str) -> None:
    assert get_report(report_id) is None


def test_an_unknown_report_id_reads_as_missing() -> None:
    assert get_report("0" * 64) is None


async def test_retrieval_route_returns_a_verified_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _report(monkeypatch)

    response = client.get(f"/variant-audit/{report['report_id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["report"] == report


def test_retrieval_route_404s_on_an_unknown_report() -> None:
    response = client.get(f"/variant-audit/{'0' * 64}")

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].casefold()


async def test_a_storage_failure_does_not_void_the_paid_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The buyer holds a verifiable report even when the store cannot write."""

    def _explode(report: dict[str, object]) -> None:
        raise OSError("disk is read-only")

    monkeypatch.setattr(variant_audit_store, "record_report", _explode)
    monkeypatch.setattr(variant_audit.variant_audit_store, "record_report", _explode)

    report = await _report(monkeypatch)

    assert verify_report(dict(report)) is True
    assert get_report(str(report["report_id"])) is None


async def test_an_inconclusive_run_is_still_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retention is not a grade: an ungraded run is evidence a buyer may re-fetch."""
    report = await _report(
        monkeypatch,
        outcome=lambda payload: AuditOutcome.INCONCLUSIVE,
    )

    assert report["totals"]["grade"] == "INCONCLUSIVE"
    assert get_report(str(report["report_id"])) == report


async def test_a_re_audit_is_a_new_report_not_a_collision(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    """Each run carries its own server nonce, so re-auditing refreshes evidence.

    When report_id was a pure hash of the findings, an unchanged re-audit
    produced the same id, the store kept the first record, and the badge stayed
    pinned to the original timestamp — so a customer who re-audited and re-paid
    could never refresh a badge that had gone stale.
    """
    first = await _report(monkeypatch)
    monkeypatch.setattr(variant_audit.time, "time", lambda: float(first["issued_at"]) + 60)

    second = await _report(monkeypatch)

    assert second["report_id"] != first["report_id"]
    assert second["nonce"] != first["nonce"]
    assert second["issued_at"] > first["issued_at"]
    assert second["totals"] == first["totals"]
    # Both remain independently retrievable and verifiable.
    lines = [line for line in _isolated_store.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2
    assert get_report(str(first["report_id"])) == first
    assert get_report(str(second["report_id"])) == second


async def test_a_report_id_cannot_be_derived_from_public_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The id is a retrieval capability, so it must not be recomputable.

    Everything else in the signed content is predictable from the hostname: the
    schema, generator, corpus fingerprint, caps and limitations are public
    constants, and a fully-blocked run has exactly one possible set of counts.
    Only the nonce stops a stranger recomputing the id of an audit they never
    bought, reading the report, and minting a Warden-signed grade for a host
    they do not own.
    """
    report = await _report(monkeypatch)
    content_without_nonce = {
        field: report[field] for field in variant_audit.CONTENT_FIELDS if field != "nonce"
    }

    with pytest.raises(ValueError, match="content fields are invalid"):
        variant_audit.report_id_for_content(content_without_nonce)

    # Substituting any other nonce yields a different id.
    forged = variant_audit.report_id_for_content({**content_without_nonce, "nonce": "0" * 32})
    assert forged != report["report_id"]


async def test_a_refreshed_audit_produces_an_active_badge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A customer whose badge went stale can re-audit and get a live one."""
    from warden import resistance_badges

    stale_run = await _report(monkeypatch)
    stale_badge = resistance_badges.issue_badge(stale_run)
    long_after = int(stale_badge["expires_at"]) + 1
    assert resistance_badges.effective_status(stale_badge, now=long_after) == "stale"

    monkeypatch.setattr(variant_audit.time, "time", lambda: float(long_after))
    fresh_run = await _report(monkeypatch)
    fresh_badge = resistance_badges.issue_badge(fresh_run)

    assert resistance_badges.effective_status(fresh_badge, now=long_after) == "active"
    assert fresh_badge["report_id"] != stale_badge["report_id"]


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    outcome,
    *,
    since: str | None = None,
) -> dict[str, object]:
    _install_target(monkeypatch, _StubTarget(outcome=outcome))
    return await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
        since=since,
    )


async def test_a_re_audit_signs_the_grade_movement(monkeypatch: pytest.MonkeyPatch) -> None:
    weak = await _run(monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED)
    assert weak["totals"]["grade"] == "F"
    assert weak["delta"] is None

    improved = await _run(
        monkeypatch, lambda payload: AuditOutcome.BLOCKED, since=str(weak["report_id"])
    )

    assert verify_report(dict(improved)) is True
    delta = improved["delta"]
    assert delta["since_report_id"] == weak["report_id"]
    assert delta["since_issued_at"] == weak["issued_at"]
    assert delta["same_corpus"] is True
    assert delta["grade_from"] == "F"
    assert delta["grade_to"] == "A"
    assert delta["detection_rate_change"] == 100.0
    assert delta["per_class"] == [
        {
            "threat_class": "DRAIN_ADDRESS",
            "detection_rate_change": 100.0,
            "grade_from": "F",
            "grade_to": "A",
        }
    ]


async def test_a_regression_is_reported_as_a_negative_movement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    strong = await _run(monkeypatch, lambda payload: AuditOutcome.BLOCKED)

    regressed = await _run(
        monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED, since=str(strong["report_id"])
    )

    assert regressed["delta"]["detection_rate_change"] == -100.0
    assert regressed["delta"]["grade_from"] == "A"
    assert regressed["delta"]["grade_to"] == "F"


async def test_a_delta_cannot_be_edited_after_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    weak = await _run(monkeypatch, lambda payload: AuditOutcome.NOT_BLOCKED)
    improved = await _run(
        monkeypatch, lambda payload: AuditOutcome.BLOCKED, since=str(weak["report_id"])
    )

    flattered = json.loads(json.dumps(improved))
    flattered["delta"]["grade_from"] = "D"

    assert verify_report(flattered) is False


async def test_an_unknown_since_is_refused_before_any_probe_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    with pytest.raises(ValueError, match="since must name a retained"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=1, since="0" * 64)

    assert target.sent == []


async def test_a_delta_across_hosts_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    first = await _run(monkeypatch, lambda payload: AuditOutcome.BLOCKED)

    async def _other_host(self: AgentAuditor, target_url: str):
        return "https://198.51.100.9:443/scan", "other.example", urlparse(target_url)

    monkeypatch.setattr(AgentAuditor, "_validate_public_http_url", _other_host)

    with pytest.raises(ValueError, match="same target host"):
        await run_variant_audit(
            "https://other.example/scan",
            threat_classes=("DRAIN_ADDRESS",),
            max_variants_per_class=2,
            since=str(first["report_id"]),
        )


async def test_a_delta_flags_a_corpus_that_moved_between_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A re-audit after the generator moved is a different test, and says so."""
    first = await _run(monkeypatch, lambda payload: AuditOutcome.BLOCKED)
    monkeypatch.setattr(
        variant_audit.adversarial_variants, "GENERATOR_ID", "warden-adversarial-variants/999"
    )

    second = await _run(
        monkeypatch, lambda payload: AuditOutcome.BLOCKED, since=str(first["report_id"])
    )

    assert second["delta"]["same_corpus"] is False
    assert any("same_corpus is false" in line for line in second["limitations"])


async def test_a_run_without_a_comparison_carries_no_delta_caveats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _run(monkeypatch, lambda payload: AuditOutcome.BLOCKED)

    assert report["delta"] is None
    assert not any("delta" in line for line in report["limitations"])


async def test_the_deep_tier_has_its_own_tighter_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deep run holds a worker for minutes, so it is metered apart from the rest."""
    from warden import ratelimit

    monkeypatch.setenv("WARDEN_DEEP_VARIANT_AUDIT_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    ratelimit._reset_state()
    _install_target(monkeypatch, _StubTarget())
    body = {
        "target_url": _TARGET_URL,
        "threat_classes": ["DRAIN_ADDRESS"],
        "max_variants_per_class": 1,
    }

    standard = [client.post("/variant-audit", json=body).status_code for _ in range(3)]
    first_deep = client.post("/variant-audit", json={**body, "depth": "deep"})
    second_deep = client.post("/variant-audit", json={**body, "depth": "deep"})

    assert standard == [200, 200, 200]
    assert first_deep.status_code == 200
    assert second_deep.status_code == 429
    assert second_deep.headers["Retry-After"].isdigit()
    ratelimit._reset_state()


async def test_a_poisoned_store_does_not_void_a_report_the_buyer_paid_for(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    """Retention is best effort; the audit is what was bought."""
    first = await _report(monkeypatch)
    _isolated_store.write_text(
        json.dumps({**first, "target_host": "someone-else.example"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = await _report(monkeypatch)

    assert verify_report(dict(report)) is True


async def test_a_corrupt_line_does_not_hide_a_later_genuine_record(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    """The lookup prefilters on the id, so unparseable lines must be skipped."""
    report = await _report(monkeypatch)
    report_id = str(report["report_id"])
    _isolated_store.write_text(
        f'{{"report_id": "{report_id}", "truncated"\n'
        + json.dumps(report, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    assert get_report(report_id) == report


async def test_the_lookup_returns_the_last_matching_record(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_store: Path,
) -> None:
    report = await _report(monkeypatch)
    report_id = str(report["report_id"])
    stale = {**report, "issued_at": int(report["issued_at"]) - 1}
    _isolated_store.write_text(
        json.dumps(stale, sort_keys=True) + "\n" + json.dumps(report, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert get_report(report_id) == report


async def test_free_evidence_routes_are_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unmetered, they are a lever for stalling every paid route."""
    from warden import ratelimit

    monkeypatch.setenv("WARDEN_EVIDENCE_RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "0")
    ratelimit._reset_state()
    report = await _report(monkeypatch)
    url = f"/variant-audit/{report['report_id']}"

    statuses = [client.get(url).status_code for _ in range(3)]

    assert statuses == [200, 200, 429]
    for suffix in ("/badge", "/badge.svg"):
        assert client.get(url + suffix).status_code == 429
    ratelimit._reset_state()
