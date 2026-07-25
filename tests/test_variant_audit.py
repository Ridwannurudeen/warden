"""Adversarial variant audit: consent, bounds, held-out separation, determinism."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import adversarial_variants, variant_audit
from warden.adversarial_variants import HELD_OUT_ATTACKS_PATH, scanner_equivalence
from warden.auditor import AgentAuditor, AuditOutcome
from warden.badges import b64u_encode
from warden.dataset_promotion import canonical_dataset_payload
from warden.variant_audit import (
    CONTENT_FIELDS,
    MAX_TOTAL_VARIANTS,
    MAX_VARIANTS_PER_CLASS,
    run_variant_audit,
    verify_report,
)

_CONSENT_PATH = "/.well-known/warden-consent"
_TARGET_URL = "https://target.example/scan"
_FORBIDDEN_KEYS = frozenset(
    {"payload", "payload_sha256", "source_case_id", "response_body", "body", "variants"}
)


@pytest.fixture(autouse=True)
def _variant_audit_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)
    monkeypatch.delenv("WARDEN_REQUIRE_CONSENT", raising=False)
    monkeypatch.delenv("WARDEN_ENVIRONMENT", raising=False)


class _Response:
    def __init__(self, status_code: int, body: str, *, content_type: str) -> None:
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self._body = body.encode("utf-8")

    async def aiter_raw(self, chunk_size: int | None = None):
        yield self._body


class _Stream:
    def __init__(self, response: _Response) -> None:
        self._response = response

    async def __aenter__(self) -> _Response:
        return self._response

    async def __aexit__(self, *args: object) -> bool:
        return False


class _StubTarget:
    """A stubbed httpx client standing in for a consented endpoint.

    Every payload it receives is recorded, so a test can assert both what
    reached the target and how many requests it took.
    """

    def __init__(
        self,
        *,
        consent: bool = True,
        outcome: Callable[[str], AuditOutcome] = lambda payload: AuditOutcome.BLOCKED,
    ) -> None:
        self._consent = consent
        self._outcome = outcome
        self.sent: list[str] = []

    async def __aenter__(self) -> _StubTarget:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    def stream(
        self,
        method: str,
        url: str,
        *,
        json: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        extensions: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> _Stream:
        if url.endswith(_CONSENT_PATH):
            if not self._consent:
                return _Stream(_Response(404, "missing", content_type="text/plain"))
            return _Stream(_Response(200, "warden-audit-allowed", content_type="text/plain"))
        payload = str((json or {})["payload"])
        self.sent.append(payload)
        outcome = self._outcome(payload)
        if outcome is AuditOutcome.BLOCKED:
            return _Stream(_Response(200, '{"verdict":"block"}', content_type="application/json"))
        if outcome is AuditOutcome.NOT_BLOCKED:
            return _Stream(_Response(200, '{"verdict":"allow"}', content_type="application/json"))
        return _Stream(_Response(503, '{"error":"unavailable"}', content_type="application/json"))


def _install_client(monkeypatch: pytest.MonkeyPatch, target: _StubTarget) -> _StubTarget:
    """Route audit requests to the stub. No test opens a real socket."""
    monkeypatch.setattr(
        "warden.variant_audit.httpx.AsyncClient",
        lambda *args, **kwargs: target,
    )
    return target


def _install_target(monkeypatch: pytest.MonkeyPatch, target: _StubTarget) -> _StubTarget:
    async def _validate_public_http_url(self: AgentAuditor, target_url: str):
        return "https://203.0.113.7:443/scan", "target.example", urlparse(target_url)

    monkeypatch.setattr(
        AgentAuditor,
        "_validate_public_http_url",
        _validate_public_http_url,
    )
    return _install_client(monkeypatch, target)


def _content(report: dict[str, object]) -> dict[str, object]:
    return {field: report[field] for field in CONTENT_FIELDS}


def _held_out_rows() -> list[dict[str, object]]:
    rows = [
        json.loads(line)
        for line in Path(HELD_OUT_ATTACKS_PATH).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows
    return rows


async def test_variant_audit_refuses_a_target_without_consent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget(consent=False))

    with pytest.raises(ValueError, match="did not pass consent check"):
        await run_variant_audit(_TARGET_URL)

    assert target.sent == []


async def test_variant_audit_refuses_unconsented_target_in_development_soft_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The 20-probe audit tolerates soft mode; firing hundreds of variants does not.
    monkeypatch.setenv("WARDEN_ENVIRONMENT", "development")
    monkeypatch.setenv("WARDEN_REQUIRE_CONSENT", "false")
    target = _install_target(monkeypatch, _StubTarget(consent=False))

    with pytest.raises(ValueError, match="did not pass consent check"):
        await run_variant_audit(_TARGET_URL)

    assert target.sent == []


@pytest.mark.parametrize(
    "target_url",
    [
        "http://127.0.0.1:8000/scan",
        "http://[::1]:8000/scan",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "https://user:pass@target.example/scan",
    ],
)
async def test_variant_audit_rejects_internal_and_malformed_targets(
    monkeypatch: pytest.MonkeyPatch,
    target_url: str,
) -> None:
    # The real SSRF validation runs here: only the transport is stubbed.
    target = _install_client(monkeypatch, _StubTarget())

    with pytest.raises(ValueError):
        await run_variant_audit(target_url, max_variants_per_class=1)

    assert target.sent == []


async def test_variant_audit_never_sends_or_reports_a_held_out_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL)

    assert target.sent
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    sent_canonicals = {canonical_dataset_payload(payload) for payload in target.sent}
    sent_equivalence: set[str] = set()
    for payload in target.sent:
        sent_equivalence |= scanner_equivalence(payload)
    for row in _held_out_rows():
        held_payload = str(row["payload"])
        assert str(row["id"]) not in serialized
        assert held_payload not in serialized
        assert canonical_dataset_payload(held_payload) not in sent_canonicals
        assert not scanner_equivalence(held_payload) & sent_equivalence
        for payload in target.sent:
            assert held_payload not in payload


async def test_variant_audit_report_carries_no_payload_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL)

    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    for payload in target.sent:
        assert payload not in serialized

    def _walk(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                assert isinstance(key, str)
                assert key not in _FORBIDDEN_KEYS
                _walk(nested)
        elif isinstance(value, list):
            for item in value:
                _walk(item)
        else:
            assert value is None or isinstance(value, (bool, int, float, str))

    _walk(report)


async def test_variant_audit_enforces_the_per_class_and_total_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=3)

    assert len(target.sent) == int(report["totals"]["variants_sent"])
    assert all(int(entry["total"]) == 3 for entry in report["per_class"])
    assert report["caps"] == {
        "max_variants_per_class": 3,
        "max_total_variants": MAX_TOTAL_VARIANTS,
        "probe_timeout_seconds": variant_audit.AUDIT_TIMEOUT_SECONDS,
        "total_timeout_seconds": variant_audit.TOTAL_TIMEOUT_SECONDS,
        "max_response_bytes": variant_audit.MAX_AUDIT_RESPONSE_BYTES,
    }
    assert "3 variants per threat class" in report["limitations"][1]
    assert f"{MAX_TOTAL_VARIANTS} in total" in report["limitations"][1]


async def test_variant_audit_total_cap_bounds_a_full_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL)

    available = sum(
        min(len(pack["variants"]), MAX_VARIANTS_PER_CLASS)
        for pack in variant_audit._canonical_packs().values()
    )
    assert available > MAX_TOTAL_VARIANTS
    assert len(target.sent) == MAX_TOTAL_VARIANTS
    assert len(set(target.sent)) == MAX_TOTAL_VARIANTS
    assert int(report["totals"]["variants_sent"]) == MAX_TOTAL_VARIANTS
    # The cap trims every audited class instead of spending the whole budget on
    # the first ones.
    assert all(int(entry["total"]) > 0 for entry in report["per_class"])


@pytest.mark.parametrize("max_variants_per_class", [0, -1, MAX_VARIANTS_PER_CLASS + 1, True])
async def test_variant_audit_rejects_an_out_of_range_cap(
    monkeypatch: pytest.MonkeyPatch,
    max_variants_per_class: int,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    with pytest.raises(ValueError, match="max_variants_per_class"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=max_variants_per_class)

    assert target.sent == []


@pytest.mark.parametrize(
    ("threat_classes", "message"),
    [
        ((), "must not be empty"),
        (("NOT_A_CLASS",), "known Warden threat classes"),
        (("CORPUS_MATCH",), "have adversarial variants"),
    ],
)
async def test_variant_audit_rejects_unusable_threat_classes(
    monkeypatch: pytest.MonkeyPatch,
    threat_classes: tuple[str, ...],
    message: str,
) -> None:
    target = _install_target(monkeypatch, _StubTarget())

    with pytest.raises(ValueError, match=message):
        await run_variant_audit(_TARGET_URL, threat_classes=threat_classes)

    assert target.sent == []


async def test_variant_audit_per_class_arithmetic_is_correct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packs = variant_audit._canonical_packs()
    missed = {str(variant["payload"]) for variant in packs["SECRET_EXFIL"]["variants"][:2]}

    def _outcome(payload: str) -> AuditOutcome:
        return AuditOutcome.NOT_BLOCKED if payload in missed else AuditOutcome.BLOCKED

    _install_target(monkeypatch, _StubTarget(outcome=_outcome))

    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("MALICIOUS_LINK", "SECRET_EXFIL"),
        max_variants_per_class=4,
    )

    per_class = {str(entry["threat_class"]): entry for entry in report["per_class"]}
    # Classes are reported in Warden's canonical ReasonCode order, not request order.
    assert list(per_class) == ["SECRET_EXFIL", "MALICIOUS_LINK"]
    assert per_class["SECRET_EXFIL"] == {
        "threat_class": "SECRET_EXFIL",
        "total": 4,
        "detected": 2,
        "missed": 2,
        "inconclusive": 0,
        "conclusive": 4,
        "detection_rate": 50.0,
    }
    assert per_class["MALICIOUS_LINK"]["detection_rate"] == 100.0
    for entry in report["per_class"]:
        assert int(entry["total"]) == (
            int(entry["detected"]) + int(entry["missed"]) + int(entry["inconclusive"])
        )
        assert int(entry["conclusive"]) == int(entry["detected"]) + int(entry["missed"])
    assert report["totals"] == {
        "threat_classes": 2,
        "variants_sent": 8,
        "detected": 6,
        "missed": 2,
        "inconclusive": 0,
        "conclusive": 8,
        "detection_rate": 75.0,
    }


async def test_variant_audit_counts_inconclusive_probes_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packs = variant_audit._canonical_packs()
    silent = {str(variant["payload"]) for variant in packs["DRAIN_ADDRESS"]["variants"][:2]}

    def _outcome(payload: str) -> AuditOutcome:
        return AuditOutcome.INCONCLUSIVE if payload in silent else AuditOutcome.BLOCKED

    _install_target(monkeypatch, _StubTarget(outcome=_outcome))

    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=3,
    )

    assert report["per_class"] == [
        {
            "threat_class": "DRAIN_ADDRESS",
            "total": 3,
            "detected": 1,
            "missed": 0,
            "inconclusive": 2,
            "conclusive": 1,
            "detection_rate": 100.0,
        }
    ]
    assert report["totals"]["inconclusive"] == 2
    assert report["totals"]["detected"] == 1


async def test_variant_audit_reports_no_detection_rate_without_a_conclusive_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_target(
        monkeypatch,
        _StubTarget(outcome=lambda payload: AuditOutcome.INCONCLUSIVE),
    )

    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
    )

    assert report["per_class"][0]["detection_rate"] is None
    assert report["per_class"][0]["inconclusive"] == 2
    assert report["totals"]["detection_rate"] is None


async def test_variant_audit_report_is_deterministic_and_signature_verifiable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _outcome(payload: str) -> AuditOutcome:
        return AuditOutcome.BLOCKED if payload.startswith("a") else AuditOutcome.NOT_BLOCKED

    _install_target(monkeypatch, _StubTarget(outcome=_outcome))
    first = await run_variant_audit(_TARGET_URL, max_variants_per_class=5)
    _install_target(monkeypatch, _StubTarget(outcome=_outcome))
    second = await run_variant_audit(_TARGET_URL, max_variants_per_class=5)

    assert _content(first) == _content(second)
    assert first["report_id"] == second["report_id"]
    assert verify_report(dict(first)) is True
    assert verify_report(dict(second)) is True
    assert first["schema_version"] == variant_audit.SCHEMA_VERSION
    assert first["target_host"] == "target.example"
    assert first["consent_verified"] is True
    assert first["generator"] == adversarial_variants.GENERATOR_ID
    assert (
        first["corpus_fingerprint"]
        == variant_audit._canonical_packs()["SECRET_EXFIL"]["corpus_fingerprint"]
    )
    assert json.loads(json.dumps(first)) == first


async def test_variant_audit_signature_does_not_cover_a_tampered_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=1)

    tampered = json.loads(json.dumps(report))
    tampered["totals"]["detected"] = int(tampered["totals"]["detected"]) + 1
    assert verify_report(tampered) is False
