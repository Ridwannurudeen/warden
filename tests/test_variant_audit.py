"""Adversarial variant audit: consent, bounds, held-out separation, determinism."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import adversarial_variants, apa_url, protection, variant_audit
from warden.adversarial_variants import (
    HELD_OUT_ATTACKS_PATH,
    TRAINING_ATTACKS_PATH,
    load_dataset_rows,
    scanner_equivalence,
)
from warden.auditor import MAX_CONSENT_RESPONSE_BYTES, AgentAuditor, AuditOutcome
from warden.badges import b64u_encode, ed25519_sign_record
from warden.dataset_promotion import canonical_dataset_payload
from warden.variant_audit import (
    CONTENT_FIELDS,
    MAX_TOTAL_VARIANTS,
    MAX_VARIANTS_PER_CLASS,
    REPORT_FIELDS,
    report_id_for_content,
    run_variant_audit,
    verify_report,
)

_CONSENT_PATH = "/.well-known/warden-consent"
_CONSENT_MARKER = "warden-audit-allowed"
_TARGET_URL = "https://target.example/scan"
_FORBIDDEN_KEYS = frozenset(
    {"payload", "payload_sha256", "source_case_id", "response_body", "body", "variants"}
)
# Longer than any total timeout a test sets, so a probe that "hangs" is resolved by
# the audit's own timeout and never by the sleep completing.
_HANG_SECONDS = 30.0


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
    def __init__(
        self,
        status_code: int,
        body: str | bytes,
        *,
        content_type: str,
        content_encoding: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        if content_encoding is not None:
            self.headers["content-encoding"] = content_encoding
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")

    async def aiter_raw(self, chunk_size: int | None = None):
        yield self._body


class _Stream:
    def __init__(self, response: _Response, *, delay: float = 0.0) -> None:
        self._response = response
        self._delay = delay

    async def __aenter__(self) -> _Response:
        if self._delay:
            await asyncio.sleep(self._delay)
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
        consent_response: _Response | None = None,
        outcome: Callable[[str], AuditOutcome] = lambda payload: AuditOutcome.BLOCKED,
        probe_response: _Response | None = None,
        hang_after: int | None = None,
    ) -> None:
        self._consent = consent
        self._consent_response = consent_response
        self._outcome = outcome
        self._probe_response = probe_response
        self._hang_after = hang_after
        self.sent: list[str] = []
        self.urls: list[str] = []
        self.host_headers: list[str | None] = []
        self.client_kwargs: list[dict[str, object]] = []

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
        self.urls.append(url)
        self.host_headers.append((headers or {}).get("Host"))
        if url.endswith(_CONSENT_PATH):
            if self._consent_response is not None:
                return _Stream(self._consent_response)
            if not self._consent:
                return _Stream(_Response(404, "missing", content_type="text/plain"))
            return _Stream(_Response(200, _CONSENT_MARKER, content_type="text/plain"))
        payload = str((json or {})["payload"])
        self.sent.append(payload)
        # A probe that never answers proves the total timeout discards partial work.
        delay = (
            _HANG_SECONDS
            if self._hang_after is not None and len(self.sent) > self._hang_after
            else 0.0
        )
        if self._probe_response is not None:
            return _Stream(self._probe_response, delay=delay)
        outcome = self._outcome(payload)
        if outcome is AuditOutcome.BLOCKED:
            response = _Response(200, '{"verdict":"block"}', content_type="application/json")
        elif outcome is AuditOutcome.NOT_BLOCKED:
            response = _Response(200, '{"verdict":"allow"}', content_type="application/json")
        else:
            response = _Response(503, '{"error":"unavailable"}', content_type="application/json")
        return _Stream(response, delay=delay)


def _install_client(monkeypatch: pytest.MonkeyPatch, target: _StubTarget) -> _StubTarget:
    """Route audit requests to the stub. No test opens a real socket."""

    def _client(*args: object, **kwargs: object) -> _StubTarget:
        target.client_kwargs.append(kwargs)
        return target

    monkeypatch.setattr("warden.variant_audit.httpx.AsyncClient", _client)
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
        (("",), "known Warden threat classes"),
        (("drain_address",), "known Warden threat classes"),
        (("DRAIN_ADDRESS", ""), "known Warden threat classes"),
        (("DRAIN_ADDRESS", "NOT_A_CLASS"), "known Warden threat classes"),
        (("CORPUS_MATCH",), "have adversarial variants"),
        (("DRAIN_ADDRESS", "CORPUS_MATCH"), "have adversarial variants"),
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


@pytest.mark.parametrize(
    "consent_response",
    [
        pytest.param(
            _Response(200, "warden-audit-denied", content_type="text/plain"),
            id="wrong-marker-value",
        ),
        pytest.param(_Response(200, "", content_type="text/plain"), id="empty-body"),
        pytest.param(_Response(200, "true", content_type="text/plain"), id="bare-true-as-text"),
        pytest.param(
            _Response(200, f"{_CONSENT_MARKER} for partners", content_type="text/plain"),
            id="marker-with-trailing-text",
        ),
        pytest.param(
            _Response(200, "warden audit allowed", content_type="text/plain"),
            id="marker-without-hyphens",
        ),
        pytest.param(_Response(200, "false", content_type="application/json"), id="json-false"),
        pytest.param(
            _Response(200, '{"consent":false}', content_type="application/json"),
            id="json-consent-false",
        ),
        pytest.param(
            _Response(200, '{"consent":"warden-audit-denied"}', content_type="application/json"),
            id="json-consent-denied",
        ),
        pytest.param(
            _Response(200, '{"status":"open-season"}', content_type="application/json"),
            id="json-status-wrong",
        ),
        pytest.param(
            _Response(200, '{"consent":1}', content_type="application/json"),
            id="json-consent-truthy-non-bool",
        ),
        pytest.param(
            _Response(200, '{"consent":["warden-audit-allowed"]}', content_type="application/json"),
            id="json-consent-wrapped-in-a-list",
        ),
        pytest.param(
            _Response(200, "{not json", content_type="application/json"), id="malformed-json"
        ),
        pytest.param(_Response(200, b"\xff\xfe\x00", content_type="text/plain"), id="not-utf8"),
        pytest.param(
            _Response(200, _CONSENT_MARKER, content_type="text/plain", content_encoding="gzip"),
            id="compressed-body-is-never-inspected",
        ),
        pytest.param(
            _Response(200, "x" * (MAX_CONSENT_RESPONSE_BYTES + 1), content_type="text/plain"),
            id="oversized-body",
        ),
        pytest.param(_Response(204, "", content_type="text/plain"), id="204-is-not-200"),
        pytest.param(
            _Response(401, _CONSENT_MARKER, content_type="text/plain"),
            id="marker-behind-an-auth-wall",
        ),
        pytest.param(_Response(500, _CONSENT_MARKER, content_type="text/plain"), id="server-error"),
    ],
)
async def test_variant_audit_refuses_a_malformed_or_wrong_consent_marker(
    monkeypatch: pytest.MonkeyPatch,
    consent_response: _Response,
) -> None:
    """Only the exact published marker opts a target in.

    An absent marker is already covered above; these are the cases where the endpoint
    answers but does not actually say yes. Every one must refuse before a single
    attack payload leaves the process.
    """
    target = _install_target(monkeypatch, _StubTarget(consent_response=consent_response))

    with pytest.raises(ValueError, match="did not pass consent check"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=1)

    assert target.sent == []


@pytest.mark.parametrize(
    "consent_response",
    [
        pytest.param(
            _Response(200, _CONSENT_MARKER, content_type="text/plain"), id="plain-text-marker"
        ),
        pytest.param(
            _Response(200, f"  {_CONSENT_MARKER}\n", content_type="text/plain"),
            id="whitespace-padded",
        ),
        pytest.param(
            _Response(200, _CONSENT_MARKER.upper(), content_type="text/plain"), id="uppercase"
        ),
        pytest.param(
            _Response(
                200,
                _CONSENT_MARKER,
                content_type="text/plain; charset=utf-8",
                content_encoding="identity",
            ),
            id="identity-content-encoding",
        ),
        pytest.param(
            _Response(200, f'"{_CONSENT_MARKER}"', content_type="application/json"),
            id="json-string",
        ),
        pytest.param(_Response(200, "true", content_type="application/json"), id="json-true"),
        pytest.param(
            _Response(200, '{"consent":true}', content_type="application/json"),
            id="json-consent-true",
        ),
        pytest.param(
            _Response(200, f'{{"consent":"{_CONSENT_MARKER}"}}', content_type="application/json"),
            id="json-consent-marker",
        ),
        pytest.param(
            _Response(200, f'{{"status":"{_CONSENT_MARKER}"}}', content_type="application/json"),
            id="json-status-marker",
        ),
    ],
)
async def test_variant_audit_accepts_only_the_documented_consent_forms(
    monkeypatch: pytest.MonkeyPatch,
    consent_response: _Response,
) -> None:
    """The exact accepted marker values, so an integrator never has to guess one."""
    target = _install_target(monkeypatch, _StubTarget(consent_response=consent_response))

    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=1,
    )

    assert target.sent
    assert report["consent_verified"] is True
    assert verify_report(dict(report)) is True


@pytest.mark.parametrize(
    "target_url",
    [
        "http://10.0.0.5/scan",
        "http://192.168.1.10/scan",
        "http://172.16.0.1/scan",
        "http://100.64.0.1/scan",
        "http://0.0.0.0/scan",
        "http://[fd00::1]/scan",
        "http://[::ffff:127.0.0.1]/scan",
        "http://[::ffff:10.0.0.5]/scan",
        "http://[64:ff9b::7f00:1]/scan",
    ],
)
async def test_variant_audit_rejects_private_and_translated_internal_targets(
    monkeypatch: pytest.MonkeyPatch,
    target_url: str,
) -> None:
    """RFC1918, CGNAT, unspecified, IPv6 ULA, IPv4-mapped and NAT64 targets all refuse.

    The last three matter most: `::ffff:127.0.0.1` and `64:ff9b::7f00:1` are loopback
    wearing an IPv6 costume, and a guard that only string-matched would let them out.
    """
    target = _install_client(monkeypatch, _StubTarget())

    with pytest.raises(ValueError):
        await run_variant_audit(target_url, max_variants_per_class=1)

    assert target.sent == []
    assert target.urls == []


@pytest.mark.parametrize(
    "addresses",
    [
        pytest.param({"127.0.0.1"}, id="loopback"),
        pytest.param({"10.0.0.5"}, id="rfc1918"),
        pytest.param({"169.254.169.254"}, id="cloud-metadata"),
        pytest.param({"::1"}, id="ipv6-loopback"),
        pytest.param({"93.184.216.34", "10.0.0.5"}, id="public-and-private-in-one-answer"),
    ],
)
async def test_variant_audit_refuses_a_hostname_that_resolves_internally(
    monkeypatch: pytest.MonkeyPatch,
    addresses: set[str],
) -> None:
    """A public-looking name that resolves inward refuses, including a mixed answer.

    The mixed case is the interesting one: pinning only the first address would let a
    multi-record answer smuggle an internal host past the guard.
    """

    async def _resolve_host(hostname: str) -> set[str]:
        return set(addresses)

    monkeypatch.setattr(apa_url, "resolve_host", _resolve_host)
    target = _install_client(monkeypatch, _StubTarget())

    with pytest.raises(ValueError, match="blocked internal address"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=1)

    assert target.sent == []
    assert target.urls == []


async def test_variant_audit_pins_one_dns_resolution_against_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DNS is resolved exactly once and every probe goes to that pinned address.

    The fake resolver answers with a public address first and loopback afterwards. A
    prober that re-resolved — for the consent GET or for any probe — would connect to
    127.0.0.1 instead.
    """
    resolutions: list[str] = []

    async def _resolve_host(hostname: str) -> set[str]:
        resolutions.append(hostname)
        return {"93.184.216.34"} if len(resolutions) == 1 else {"127.0.0.1"}

    monkeypatch.setattr(apa_url, "resolve_host", _resolve_host)
    target = _install_client(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=2)

    assert resolutions == ["target.example"]
    assert len(target.urls) == len(target.sent) + 1
    assert all(url.startswith("https://93.184.216.34:443/") for url in target.urls)
    assert set(target.host_headers) == {"target.example"}
    assert not any("127.0.0.1" in url for url in target.urls)
    assert report["target_host"] == "target.example"
    # The rebound answer really is internal, so the single pin is what prevented SSRF.
    assert await _resolve_host("target.example") == {"127.0.0.1"}


async def test_variant_audit_does_not_follow_a_probe_redirect_to_a_private_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 3xx is inconclusive and never chased, so a target cannot bounce probes inward."""
    redirect = _Response(302, "", content_type="text/plain")
    redirect.headers["location"] = "http://127.0.0.1:8000/scan"
    target = _install_target(monkeypatch, _StubTarget(probe_response=redirect))

    report = await run_variant_audit(
        _TARGET_URL,
        threat_classes=("DRAIN_ADDRESS",),
        max_variants_per_class=2,
    )

    assert target.client_kwargs == [
        {"timeout": variant_audit.AUDIT_TIMEOUT_SECONDS, "follow_redirects": False}
    ]
    assert not any("127.0.0.1" in url for url in target.urls)
    assert report["per_class"] == [
        {
            "threat_class": "DRAIN_ADDRESS",
            "total": 2,
            "detected": 0,
            "missed": 0,
            "inconclusive": 2,
            "conclusive": 0,
            "detection_rate": None,
        }
    ]


async def test_variant_audit_refuses_a_consent_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redirected consent marker is not consent, and the redirect is not followed."""
    redirect = _Response(302, "", content_type="text/plain")
    redirect.headers["location"] = f"http://127.0.0.1:8000{_CONSENT_PATH}"
    target = _install_target(monkeypatch, _StubTarget(consent_response=redirect))

    with pytest.raises(ValueError, match="did not pass consent check"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=1)

    assert target.sent == []
    assert not any("127.0.0.1" in url for url in target.urls)


async def test_variant_audit_total_timeout_emits_no_partial_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run that overruns its budget raises and signs nothing.

    Three probes answer and the fourth never does, so the run holds a real partial
    result when the deadline fires. It must discard it rather than sign a report whose
    counts silently omit most of the battery.
    """
    monkeypatch.setattr(variant_audit, "TOTAL_TIMEOUT_SECONDS", 1.0)
    target = _install_target(monkeypatch, _StubTarget(hang_after=3))

    with pytest.raises(ValueError, match="timed out; no partial report was issued"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=2)

    assert len(target.sent) == 4


@pytest.mark.parametrize(
    "max_variants_per_class",
    [3.0, 1.5, "3", None, b"3", MAX_VARIANTS_PER_CLASS + 0.5],
)
async def test_variant_audit_rejects_a_non_integer_cap(
    monkeypatch: pytest.MonkeyPatch,
    max_variants_per_class: object,
) -> None:
    """A float, string or bytes cap is refused rather than coerced into a probe budget."""
    target = _install_target(monkeypatch, _StubTarget())

    with pytest.raises(ValueError, match="max_variants_per_class"):
        await run_variant_audit(_TARGET_URL, max_variants_per_class=max_variants_per_class)

    assert target.sent == []


async def test_variant_audit_only_sends_payloads_that_decode_to_a_training_attack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive provenance: every wire payload traces to exactly one corpus/attacks.jsonl row.

    The held-out test proves benchmark rows are absent. This proves the complement —
    that what actually left the process came from the training corpus and nowhere else
    — by normalizing each sent payload back to its single training origin.
    """
    target = _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=2)

    training_rows = load_dataset_rows(TRAINING_ATTACKS_PATH, label="training attacks")
    training_by_canonical = {
        canonical_dataset_payload(str(row["payload"])): str(row["id"]) for row in training_rows
    }
    held_out_ids = {str(row["id"]) for row in _held_out_rows()}
    variants_by_payload = {
        str(variant["payload"]): variant
        for pack in variant_audit._canonical_packs().values()
        for variant in pack["variants"]
    }

    assert target.sent
    assert adversarial_variants.SOURCE_DATASET == "corpus/attacks.jsonl"
    for payload in target.sent:
        variant = variants_by_payload[payload]
        assert variant["source_dataset"] == adversarial_variants.SOURCE_DATASET
        assert variant["source"]["dataset"] == adversarial_variants.SOURCE_DATASET
        source_case_id = str(variant["source_case_id"])
        assert source_case_id not in held_out_ids
        origins = {
            training_by_canonical[candidate]
            for candidate in scanner_equivalence(payload)
            if candidate in training_by_canonical
        }
        assert origins == {source_case_id}
    assert int(report["totals"]["variants_sent"]) == len(target.sent)


async def test_variant_audit_report_binds_exactly_the_documented_count_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The report is counts plus declared metadata: no payloads, hashes or case ids."""
    _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=1)

    assert set(report) == REPORT_FIELDS
    assert set(report["caps"]) == {
        "max_variants_per_class",
        "max_total_variants",
        "probe_timeout_seconds",
        "total_timeout_seconds",
        "max_response_bytes",
    }
    rate_fields = {"detected", "missed", "inconclusive", "conclusive", "detection_rate"}
    for entry in report["per_class"]:
        assert set(entry) == rate_fields | {"threat_class", "total"}
    assert set(report["totals"]) == rate_fields | {"threat_classes", "variants_sent"}

    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    for pack in variant_audit._canonical_packs().values():
        for variant in pack["variants"]:
            assert str(variant["source_case_id"]) not in serialized
            assert str(variant["payload_sha256"]) not in serialized
            assert str(variant["payload"]) not in serialized


async def test_variant_audit_report_binds_the_host_but_not_the_probed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Documented gap: the report names a host, not the exact endpoint that was probed.

    The 20-probe audit badge binds scheme, host, port, path and query. This report
    binds only the host, so two different paths on one host produce byte-identical
    signed content and an identical report_id. A buyer cannot tell from the report
    which endpoint was tested.
    """

    async def _validate_public_http_url(self: AgentAuditor, target_url: str):
        parsed = urlparse(target_url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return f"https://93.184.216.34:443{path}", "target.example", parsed

    monkeypatch.setattr(AgentAuditor, "_validate_public_http_url", _validate_public_http_url)

    hardened = _install_client(monkeypatch, _StubTarget())
    first = await run_variant_audit("https://target.example/scan", max_variants_per_class=1)
    permissive = _install_client(monkeypatch, _StubTarget())
    second = await run_variant_audit(
        "https://target.example/echo-everything?debug=1", max_variants_per_class=1
    )

    assert any(url.endswith("/scan") for url in hardened.urls)
    assert any(url.endswith("/echo-everything?debug=1") for url in permissive.urls)
    assert _content(first) == _content(second)
    assert first["report_id"] == second["report_id"]
    assert first["target_host"] == second["target_host"] == "target.example"
    assert "/echo-everything" not in json.dumps(second)


def _resign(record: dict[str, object]) -> dict[str, object]:
    """Re-sign a mutated record with the live issuer key.

    A mutation that also refreshes report_id and the signature is the hardest case:
    only a field verify_report checks independently of the hash can still reject it.
    """
    content = {field: record[field] for field in CONTENT_FIELDS}
    rebuilt = {
        **content,
        "report_id": report_id_for_content(content),
        "issuer": record["issuer"],
        "issued_at": record["issued_at"],
    }
    return ed25519_sign_record(rebuilt, protection.issuer_private_key(), "issuer_sig")


@pytest.mark.parametrize("field", sorted(REPORT_FIELDS))
async def test_variant_audit_signature_covers_every_report_field(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """Mutating any single field of a signed report breaks verification."""
    _install_target(monkeypatch, _StubTarget())

    report = await run_variant_audit(_TARGET_URL, max_variants_per_class=1)
    assert verify_report(dict(report)) is True

    mutations: dict[str, object] = {
        "schema_version": int(report["schema_version"]) + 1,
        "target_host": "attacker.example",
        "corpus_fingerprint": f"sha256:{'0' * 64}",
        "generator": "warden-adversarial-variants/999",
        "caps": {**report["caps"], "max_variants_per_class": MAX_VARIANTS_PER_CLASS},
        "per_class": [{**report["per_class"][0], "detected": 999}],
        "totals": {**report["totals"], "detected": 999},
        "consent_verified": False,
        "limitations": list(report["limitations"])[:-1],
        "report_id": "0" * 64,
        "issuer": "not-warden",
        "issued_at": int(report["issued_at"]) + 1,
        "issuer_sig": ed25519_sign_record(
            {"unrelated": "record"}, protection.issuer_private_key(), "issuer_sig"
        )["issuer_sig"],
    }
    tampered = {**json.loads(json.dumps(report)), field: mutations[field]}

    assert tampered[field] != report[field]
    assert verify_report(tampered) is False


@pytest.mark.parametrize("field", sorted(REPORT_FIELDS))
async def test_variant_audit_rejects_a_report_with_a_dropped_field(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """A record missing any required field is not a report, whatever else verifies."""
    _install_target(monkeypatch, _StubTarget())

    report = json.loads(json.dumps(await run_variant_audit(_TARGET_URL, max_variants_per_class=1)))
    del report[field]

    assert verify_report(report) is False


async def test_variant_audit_rejects_an_extra_field_smuggled_into_a_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An added field cannot ride along, so no unsigned claim can be attached."""
    _install_target(monkeypatch, _StubTarget())

    report = json.loads(json.dumps(await run_variant_audit(_TARGET_URL, max_variants_per_class=1)))
    report["certified"] = True

    assert verify_report(report) is False


async def test_variant_audit_rejects_a_report_signed_by_another_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A well-formed report signed by a key that is not the issuer's does not verify."""
    _install_target(monkeypatch, _StubTarget())
    report = json.loads(json.dumps(await run_variant_audit(_TARGET_URL, max_variants_per_class=1)))

    forged = ed25519_sign_record(
        {field: report[field] for field in REPORT_FIELDS if field != "issuer_sig"},
        Ed25519PrivateKey.generate(),
        "issuer_sig",
    )

    assert forged["issuer_sig"] != report["issuer_sig"]
    assert verify_report(forged) is False


async def test_variant_audit_rejects_a_non_finite_detection_rate_even_when_resigned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NaN cannot be signed into a report, even with a matching hash and signature.

    `NaN` serializes to a JSON literal no strict parser accepts, so a report carrying
    one would verify here and then fail to parse for the buyer holding it.
    """
    _install_target(monkeypatch, _StubTarget())
    report = json.loads(json.dumps(await run_variant_audit(_TARGET_URL, max_variants_per_class=1)))

    poisoned = _resign({**report, "totals": {**report["totals"], "detection_rate": math.nan}})

    assert math.isnan(poisoned["totals"]["detection_rate"])
    assert poisoned["report_id"] == report_id_for_content(
        {field: poisoned[field] for field in CONTENT_FIELDS}
    )
    assert verify_report(poisoned) is False


@pytest.mark.parametrize(
    "issued_at",
    [
        pytest.param(-1, id="negative"),
        pytest.param(protection.MAX_SAFE_UNIX_SECONDS + 1, id="beyond-max-safe-seconds"),
        pytest.param(True, id="bool"),
        pytest.param(1.0, id="float"),
        pytest.param("1700000000", id="string"),
    ],
)
async def test_variant_audit_rejects_an_invalid_issued_at_even_when_resigned(
    monkeypatch: pytest.MonkeyPatch,
    issued_at: object,
) -> None:
    """issued_at is checked for type and range independently of the signature."""
    _install_target(monkeypatch, _StubTarget())
    report = json.loads(json.dumps(await run_variant_audit(_TARGET_URL, max_variants_per_class=1)))

    resigned = _resign({**report, "issued_at": issued_at})

    assert resigned["issued_at"] == issued_at
    assert verify_report(resigned) is False
