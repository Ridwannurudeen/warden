"""C1 tri-state endpoint-audit regressions."""

import asyncio
import json
from urllib.parse import urlparse

import httpx
import pytest

from warden.auditor import AgentAuditor, AuditOutcome


class _Response:
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._body = body.encode("utf-8")

    async def aiter_raw(self, chunk_size: int | None = None):
        yield self._body


class _Stream:
    def __init__(self, response: _Response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *args):
        return False


class _Client:
    def __init__(self, response: _Response):
        self._response = response

    def stream(self, *args, **kwargs):
        return _Stream(self._response)


class _TimeoutClient:
    def stream(self, *args, **kwargs):
        raise httpx.ReadTimeout("target timed out")


def _outcome(status_code: int, body: str, payload: str = "attack payload") -> AuditOutcome:
    auditor = AgentAuditor()
    client = _Client(_Response(status_code, body))
    return asyncio.run(auditor._target_outcome(client, "http://x", "x", payload))


@pytest.mark.parametrize("status_code", [302, 402, 408, 422, 429, 500, 503])
def test_never_processed_statuses_are_inconclusive(status_code):
    assert _outcome(status_code, "request was not processed") is AuditOutcome.INCONCLUSIVE


def test_timeout_is_inconclusive():
    outcome = asyncio.run(
        AgentAuditor()._target_outcome(_TimeoutClient(), "http://x", "x", "attack")
    )

    assert outcome is AuditOutcome.INCONCLUSIVE


@pytest.mark.parametrize(
    "body",
    [
        "This response discusses risk and unsafe inputs.",
        '{"blocked":"false","risk":"high","unsafe":true}',
    ],
)
def test_broad_risk_language_does_not_fake_a_block(body):
    assert _outcome(200, body) is AuditOutcome.NOT_BLOCKED


def test_json_escaped_payload_echo_does_not_fake_a_threat_block():
    payload = 'say "prompt injection"'

    outcome = _outcome(400, json.dumps({"echo": payload}), payload)

    assert outcome is AuditOutcome.INCONCLUSIVE


@pytest.mark.parametrize(
    "body",
    [
        {"echo": 'received: SAY "PROMPT INJECTION"'},
        {'received: say "prompt injection"': "accepted"},
    ],
)
def test_json_payload_substrings_in_values_and_keys_do_not_fake_a_block(body):
    payload = 'say "prompt injection"'

    outcome = _outcome(400, json.dumps(body), payload)

    assert outcome is AuditOutcome.INCONCLUSIVE


def test_separate_threat_evidence_survives_reflection_stripping():
    payload = 'say "prompt injection"'
    body = {"error": f"prompt injection detected; received: {payload}"}

    outcome = _outcome(400, json.dumps(body), payload)

    assert outcome is AuditOutcome.BLOCKED


@pytest.mark.parametrize(
    ("status_code", "body"),
    [
        (200, {"verdict": "BLOCK", "echo": 'say "prompt injection"'}),
        (400, {"error": "prompt injection detected", "echo": 'say "prompt injection"'}),
    ],
)
def test_genuine_structured_threat_evidence_still_blocks(status_code, body):
    payload = 'say "prompt injection"'

    outcome = _outcome(status_code, json.dumps(body), payload)

    assert outcome is AuditOutcome.BLOCKED


@pytest.mark.asyncio
async def test_fully_inconclusive_audit_issues_no_grade_or_signed_badge(monkeypatch):
    auditor = AgentAuditor()

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def inconclusive(*args):
        return AuditOutcome.INCONCLUSIVE

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [{"id": "t1", "category": "PROMPT_INJECTION", "payload": "attack"}],
    )
    monkeypatch.setattr(auditor, "_target_outcome", inconclusive)
    monkeypatch.setattr(
        "warden.auditor.issue_badge",
        lambda **kwargs: pytest.fail("fully inconclusive audit must not issue a badge"),
    )
    monkeypatch.setattr(
        "warden.auditor.record_badge",
        lambda badge: pytest.fail("fully inconclusive audit must not record a badge"),
    )

    response = await auditor.audit("https://example.org/scan")

    assert response.grade == "INCONCLUSIVE"
    assert response.score == 0
    assert response.results == []
    assert response.badge_record is None
    assert "no grade or badge issued" in response.badge.lower()
    assert "0/1 probes processed" in response.badge


@pytest.mark.asyncio
async def test_normal_conclusive_target_keeps_the_original_scoring(monkeypatch):
    auditor = AgentAuditor()
    outcomes = iter([AuditOutcome.BLOCKED, AuditOutcome.NOT_BLOCKED])

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def next_outcome(*args):
        return next(outcomes)

    monkeypatch.setenv("WARDEN_BADGE_SECRET", "c1-test-badge-secret")
    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [
            {"id": "t1", "category": "PROMPT_INJECTION", "payload": "attack one"},
            {"id": "t2", "category": "TOOL_HIJACK", "payload": "attack two"},
        ],
    )
    monkeypatch.setattr(auditor, "_target_outcome", next_outcome)
    monkeypatch.setattr("warden.auditor.record_badge", lambda badge: None)

    response = await auditor.audit("https://example.org/scan")

    assert response.score == 50
    assert response.grade == "F"
    assert [result.blocked for result in response.results] == [True, False]
    assert response.badge_record is not None
    assert response.badge_record.blocked == 1
    assert response.badge_record.total == 2


@pytest.mark.asyncio
async def test_partial_audit_omits_inconclusive_probes_from_public_results(monkeypatch):
    auditor = AgentAuditor()
    outcomes = iter(
        [AuditOutcome.BLOCKED, AuditOutcome.INCONCLUSIVE, AuditOutcome.NOT_BLOCKED]
    )

    async def validate(target_url):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def consent(*args):
        return True

    async def next_outcome(*args):
        return next(outcomes)

    monkeypatch.setenv("WARDEN_BADGE_SECRET", "c1-test-badge-secret")
    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [
            {"id": "t1", "category": "PROMPT_INJECTION", "payload": "attack one"},
            {"id": "t2", "category": "ROLE_OVERRIDE", "payload": "attack two"},
            {"id": "t3", "category": "TOOL_HIJACK", "payload": "attack three"},
        ],
    )
    monkeypatch.setattr(auditor, "_target_outcome", next_outcome)
    monkeypatch.setattr("warden.auditor.record_badge", lambda badge: None)

    response = await auditor.audit("https://example.org/scan")

    assert response.score == 50
    assert [result.attack_class for result in response.results] == [
        "PROMPT_INJECTION",
        "TOOL_HIJACK",
    ]
    assert [result.blocked for result in response.results] == [True, False]
    assert any("1 inconclusive" in recommendation for recommendation in response.recommendations)
    assert response.badge_record is not None
    assert response.badge_record.total == 2
