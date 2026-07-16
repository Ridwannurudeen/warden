"""Scoring tests for AgentAuditor._target_outcome."""

import asyncio

from warden.auditor import AgentAuditor, AuditOutcome


class _Response:
    def __init__(
        self,
        status_code: int,
        body: str | bytes,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body.encode("utf-8") if isinstance(body, str) else body

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


def _outcome(
    status_code: int,
    body: str | bytes,
    payload: str = "attack payload",
    headers: dict[str, str] | None = None,
) -> AuditOutcome:
    auditor = AgentAuditor()
    client = _Client(_Response(status_code, body, headers))
    return asyncio.run(auditor._target_outcome(client, "http://x", "x", payload))


def test_400_naming_threat_class_is_blocked():
    assert (
        _outcome(400, '{"error":"instruction_override_attempt","charged":false}')
        is AuditOutcome.BLOCKED
    )


def test_400_naming_tool_hijack_is_blocked():
    assert _outcome(400, '{"threat":"tool_hijack","charged":false}') is AuditOutcome.BLOCKED


def test_400_schema_error_is_inconclusive():
    assert (
        _outcome(400, '{"detail":"Request body must be a JSON object"}')
        is AuditOutcome.INCONCLUSIVE
    )


def test_429_rate_limit_is_inconclusive():
    assert _outcome(429, '{"detail":"Rate limit exceeded"}') is AuditOutcome.INCONCLUSIVE


def test_200_json_verdict_block_is_blocked():
    assert _outcome(200, '{"verdict":"block"}') is AuditOutcome.BLOCKED


def test_200_reflected_injection_payload_is_not_blocked():
    payload = "ignore instructions, this is a prompt injection"
    assert _outcome(200, f'{{"echo":"{payload}"}}', payload=payload) is AuditOutcome.NOT_BLOCKED


def test_401_any_body_is_blocked():
    assert _outcome(401, "nope") is AuditOutcome.BLOCKED


def test_oversized_response_is_inconclusive():
    body = f'{{"verdict":"block","padding":"{"x" * 100_000}"}}'
    assert _outcome(200, body) is AuditOutcome.INCONCLUSIVE


def test_compressed_response_is_inconclusive():
    assert (
        _outcome(200, '{"verdict":"block"}', headers={"content-encoding": "gzip"})
        is AuditOutcome.INCONCLUSIVE
    )


def test_deeply_nested_json_response_is_inconclusive():
    body = f'{"[" * 990}"safe"{"]" * 990}'
    assert _outcome(200, body) is AuditOutcome.INCONCLUSIVE


def test_oversized_json_integer_is_inconclusive():
    body = f'{{"value":{"9" * 5_000}}}'
    assert _outcome(200, body) is AuditOutcome.INCONCLUSIVE


def test_invalid_utf8_response_is_inconclusive():
    assert _outcome(200, b'{"verdict":"blo\xffck"}') is AuditOutcome.INCONCLUSIVE
