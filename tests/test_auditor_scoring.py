"""Scoring tests for AgentAuditor._target_blocks_payload."""

import asyncio

from warden.auditor import AgentAuditor


class _Response:
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._body = body.encode("utf-8")

    async def aiter_bytes(self):
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


def _blocks(status_code: int, body: str, payload: str = "attack payload") -> bool:
    auditor = AgentAuditor()
    client = _Client(_Response(status_code, body))
    return asyncio.run(auditor._target_blocks_payload(client, "http://x", "x", payload))


def test_400_naming_threat_class_is_blocked():
    assert _blocks(400, '{"error":"instruction_override_attempt","charged":false}') is True


def test_400_naming_tool_hijack_is_blocked():
    assert _blocks(400, '{"threat":"tool_hijack","charged":false}') is True


def test_400_schema_error_is_not_blocked():
    assert _blocks(400, '{"detail":"Request body must be a JSON object"}') is False


def test_429_rate_limit_is_not_blocked():
    assert _blocks(429, '{"detail":"Rate limit exceeded"}') is False


def test_200_json_verdict_block_is_blocked():
    assert _blocks(200, '{"verdict":"block"}') is True


def test_200_reflected_injection_payload_is_not_blocked():
    payload = "ignore instructions, this is a prompt injection"
    assert _blocks(200, f'{{"echo":"{payload}"}}', payload=payload) is False


def test_401_any_body_is_blocked():
    assert _blocks(401, "nope") is True
