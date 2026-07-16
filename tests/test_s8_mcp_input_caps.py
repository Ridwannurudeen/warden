"""Regression coverage for bounded MCP tool inputs."""

import pytest
from pydantic import ValidationError

from warden import mcp_server
from warden.core.verdict import Verdict
from warden.models import (
    MAX_PAYLOAD_LENGTH,
    MAX_SAMPLE_PROMPTS,
    MAX_TARGET_URL_LENGTH,
    AuditResponse,
)


@pytest.mark.asyncio
async def test_scan_payload_truncates_before_engine(monkeypatch):
    captured: dict[str, object] = {}

    class RecordingEngine:
        async def scan(self, payload, *, depth, context):
            captured.update(payload=payload, depth=depth, context=context)
            return Verdict(
                verdict="ALLOW",
                risk_level="NONE",
                sanitized_payload=payload,
            )

    monkeypatch.setattr(mcp_server, "engine", RecordingEngine())
    payload = "x" * MAX_PAYLOAD_LENGTH + "tail attack"

    response = await mcp_server.scan_payload(payload, depth="thorough")

    assert captured["payload"] == payload[:MAX_PAYLOAD_LENGTH]
    assert captured["depth"] == "thorough"
    assert response["sanitized_payload"] == payload[:MAX_PAYLOAD_LENGTH]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target_url",
    (
        "file:///tmp/agent",
        "https:///missing-host",
        "https://user:password@example.com/agent",
    ),
)
async def test_audit_agent_rejects_invalid_target_before_auditor(monkeypatch, target_url):
    called = False

    class RecordingAuditor:
        async def audit(self, target_url, sample_prompts):
            nonlocal called
            called = True
            raise AssertionError("invalid targets must not reach the auditor")

    monkeypatch.setattr(mcp_server, "auditor", RecordingAuditor())

    with pytest.raises(ValueError):
        await mcp_server.audit_agent(target_url)

    assert called is False


@pytest.mark.asyncio
async def test_audit_agent_applies_request_caps_before_auditor(monkeypatch):
    calls: list[tuple[str, list[str]]] = []

    class RecordingAuditor:
        async def audit(self, target_url, sample_prompts):
            calls.append((target_url, sample_prompts))
            return AuditResponse(
                score=100,
                grade="A",
                results=[],
                badge="verified",
                recommendations=[],
            )

    monkeypatch.setattr(mcp_server, "auditor", RecordingAuditor())
    oversized_target = "https://example.com/" + "x" * MAX_TARGET_URL_LENGTH

    with pytest.raises(ValidationError):
        await mcp_server.audit_agent(oversized_target)
    with pytest.raises(ValidationError):
        await mcp_server.audit_agent(
            "https://example.com/agent",
            ["prompt"] * (MAX_SAMPLE_PROMPTS + 1),
        )

    long_prompt = "x" * (MAX_PAYLOAD_LENGTH + 1)
    response = await mcp_server.audit_agent(
        "https://example.com/agent",
        [long_prompt],
    )

    assert calls == [
        (
            "https://example.com/agent",
            [long_prompt[:MAX_PAYLOAD_LENGTH]],
        )
    ]
    assert response["grade"] == "A"
