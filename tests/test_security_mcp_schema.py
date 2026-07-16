import pytest
from pydantic import ValidationError

from warden import mcp_server
from warden.models import (
    MAX_PAYLOAD_LENGTH,
    MAX_SAMPLE_PROMPTS,
    MAX_TARGET_URL_LENGTH,
    AuditRequest,
    ScanResponse,
)


@pytest.mark.asyncio
async def test_scan_tool_schema_exposes_bounded_typed_contract():
    tool = await mcp_server.mcp.get_tool("scan_payload")

    assert tool is not None
    properties = tool.parameters["properties"]
    assert properties["payload"]["maxLength"] == MAX_PAYLOAD_LENGTH
    assert properties["depth"]["enum"] == ["fast", "thorough"]
    context_schema = properties["context"]["anyOf"][0]
    assert context_schema["$ref"].endswith("/$defs/ScanContext")
    assert set(tool.output_schema["properties"]) == {
        field.alias or name for name, field in ScanResponse.model_fields.items()
    }


@pytest.mark.asyncio
async def test_scan_tool_rejects_invalid_depth_instead_of_silently_using_fast(monkeypatch):
    called = False

    class RecordingEngine:
        async def scan(self, payload, *, depth, context):
            nonlocal called
            called = True

    monkeypatch.setattr(mcp_server, "engine", RecordingEngine())

    with pytest.raises(ValidationError):
        await mcp_server.scan_payload("ordinary payload", depth="thourough")

    assert called is False


@pytest.mark.asyncio
async def test_audit_tool_schema_exposes_runtime_input_limits():
    tool = await mcp_server.mcp.get_tool("audit_agent")

    assert tool is not None
    properties = tool.parameters["properties"]
    target_schema = properties["target_url"]
    prompts_schema = properties["sample_prompts"]["anyOf"][0]
    item_schema = prompts_schema["items"]
    validated = AuditRequest(
        target_url="https://example.com/agent",
        sample_prompts=["x" * (MAX_PAYLOAD_LENGTH + 1)],
    )

    assert target_schema["maxLength"] == MAX_TARGET_URL_LENGTH
    assert prompts_schema["maxItems"] == MAX_SAMPLE_PROMPTS
    assert item_schema["maxLength"] == MAX_PAYLOAD_LENGTH
    assert len(validated.sample_prompts[0]) == item_schema["maxLength"]
