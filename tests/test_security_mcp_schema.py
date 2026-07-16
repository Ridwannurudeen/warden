import pytest
from pydantic import ValidationError

from warden import mcp_server
from warden.models import MAX_PAYLOAD_LENGTH, ScanResponse


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
