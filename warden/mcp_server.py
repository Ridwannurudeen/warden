"""FastMCP server exposing Warden's A2MCP tools."""

from typing import Annotated
from urllib.parse import urlparse

from fastmcp import FastMCP
from pydantic import Field

from warden.auditor import AgentAuditor
from warden.engine import WardenEngine
from warden.models import (
    AuditRequest,
    AuditResponse,
    Depth,
    MAX_PAYLOAD_LENGTH,
    MAX_SAMPLE_PROMPTS,
    MAX_TARGET_URL_LENGTH,
    ScanContext,
    ScanRequest,
    ScanResponse,
)

mcp = FastMCP("Warden")
engine = WardenEngine()
auditor = AgentAuditor()


@mcp.tool(output_schema=ScanResponse.model_json_schema(by_alias=True))
async def scan_payload(
    payload: Annotated[str, Field(max_length=MAX_PAYLOAD_LENGTH)],
    depth: Depth = "fast",
    context: ScanContext | None = None,
) -> dict[str, object]:
    """Scan untrusted agent payload content and return a Warden verdict."""
    request = ScanRequest.model_validate(
        {"payload": payload, "depth": depth, "context": context or {}}
    )
    verdict = await engine.scan(
        request.payload,
        depth=request.depth,
        context=request.context.model_dump(),
    )
    return ScanResponse.from_verdict(verdict).model_dump(by_alias=True)


@mcp.tool(output_schema=AuditResponse.model_json_schema())
async def audit_agent(
    target_url: Annotated[
        str,
        Field(min_length=1, max_length=MAX_TARGET_URL_LENGTH),
    ],
    sample_prompts: Annotated[
        list[Annotated[str, Field(max_length=MAX_PAYLOAD_LENGTH)]],
        Field(max_length=MAX_SAMPLE_PROMPTS),
    ]
    | None = None,
    input_field: Annotated[
        str,
        Field(
            min_length=1,
            max_length=64,
            description="JSON body key the target expects the untrusted text under (default 'payload').",
        ),
    ] = "payload",
) -> dict[str, object]:
    """Run the Warden fixed attack battery against an HTTP agent endpoint."""
    request = AuditRequest.model_validate(
        {
            "target_url": target_url,
            "sample_prompts": sample_prompts or [],
            "input_field": input_field,
        }
    )
    parsed_target = urlparse(request.target_url)
    if parsed_target.scheme not in {"http", "https"}:
        raise ValueError("target_url must use http or https")
    if not parsed_target.hostname:
        raise ValueError("target_url must include a hostname")
    if parsed_target.username or parsed_target.password:
        raise ValueError("target_url must not include credentials")

    response: AuditResponse = await auditor.audit(
        request.target_url,
        request.sample_prompts,
        request.input_field,
    )
    return response.model_dump()


if __name__ == "__main__":
    mcp.run(transport="stdio")
