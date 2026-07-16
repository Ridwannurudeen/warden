"""FastMCP server exposing Warden's A2MCP tools."""

from urllib.parse import urlparse

from fastmcp import FastMCP

from warden.auditor import AgentAuditor
from warden.engine import WardenEngine
from warden.models import (
    MAX_PAYLOAD_LENGTH,
    AuditRequest,
    AuditResponse,
    ScanContext,
    ScanResponse,
)

mcp = FastMCP("Warden")
engine = WardenEngine()
auditor = AgentAuditor()


@mcp.tool
async def scan_payload(
    payload: str,
    depth: str = "fast",
    context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Scan untrusted agent payload content and return a Warden verdict."""
    scan_depth = depth if depth in {"fast", "thorough"} else "fast"
    scan_context = ScanContext.model_validate(context or {})
    verdict = await engine.scan(
        payload[:MAX_PAYLOAD_LENGTH],
        depth=scan_depth,
        context=scan_context.model_dump(),
    )
    return ScanResponse.from_verdict(verdict).model_dump(by_alias=True)


@mcp.tool
async def audit_agent(
    target_url: str,
    sample_prompts: list[str] | None = None,
) -> dict[str, object]:
    """Run the Warden fixed attack battery against an HTTP agent endpoint."""
    request = AuditRequest.model_validate(
        {"target_url": target_url, "sample_prompts": sample_prompts or []}
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
    )
    return response.model_dump()


if __name__ == "__main__":
    mcp.run()
