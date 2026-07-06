"""FastMCP server exposing Warden's A2MCP tools."""

from fastmcp import FastMCP

from warden.auditor import AgentAuditor
from warden.engine import WardenEngine
from warden.models import AuditResponse, ScanContext, ScanResponse

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
        payload,
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
    response: AuditResponse = await auditor.audit(target_url, sample_prompts or [])
    return response.model_dump()


if __name__ == "__main__":
    mcp.run()
