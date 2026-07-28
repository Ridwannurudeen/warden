"""In-process work functions that fulfil accepted marketplace jobs."""

from warden.auditor import AgentAuditor
from warden.engine import WardenEngine
from warden.models import ScanResponse


class WorkParamsError(ValueError):
    """A job's serviceParams are malformed for the requested work."""


def _require_str(params: dict[str, object], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise WorkParamsError(f"serviceParams.{key} must be a non-empty string")
    return value


def _optional_str_list(params: dict[str, object], key: str) -> list[str]:
    value = params.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise WorkParamsError(f"serviceParams.{key} must be a list of strings")
    return value


async def run_scan(
    params: dict[str, object], engine: WardenEngine | None = None
) -> dict[str, object]:
    payload = _require_str(params, "payload")
    depth = params.get("depth", "fast")
    if depth not in {"fast", "thorough"}:
        raise WorkParamsError("serviceParams.depth must be 'fast' or 'thorough'")
    expected_addresses = _optional_str_list(params, "expected_addresses")
    scan_engine = engine if engine is not None else WardenEngine()
    verdict = await scan_engine.scan(
        payload,
        depth=depth,
        context={"expected_addresses": expected_addresses},
        allow_paid_semantic=False,
    )
    return ScanResponse.from_verdict(verdict).model_dump()


async def run_audit(
    params: dict[str, object], auditor: AgentAuditor | None = None
) -> dict[str, object]:
    target_url = _require_str(params, "target_url")
    sample_prompts = _optional_str_list(params, "sample_prompts")
    input_field = params.get("input_field", "payload")
    if not isinstance(input_field, str) or not input_field:
        raise WorkParamsError("serviceParams.input_field must be a non-empty string")
    agent_auditor = auditor if auditor is not None else AgentAuditor()
    try:
        response = await agent_auditor.audit(
            target_url,
            sample_prompts=sample_prompts or None,
            input_field=input_field,
        )
    except ValueError as exc:
        raise WorkParamsError(f"audit rejected: {exc}") from exc
    return response.model_dump()
