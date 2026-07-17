"""Detect tool-call shaped payloads carrying executable instructions."""

import json
import re

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

TOOL_KEYS = {
    "tool_call",
    "tool_calls",
    "tool_result",
    "function",
    "arguments",
    "method",
    "params",
}
FINANCIAL_ACTION_RE = re.compile(
    r"(?i)\b(transfer|approve|setApproval(?:ForAll)?|sign|sendTransaction|withdraw|deposit|pay)\b"
)
DANGEROUS_COMMAND_RE = re.compile(
    r"(?i)\b(?:exec(?:ute)?(?:[_-](?:shell|command))?|"
    r"run[_-]?(?:shell|command)|shell|(?:ba|z|k)?sh|powershell|"
    r"cmd(?:\.exe)?|curl|wget|invoke-webrequest)\b"
)
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
BLOCK_REFERENCE_RE = re.compile(r"(?:latest|pending|safe|finalized|earliest|0x[0-9a-fA-F]+)")
TOOL_SHAPE_RE = re.compile(
    r"(?i)(\"(?:tool_call|tool_calls|tool_result|function|arguments)\"|"
    r"\"role\"\s*:\s*\"tool\"|"
    r"\b(?:tool_call|tool_calls|tool_result|function|arguments)\s*[:=])"
)
FENCED_BLOCK_RE = re.compile(r"```(?:json|tool|javascript|python)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
TAGGED_TOOL_RE = re.compile(
    r"<(?P<tag>tool|function|invoke)\b(?P<attributes>[^>]{0,512})>"
    r"(?P<body>(?:(?!</?(?:tool|function|invoke)\b).)*)"
    r"</(?P=tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
SELF_CLOSING_TAGGED_TOOL_RE = re.compile(
    r"<(?:tool|function|invoke)\b(?P<attributes>[^>]{0,512})/\s*>",
    re.IGNORECASE,
)


class ToolHijackAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "tool_hijack"

    @property
    def weight(self) -> float:
        return 0.25

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        payload = str(ctx.extra.get("payload") or "")
        if not payload.strip():
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})

        tool_shape = self._has_tool_shape(payload)
        financial_action = FINANCIAL_ACTION_RE.search(payload)
        fenced_tool = any(self._has_tool_shape(block) for block in FENCED_BLOCK_RE.findall(payload))
        tagged_action = self._tagged_dangerous_action(payload)

        if not tool_shape and not fenced_tool and tagged_action is None:
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})
        if (
            tagged_action is None
            and financial_action is None
            and self._is_read_only_tool_payload(payload)
        ):
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})

        executable_action = tagged_action or financial_action
        confidence = 0.88 if executable_action else 0.60
        match = executable_action.group() if executable_action else "tool-shaped payload"
        detection = {
            "class": ReasonCode.TOOL_HIJACK.value,
            "match": match,
            "confidence": confidence,
        }
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=confidence * 100,
            flags=["Tool-call shaped payload with executable instruction"],
            data={"detections": [detection]},
        )

    @classmethod
    def _has_tool_shape(cls, payload: str) -> bool:
        if TOOL_SHAPE_RE.search(payload):
            return True
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return False
        return cls._json_has_tool_key(parsed)

    @staticmethod
    def _tagged_dangerous_action(payload: str) -> re.Match[str] | None:
        for tagged_call in TAGGED_TOOL_RE.finditer(payload):
            content = f"{tagged_call.group('attributes')} {tagged_call.group('body')}"
            action = FINANCIAL_ACTION_RE.search(content) or DANGEROUS_COMMAND_RE.search(content)
            if action is not None:
                return action
        for tagged_call in SELF_CLOSING_TAGGED_TOOL_RE.finditer(payload):
            attributes = tagged_call.group("attributes")
            action = FINANCIAL_ACTION_RE.search(attributes) or DANGEROUS_COMMAND_RE.search(
                attributes
            )
            if action is not None:
                return action
        return None

    @classmethod
    def _json_has_tool_key(cls, value: object) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key) in TOOL_KEYS:
                    return True
                if str(key) == "role" and nested == "tool":
                    return True
                if cls._json_has_tool_key(nested):
                    return True
        if isinstance(value, list):
            return any(cls._json_has_tool_key(item) for item in value)
        return False

    @classmethod
    def _is_read_only_tool_payload(cls, payload: str) -> bool:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return False

        if not isinstance(parsed, dict):
            return False
        return cls._is_canonical_get_balance_call(parsed) or cls._is_canonical_eth_balance_call(
            parsed
        )

    @staticmethod
    def _is_canonical_get_balance_call(payload: dict[object, object]) -> bool:
        if set(payload) != {"tool_call"}:
            return False
        call = payload["tool_call"]
        if not isinstance(call, dict) or set(call) != {"function", "arguments"}:
            return False
        arguments = call["arguments"]
        return (
            call["function"] == "getBalance"
            and isinstance(arguments, dict)
            and set(arguments) == {"address"}
            and isinstance(arguments["address"], str)
            and EVM_ADDRESS_RE.fullmatch(arguments["address"]) is not None
        )

    @staticmethod
    def _is_canonical_eth_balance_call(payload: dict[object, object]) -> bool:
        required_keys = {"jsonrpc", "method", "params"}
        if not required_keys <= set(payload) <= required_keys | {"id"}:
            return False
        if payload["jsonrpc"] != "2.0" or payload["method"] != "eth_getBalance":
            return False
        if "id" in payload and (isinstance(payload["id"], bool) or not isinstance(payload["id"], int)):
            return False
        params = payload["params"]
        return (
            isinstance(params, list)
            and len(params) == 2
            and isinstance(params[0], str)
            and EVM_ADDRESS_RE.fullmatch(params[0]) is not None
            and isinstance(params[1], str)
            and BLOCK_REFERENCE_RE.fullmatch(params[1]) is not None
        )
