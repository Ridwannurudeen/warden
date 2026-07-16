"""Detect tool-call shaped payloads carrying executable instructions."""

import json
import re

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

TOOL_KEYS = {"tool_call", "tool_calls", "tool_result", "function", "arguments"}
FINANCIAL_ACTION_RE = re.compile(
    r"(?i)\b(transfer|approve|setApproval(?:ForAll)?|sign|sendTransaction|withdraw|deposit|pay)\b"
)
TOOL_OPERATION_KEYS = {"function", "name", "method"}
READ_ONLY_TOOL_OPERATIONS = {"getbalance", "eth_getbalance"}
TOOL_SHAPE_RE = re.compile(
    r"(?i)(\"(?:tool_call|tool_calls|tool_result|function|arguments)\"|"
    r"\"role\"\s*:\s*\"tool\"|"
    r"\b(?:tool_call|tool_calls|tool_result|function|arguments)\s*[:=])"
)
FENCED_BLOCK_RE = re.compile(r"```(?:json|tool|javascript|python)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


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

        if not tool_shape and not fenced_tool:
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})
        if financial_action is None and self._is_read_only_tool_payload(payload):
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})

        confidence = 0.88 if financial_action else 0.60
        match = financial_action.group() if financial_action else "tool-shaped payload"
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

        operations = cls._json_tool_operations(parsed)
        return bool(operations) and all(
            operation.casefold() in READ_ONLY_TOOL_OPERATIONS for operation in operations
        )

    @classmethod
    def _json_tool_operations(cls, value: object) -> list[str]:
        operations: list[str] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key) in TOOL_OPERATION_KEYS and isinstance(nested, str):
                    operations.append(nested)
                else:
                    operations.extend(cls._json_tool_operations(nested))
        elif isinstance(value, list):
            for item in value:
                operations.extend(cls._json_tool_operations(item))
        return operations
