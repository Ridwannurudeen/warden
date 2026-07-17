"""Detect tool-call shaped payloads carrying executable instructions."""

from html import unescape
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
    r"(?i)\b(transfer|approve|set[\s_-]*approval(?:[\s_-]*for[\s_-]*all)?|"
    r"sign|send[\s_-]*transaction|withdraw|deposit|pay)\b"
)
DANGEROUS_COMMAND_RE = re.compile(
    r"(?i)\b(?:exec(?:ute)?(?:[\s_-]+(?:shell|command))?|"
    r"run[\s_-]*(?:shell|command)|shell|(?:ba|z|k)?sh|powershell|"
    r"cmd(?:\.exe)?|curl|wget|invoke-webrequest)\b"
)
ACTION_IDENTIFIER_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|[_-]+")
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
BLOCK_REFERENCE_RE = re.compile(r"(?:latest|pending|safe|finalized|earliest|0x[0-9a-fA-F]+)")
TOOL_SHAPE_RE = re.compile(
    r"(?i)(\"(?:tool_call|tool_calls|tool_result|function|arguments)\"|"
    r"\"role\"\s*:\s*\"tool\"|"
    r"\b(?:tool_call|tool_calls|tool_result|function|arguments)\s*[:=])"
)
FENCED_BLOCK_RE = re.compile(r"```(?:json|tool|javascript|python)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
MARKUP_TOKEN_RE = re.compile(
    r"(?P<cdata><!\[CDATA\[)|(?P<comment><!--)|(?P<instruction><\?)|"
    r"(?P<declaration><!)|"
    r"<(?P<closing>/)?(?P<tag>[^\s<>/]+)(?=[\s/>])",
    re.IGNORECASE,
)
TOOL_TAG_NAMES = frozenset({"tool", "function", "invoke"})
CONTENT_ATTRIBUTE_NAMES = frozenset(
    {"action", "arguments", "command", "content", "params", "text", "value"}
)


def _dangerous_action(content: str) -> re.Match[str] | None:
    action = FINANCIAL_ACTION_RE.search(content) or DANGEROUS_COMMAND_RE.search(content)
    if action is not None:
        return action
    normalized = ACTION_IDENTIFIER_BOUNDARY_RE.sub(" ", content)
    return FINANCIAL_ACTION_RE.search(normalized) or DANGEROUS_COMMAND_RE.search(normalized)


def _fragmented_action(*fragment_sets: list[str]) -> re.Match[str] | None:
    for fragments in fragment_sets:
        action = _dangerous_action(unescape("".join(fragments)))
        if action is not None:
            return action
    return None


def _content_attribute_values(header: str) -> str:
    values: list[str] = []
    cursor = 0
    while cursor < len(header):
        while cursor < len(header) and (header[cursor].isspace() or header[cursor] == "/"):
            cursor += 1
        name_start = cursor
        while cursor < len(header) and not header[cursor].isspace() and header[cursor] != "=":
            cursor += 1
        name = header[name_start:cursor].lower()
        while cursor < len(header) and header[cursor].isspace():
            cursor += 1
        if cursor >= len(header) or header[cursor] != "=":
            continue
        cursor += 1
        while cursor < len(header) and header[cursor].isspace():
            cursor += 1
        if cursor >= len(header):
            break
        if header[cursor] in {'"', "'"}:
            quote = header[cursor]
            cursor += 1
            value_start = cursor
            while cursor < len(header) and header[cursor] != quote:
                cursor += 1
            value = header[value_start:cursor]
            if cursor < len(header):
                cursor += 1
        else:
            value_start = cursor
            while cursor < len(header) and not header[cursor].isspace():
                cursor += 1
            value = header[value_start:cursor]
        if name in CONTENT_ATTRIBUTE_NAMES:
            values.append(value)
    return "".join(values)


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
        financial_action = FINANCIAL_ACTION_RE.search(payload) or FINANCIAL_ACTION_RE.search(
            ACTION_IDENTIFIER_BOUNDARY_RE.sub(" ", payload)
        )
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

    @classmethod
    def _tagged_dangerous_action(cls, payload: str) -> re.Match[str] | None:
        cursor = 0
        stack: list[str] = []
        joined_fragments: list[str] = []
        spaced_fragments: list[str] = []
        attributed_fragments: list[str] = []
        while token := MARKUP_TOKEN_RE.search(payload, cursor):
            if stack and token.start() > cursor:
                body = payload[cursor : token.start()]
                joined_fragments.append(body)
                spaced_fragments.append(body)
                attributed_fragments.append(body)

            if token.group("cdata"):
                cdata_end = payload.find("]]>", token.end())
                if cdata_end < 0:
                    if stack:
                        content = payload[token.end() :]
                        joined_fragments.append(content)
                        spaced_fragments.append(content)
                        attributed_fragments.append(content)
                    cursor = len(payload)
                    break
                if stack:
                    content = payload[token.end() : cdata_end]
                    joined_fragments.append(content)
                    spaced_fragments.append(content)
                    attributed_fragments.append(content)
                cursor = cdata_end + 3
                continue

            if token.group("comment"):
                comment_end = payload.find("-->", token.end())
                if comment_end < 0:
                    cursor = len(payload)
                    break
                cursor = comment_end + 3
                continue

            if token.group("instruction"):
                instruction_end = payload.find("?>", token.end())
                if instruction_end < 0:
                    cursor = len(payload)
                    break
                cursor = instruction_end + 2
                continue

            if token.group("declaration"):
                declaration_end = cls._tag_header_end(payload, token.end())
                if declaration_end < 0:
                    cursor = len(payload)
                    break
                cursor = declaration_end + 1
                continue

            header_end = cls._tag_header_end(payload, token.end())
            tag = token.group("tag").lower()
            namespace_parts = tag.split(":")
            recognized_tool_tag = (
                namespace_parts[0] in TOOL_TAG_NAMES
                or namespace_parts[-1] in TOOL_TAG_NAMES
            )
            if header_end < 0:
                incomplete_tag = payload[token.start() :]
                if stack:
                    joined_fragments.append(incomplete_tag)
                    spaced_fragments.append(incomplete_tag)
                    attributed_fragments.append(incomplete_tag)
                    return _fragmented_action(
                        joined_fragments,
                        spaced_fragments,
                        attributed_fragments,
                    )
                return (
                    _dangerous_action(unescape(incomplete_tag))
                    if recognized_tool_tag
                    else None
                )

            inside_tagged_body = bool(stack)
            header = payload[token.end() : header_end]
            if inside_tagged_body:
                spaced_fragments.append(" ")
                action = _dangerous_action(tag)
                if action is not None:
                    return action
            if inside_tagged_body or recognized_tool_tag:
                action = _dangerous_action(unescape(header))
                if action is not None:
                    return action
            if (inside_tagged_body or recognized_tool_tag) and not token.group("closing"):
                attribute_header = header[:-1] if header.endswith("/") else header
                attribute_values = _content_attribute_values(attribute_header)
                action = _dangerous_action(unescape(attribute_values))
                if action is not None:
                    return action
                attributed_fragments.append(attribute_values)

            if token.group("closing"):
                if stack and stack[-1] == tag and not header.strip():
                    stack.pop()
                    if not stack:
                        action = _fragmented_action(
                            joined_fragments,
                            spaced_fragments,
                            attributed_fragments,
                        )
                        if action is not None:
                            return action
                        joined_fragments = []
                        spaced_fragments = []
                        attributed_fragments = []
            elif not header.endswith("/") and (stack or recognized_tool_tag):
                stack.append(tag)

            cursor = header_end + 1

        if stack:
            remainder = payload[cursor:]
            joined_fragments.append(remainder)
            spaced_fragments.append(remainder)
            attributed_fragments.append(remainder)
            return _fragmented_action(
                joined_fragments,
                spaced_fragments,
                attributed_fragments,
            )
        return None

    @staticmethod
    def _tag_header_end(payload: str, start: int) -> int:
        quote: str | None = None
        for index in range(start, len(payload)):
            character = payload[index]
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in {'"', "'"}:
                quote = character
            elif character == ">":
                return index
        return -1

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
