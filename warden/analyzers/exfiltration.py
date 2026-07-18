"""Detect seed phrases, private keys, and secret exfiltration instructions."""

import re
from bisect import bisect_left, bisect_right
from pathlib import Path

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

BIP39_WORDS = frozenset(
    Path(__file__).with_name("bip39_words.txt").read_text(encoding="utf-8").splitlines()
)
PRIVATE_KEY_RE = re.compile(r"(?<![A-Fa-f0-9])(?:0x)?[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
# A bare 64-hex string is format-identical to an Ethereum tx hash or SHA-256
# digest, so only explicit secret context can classify it as key material.
KEY_CONTEXT_RE = re.compile(
    r"(?i)(?:\b(?:private|secret|signing)\s+keys?\b|\bkey\s+material\b|"
    r"seed(?:\s*phrase)?|mnemonic|\bprivkey\b|credential)"
)
PUBLIC_HASH_CONTEXT_RE = re.compile(
    r"(?i)(?:\b(?:tx|transaction)\s+(?:id|hash)\b|\b(?:sha-?256|keccak)\b|"
    r"\b(?:digest|checksum|bytes32|storage\s+slot)\b)"
)
NEGATED_INSTRUCTION_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't|avoid)\s+$"
)
SECRET_DOCUMENT_SUFFIX_RE = re.compile(
    r"(?i)^\s+(?:(?:rotation|security)\s+)?"
    r"(?:notice|documentation|docs?|guide|manual|policy|procedure|report)\b"
)
# Distinctive API-key/token shapes with near-zero benign collision rates.
# Only flagged when an exfil verb appears near the token (or a full exfil
# instruction is present elsewhere), so documentation and benign prose that
# merely mention such prefixes stay clean.
SECRET_TOKEN_RES = [
    re.compile(r"(?<![A-Za-z0-9])sk-(?:live|test|ant|proj)-[A-Za-z0-9-]{8,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9-]{12,}"),
    re.compile(r"(?<![A-Za-z0-9])gh[posru]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
]
EXFIL_VERB_RE = re.compile(
    r"(?i)\b(?:send|paste|share|upload|post|leak|ship|smuggle|forward|exfiltrate"
    r"|output|return|reveal|give|provide|print|dump|echo|disclose|expose|show"
    r"|transfer|wire|transmit|reply\s+with|respond\s+with)\b"
)
EXFIL_INSTRUCTION_RES = [
    re.compile(
        r"(?i)\b(?:send|paste|share|upload|post|exfiltrate|leak)\s+(?:your\s+)?"
        r"(?:wallet|context|seed phrase|seed|mnemonic|private key|api key|secret|system prompt)\b"
    ),
    re.compile(r"(?i)\breveal\s+(?:the\s+)?system\s+prompt\b"),
    # Broader verbs ("output/return/give/print/…") over credential/key tokens only,
    # including underscored/prefixed forms like OKX_API_KEY. Kept off wallet/context
    # to avoid false positives on benign "provide the wallet balance" phrasing.
    re.compile(
        r"(?i)\b(?:send|paste|share|upload|post|leak|ship|smuggle|forward|output|return"
        r"|reveal|give|provide|print|dump|echo|disclose|expose|show|reply\s+with"
        r"|respond\s+with)\s+"
        r"(?:me\s+|us\s+)?(?:your|the|all|any)?\s*"
        r"(?:credentials?|mnemonic|seed\s*phrase|system\s*prompt|"
        r"(?:[a-z0-9]+[_-])?(?:api(?:[_ -]?secret)?|secret|access|private|signing|auth)"
        r"[_ -]?keys?)\b"
    ),
]
SENSITIVE_OBJECT_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"(?<![\w.-])\.env(?![\w.-])(?:\s+(?:files?|contents?))?"
    r"|\b(?:"
    r"authorization\s+headers?"
    r"|bearer\s+tokens?"
    r"|session\s+(?:cookies?|tokens?)"
    r"|system\s+prompts?"
    r"|developer\s+prompts?"
    r"|mnemonics?"
    r"|seed\s*phrases?"
    r"|credentials?"
    r"|passwords?"
    r"|(?:api|access|auth|private|secret|signing)[_ -]?keys?"
    r")\b"
    r")"
)
OUTBOUND_SINK_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"https?://[^\s<>'\"]+"
    r"|\b(?:external\s+)?(?:endpoints?|webhooks?|collectors?|collection\s+servers?)\b"
    r"|\bcallback\s+(?:urls?|payloads?)\b"
    r"|\b(?:post|request)\s+bod(?:y|ies)\b"
    r"|\b(?:query|url)\s+parameters?\b"
    r"|\b(?:email|direct\s+message|dm|chat)\b"
    r")"
)
OUTBOUND_FLOW_RE = re.compile(
    r"(?i)\b(?:include|attach|place|put|embed|append|copy|route|forward|send(?:ing)?|"
    r"upload|post|transmit|write|add|contain|contains|containing|populate|set|"
    r"carry|insert|serialize|encode|export|map|includes)\b"
)
OUTBOUND_NEGATION_PREFIX_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|does\s+not|doesn't|never|must\s+not|should\s+not|"
    r"cannot|can't|avoid)"
    r"(?:\s+\w+){0,3}\s+$"
)
POST_NOUN_SUFFIX_RE = re.compile(r"(?i)^\s+(?:bod(?:y|ies)|requests?)\b")
ABSENT_SENSITIVE_PREFIX_RE = re.compile(r"(?i)\b(?:no|zero|without)\s+(?:\w+\s+){0,2}$")
NEGATED_TRANSFORM_TARGET_PREFIX_RE = re.compile(
    r"(?i)(?:\b(?:redact(?:ed|ing|s)?|mask(?:ed|ing|s)?|"
    r"sanitiz(?:e|ed|es|ing))\s+no"
    r"|\bwithout\s+(?:redact(?:ed|ing|s)?|mask(?:ed|ing|s)?|"
    r"sanitiz(?:e|ed|es|ing))\s+(?:the\s+)?)\s*$"
)
TRANSFORMED_SENSITIVE_PREFIX_RE = re.compile(
    r"(?i)\b(?:redacted|masked|sanitized)\s+(?:\w+\s+){0,2}$"
)
NEGATED_TRANSFORMED_SENSITIVE_PREFIX_RE = re.compile(
    r"(?i)\b(?:not|never|non)[ -]?(?:redacted|masked|sanitized)"
    r"\s+(?:\w+\s+){0,2}$"
)
SAFE_SENSITIVE_SUFFIX_RE = re.compile(
    r"(?ix)^\s+(?:"
    r"(?:only\s+)?(?:in|as)\s+(?:a\s+)?(?:redacted|masked|sanitized)\s+"
    r"(?:form|value|version)"
    r"|(?:is|are|was|were)\s+(?:fully\s+)?(?:redacted|masked|sanitized)"
    r")\b"
)
TRANSFORM_CONDITION_RE = re.compile(
    r"(?ix)"
    r"\b(?:only\s+)?after\s+(?:"
    r"(?:fully\s+)?(?:redact(?:ed|ing)?|mask(?:ed|ing)?|sanitiz(?:e|ed|ing))\s+"
    r"(?:the\s+)?(?:"
    r"it|them|"
    r"\.env(?:\s+(?:files?|contents?))?|"
    r"authorization\s+headers?|bearer\s+tokens?|session\s+(?:cookies?|tokens?)|"
    r"(?:system|developer)\s+prompts?|mnemonics?|seed\s*phrases?|credentials?|"
    r"passwords?|(?:api|access|auth|private|secret|signing)[_ -]?keys?"
    r")"
    r"|(?:"
    r"\.env(?:\s+(?:files?|contents?))?|"
    r"authorization\s+headers?|bearer\s+tokens?|session\s+(?:cookies?|tokens?)|"
    r"(?:system|developer)\s+prompts?|mnemonics?|seed\s*phrases?|credentials?|"
    r"passwords?|(?:api|access|auth|private|secret|signing)[_ -]?keys?"
    r")\s+(?:is|are|was|were)\s+(?:redacted|masked|sanitized)"
    r")"
)
NEGATED_TRANSFORM_CONDITION_PREFIX_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|not|without)(?:\s+\w+){0,4}\s+$"
)
POSITIVE_TRANSFORM_RE = re.compile(
    r"(?i)\b(?:redact(?:ed|ing|s)?|mask(?:ed|ing|s)?|sanitiz(?:e|ed|es|ing))\b"
)
NEGATED_TRANSFORM_PREFIX_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|not|without|fail(?:ed|s|ing)?\s+to|"
    r"skip(?:ped|s|ping)?|avoid(?:ed|s|ing)?)\s+$"
)
LOCAL_TRANSFORM_SCOPE_RE = re.compile(
    r"(?i)\b(?:in|from)\s+(?:the\s+)?(?:local\s+)?"
    r"(?:logs?|telemetry|traces?|metrics?)\b"
)
LOCAL_RETENTION_PREFIX_RE = re.compile(
    r"(?i)\b(?:store|keep|retain|save|persist|hold|write|serialize|cache)"
    r"\s+(?:the\s+)?$"
)
LOCAL_RETENTION_SUFFIX_RE = re.compile(
    r"(?ix)^\s+(?:"
    r"(?:strictly\s+)?locally\b"
    r"|(?:in|into|within)\s+(?:the\s+)?local\s+"
    r"(?:encrypted\s+)?(?:storage|vault|file|cache|memory)\b"
    r"|(?:remains?|stays?|is|are|must\s+remain)\s+(?:strictly\s+)?local\b"
    r")"
)
SOURCE_SENSITIVE_VERB_RE = re.compile(
    r"(?i)\b(?:read|retrieve|extract|fetch|load|access|obtain|collect|capture|get|take)\b"
)
DOCUMENTATION_CONTEXT_RE = re.compile(
    r"(?i)\b(?:documentation|docs?|guide|manual|policy|report|example|schema|format)\b"
)
SINK_DOCUMENT_SUFFIX_RE = re.compile(
    r"(?i)^\s+(?:documentation|docs?|guide|manual|schema|example|format|"
    r"reliability\s+report)\b"
)
UNRELATED_CLAUSE_BOUNDARY_RE = re.compile(
    r"(?i),\s*(?:while|whereas|although|but|and\s+(?:separately|meanwhile))\b"
)
SENSITIVE_REFERENCE_PRONOUN_RE = re.compile(r"(?i)\b(?:it|them|this|these|those)\b")
SECRET_FLOW_BOUNDARY_RE = re.compile(r"(?:[.!?;](?=\s|$)|[\r\n]+)")
MAX_PRONOUN_OBJECT_DISTANCE = 64
MAX_FLOW_EXCERPT_SIZE = 640


class ExfiltrationAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "exfiltration"

    @property
    def weight(self) -> float:
        return 0.25

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        payload = str(ctx.extra.get("payload") or "")
        if not payload.strip():
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0, data={"detections": []}
            )

        detections: list[dict[str, object]] = []
        instruction = self._exfil_instruction(payload)
        has_key_context = KEY_CONTEXT_RE.search(payload) is not None
        for private_key in PRIVATE_KEY_RE.finditer(payload):
            window = payload[max(0, private_key.start() - 40) : private_key.end() + 40]
            has_context = not PUBLIC_HASH_CONTEXT_RE.search(window) and (
                has_key_context or instruction is not None
            )
            if has_context:
                detections.append(self._detection(private_key.group(), 0.95))

        for token, start, end in self._secret_tokens(payload):
            window = payload[max(0, start - 80) : min(len(payload), end + 80)]
            if instruction is not None or EXFIL_VERB_RE.search(window):
                detections.append(self._detection(token, 0.90))

        for seed_phrase in self._seed_phrases(payload):
            detections.append(self._detection(seed_phrase, 0.95))

        if instruction:
            detections.append(self._detection(instruction, 0.80))

        score = max((detection["confidence"] for detection in detections), default=0.0) * 100
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=["Secret exfiltration signal detected"] if detections else [],
            data={"detections": detections},
        )

    @staticmethod
    def _secret_tokens(payload: str) -> list[tuple[str, int, int]]:
        tokens: list[tuple[str, int, int]] = []
        claimed: list[tuple[int, int]] = []
        for pattern in SECRET_TOKEN_RES:
            for match in pattern.finditer(payload):
                span = (match.start(), match.end())
                if any(span[0] < end and start < span[1] for start, end in claimed):
                    continue
                claimed.append(span)
                tokens.append((match.group(), *span))
        return tokens

    @staticmethod
    def _seed_phrases(payload: str) -> list[str]:
        words = list(re.finditer(r"\b[a-z]{3,8}\b", payload.lower()))
        phrases: list[str] = []
        start = 0
        while start <= len(words) - 12:
            window = words[start : start + 12]
            if all(match.group() in BIP39_WORDS for match in window):
                phrases.append(payload[window[0].start() : window[-1].end()])
                start += 12
            else:
                start += 1
        return phrases

    @staticmethod
    def _exfil_instruction(payload: str) -> str | None:
        semantic_flow = ExfiltrationAnalyzer._sensitive_outbound_flow(payload)
        if semantic_flow is not None:
            return semantic_flow

        for pattern in EXFIL_INSTRUCTION_RES:
            for instruction in pattern.finditer(payload):
                prefix = payload[max(0, instruction.start() - 24) : instruction.start()]
                suffix = payload[instruction.end() : instruction.end() + 48]
                if (
                    not NEGATED_INSTRUCTION_RE.search(prefix)
                    and not SECRET_DOCUMENT_SUFFIX_RE.search(suffix)
                    and not ExfiltrationAnalyzer._has_safe_transform_condition(
                        payload[instruction.start() : min(len(payload), instruction.end() + 256)]
                    )
                ):
                    return instruction.group()
        return None

    @staticmethod
    def _has_safe_transform_condition(text: str) -> bool:
        for condition in TRANSFORM_CONDITION_RE.finditer(text):
            prefix = text[max(0, condition.start() - 64) : condition.start()]
            if not NEGATED_TRANSFORM_CONDITION_PREFIX_RE.search(prefix):
                return True
        return False

    @staticmethod
    def _sensitive_outbound_flow(payload: str) -> str | None:
        statement_start = 0
        document_break_before = False
        statement_ranges: list[tuple[int, int, bool]] = []
        for boundary in SECRET_FLOW_BOUNDARY_RE.finditer(payload):
            if (
                boundary.start() > statement_start
                and payload[statement_start : boundary.start()].strip()
            ):
                statement_ranges.append((statement_start, boundary.start(), document_break_before))
                document_break_before = False
            if len(re.findall(r"\r\n|[\r\n]", boundary.group())) >= 2:
                document_break_before = True
            statement_start = boundary.end()
        if statement_start < len(payload) and payload[statement_start:].strip():
            statement_ranges.append((statement_start, len(payload), document_break_before))

        active_sensitive: re.Match[str] | None = None
        for start, end, has_document_break in statement_ranges:
            if has_document_break:
                active_sensitive = None

            sensitive_matches = list(SENSITIVE_OBJECT_RE.finditer(payload, start, end))
            if not sensitive_matches and active_sensitive is None:
                continue
            sensitive_starts = [match.start() for match in sensitive_matches]

            unsafe_sensitive: list[re.Match[str]] = []
            for sensitive in sensitive_matches:
                qualifier = payload[max(start, sensitive.start() - 64) : sensitive.start()]
                suffix = payload[sensitive.end() : min(end, sensitive.end() + 96)]
                if (
                    (
                        ABSENT_SENSITIVE_PREFIX_RE.search(qualifier)
                        and not NEGATED_TRANSFORM_TARGET_PREFIX_RE.search(qualifier)
                    )
                    or (
                        TRANSFORMED_SENSITIVE_PREFIX_RE.search(qualifier)
                        and not NEGATED_TRANSFORMED_SENSITIVE_PREFIX_RE.search(qualifier)
                    )
                    or SAFE_SENSITIVE_SUFFIX_RE.search(suffix)
                    or SECRET_DOCUMENT_SUFFIX_RE.search(suffix)
                ):
                    continue
                unsafe_sensitive.append(sensitive)

            unsafe_starts = [match.start() for match in unsafe_sensitive]
            unsafe_start_set = set(unsafe_starts)
            source_matches = list(SOURCE_SENSITIVE_VERB_RE.finditer(payload, start, end))
            source_starts = [match.start() for match in source_matches]
            documentation_starts = [
                match.start() for match in DOCUMENTATION_CONTEXT_RE.finditer(payload, start, end)
            ]
            for sensitive in unsafe_sensitive:
                source_index = bisect_right(source_starts, sensitive.start()) - 1
                if source_index < 0:
                    continue
                source = source_matches[source_index]
                source_prefix = payload[max(start, source.start() - 48) : source.start()]
                documentation_index = bisect_left(documentation_starts, source.end())
                has_documentation_context = (
                    documentation_index < len(documentation_starts)
                    and documentation_starts[documentation_index] < sensitive.start()
                )
                if (
                    not OUTBOUND_NEGATION_PREFIX_RE.search(source_prefix)
                    and not has_documentation_context
                ):
                    active_sensitive = sensitive

            sinks = [
                sink
                for sink in OUTBOUND_SINK_RE.finditer(payload, start, end)
                if not SINK_DOCUMENT_SUFFIX_RE.search(
                    payload[sink.end() : min(end, sink.end() + 48)]
                )
            ]
            if not sinks:
                continue
            sink_starts = [sink.start() for sink in sinks]

            transform_matches = list(POSITIVE_TRANSFORM_RE.finditer(payload, start, end))
            transform_starts = [match.start() for match in transform_matches]
            local_scope_starts = [
                match.start() for match in LOCAL_TRANSFORM_SCOPE_RE.finditer(payload, start, end)
            ]
            unrelated_clause_starts = [
                match.start()
                for match in UNRELATED_CLAUSE_BOUNDARY_RE.finditer(payload, start, end)
            ]

            for flow in OUTBOUND_FLOW_RE.finditer(payload, start, end):
                if flow.group().casefold() == "post" and POST_NOUN_SUFFIX_RE.search(
                    payload[flow.end() : min(end, flow.end() + 16)]
                ):
                    continue
                prefix = payload[max(start, flow.start() - 64) : flow.start()]
                if OUTBOUND_NEGATION_PREFIX_RE.search(prefix):
                    continue

                condition_window = payload[flow.start() : min(end, flow.end() + 256)]
                if ExfiltrationAnalyzer._has_safe_transform_condition(condition_window):
                    continue

                relevant_sensitive: re.Match[str] | None = None
                pronoun = SENSITIVE_REFERENCE_PRONOUN_RE.search(
                    payload,
                    flow.end(),
                    min(end, flow.end() + MAX_PRONOUN_OBJECT_DISTANCE),
                )
                if pronoun is not None:
                    sink_after_pronoun = bisect_left(sink_starts, pronoun.end())
                    if sink_after_pronoun >= len(sinks):
                        continue
                    sink = sinks[sink_after_pronoun]

                    sensitive_index = bisect_right(sensitive_starts, flow.start()) - 1
                    if sensitive_index >= 0:
                        candidate = sensitive_matches[sensitive_index]
                        if candidate.start() not in unsafe_start_set:
                            continue

                        transform_index = bisect_right(transform_starts, candidate.start()) - 1
                        if transform_index >= 0:
                            transform = transform_matches[transform_index]
                            transform_prefix = payload[
                                max(start, transform.start() - 40) : transform.start()
                            ]
                            transform_target_size = candidate.start() - transform.end()
                            local_scope_index = bisect_left(local_scope_starts, candidate.end())
                            has_local_scope = (
                                local_scope_index < len(local_scope_starts)
                                and local_scope_starts[local_scope_index] < flow.start()
                            )
                            if (
                                transform_target_size <= 64
                                and re.fullmatch(
                                    r"\s+(?:(?:the|all|any|these|those)\s+){0,2}",
                                    payload[transform.end() : candidate.start()],
                                    flags=re.IGNORECASE,
                                )
                                and not NEGATED_TRANSFORM_PREFIX_RE.search(transform_prefix)
                                and not has_local_scope
                            ):
                                continue
                        relevant_sensitive = candidate
                    elif active_sensitive is not None:
                        relevant_sensitive = active_sensitive
                    else:
                        continue
                else:
                    direct_index = bisect_left(unsafe_starts, flow.end())
                    if direct_index >= len(unsafe_sensitive):
                        continue
                    relevant_sensitive = unsafe_sensitive[direct_index]
                    if ExfiltrationAnalyzer._is_local_retention(
                        payload, start, end, relevant_sensitive
                    ):
                        continue
                    unrelated_clause_index = bisect_left(unrelated_clause_starts, flow.end())
                    if (
                        unrelated_clause_index < len(unrelated_clause_starts)
                        and unrelated_clause_starts[unrelated_clause_index]
                        < relevant_sensitive.start()
                    ):
                        continue

                    sink_index = bisect_left(sink_starts, flow.end())
                    if sink_index < len(sinks):
                        sink = sinks[sink_index]
                    else:
                        sink = sinks[-1]

                excerpt_start = max(
                    start,
                    min(flow.start(), sink.start(), relevant_sensitive.start()) - 64,
                )
                excerpt_end = min(
                    end,
                    max(flow.end(), sink.end(), relevant_sensitive.end()) + 96,
                )
                if excerpt_end - excerpt_start > MAX_FLOW_EXCERPT_SIZE:
                    excerpt_start = max(start, min(flow.start(), sink.start()) - 64)
                    excerpt_end = min(end, max(flow.end(), sink.end()) + 96)
                return payload[excerpt_start:excerpt_end].strip()
        return None

    @staticmethod
    def _is_local_retention(
        payload: str,
        statement_start: int,
        statement_end: int,
        sensitive: re.Match[str],
    ) -> bool:
        prefix = payload[max(statement_start, sensitive.start() - 64) : sensitive.start()]
        suffix = payload[sensitive.end() : min(statement_end, sensitive.end() + 96)]
        local_state = LOCAL_RETENTION_SUFFIX_RE.search(suffix)
        if local_state is None:
            return False
        return bool(
            local_state.group()
            .lstrip()
            .lower()
            .startswith(("remain", "stay", "is ", "are ", "must remain"))
            or LOCAL_RETENTION_PREFIX_RE.search(prefix)
        )

    @staticmethod
    def _detection(match: str, confidence: float) -> dict[str, object]:
        return {
            "class": ReasonCode.SECRET_EXFIL.value,
            "match": match,
            "confidence": confidence,
        }
