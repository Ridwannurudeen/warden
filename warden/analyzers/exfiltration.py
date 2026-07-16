"""Detect seed phrases, private keys, and secret exfiltration instructions."""

import re
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
    re.compile(r"(?i)\bPOST\b.{0,80}\bhttps?://"),
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
            detections.append(self._detection(instruction.group(), 0.80))

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
    def _exfil_instruction(payload: str) -> re.Match[str] | None:
        for pattern in EXFIL_INSTRUCTION_RES:
            for instruction in pattern.finditer(payload):
                prefix = payload[max(0, instruction.start() - 24) : instruction.start()]
                suffix = payload[instruction.end() : instruction.end() + 48]
                if not NEGATED_INSTRUCTION_RE.search(
                    prefix
                ) and not SECRET_DOCUMENT_SUFFIX_RE.search(suffix):
                    return instruction
        return None

    @staticmethod
    def _detection(match: str, confidence: float) -> dict[str, object]:
        return {
            "class": ReasonCode.SECRET_EXFIL.value,
            "match": match,
            "confidence": confidence,
        }
