"""Detect seed phrases, private keys, and secret exfiltration instructions."""

import re
from pathlib import Path

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

BIP39_WORDS = frozenset(
    Path(__file__).with_name("bip39_words.txt").read_text(encoding="utf-8").splitlines()
)
PRIVATE_KEY_RE = re.compile(r"(?<![A-Fa-f0-9])(?:0x)?[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
# A bare 64-hex string is format-identical to an Ethereum tx hash or a SHA-256
# digest, so it is only treated as a hard-block secret when secret/key context
# sits next to it; otherwise it is flagged at low confidence (SANITIZE, not BLOCK).
KEY_CONTEXT_RE = re.compile(r"(?i)(?:\bkeys?\b|seed(?:\s*phrase)?|mnemonic|\bprivkey\b|credential)")
EXFIL_INSTRUCTION_RES = [
    re.compile(
        r"(?i)\b(?:send|paste|share|upload|post|exfiltrate|leak)\s+(?:your\s+)?"
        r"(?:wallet|context|seed phrase|seed|mnemonic|private key|api key|secret|system prompt)\b"
    ),
    re.compile(r"(?i)\breveal\s+(?:the\s+)?system\s+prompt\b"),
    re.compile(r"(?i)\bPOST\b.{0,80}\bhttps?://"),
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
        private_key = PRIVATE_KEY_RE.search(payload)
        if private_key:
            window = payload[max(0, private_key.start() - 40) : private_key.end() + 40]
            has_context = bool(KEY_CONTEXT_RE.search(window)) or any(
                pattern.search(payload) for pattern in EXFIL_INSTRUCTION_RES
            )
            detections.append(self._detection(private_key.group(), 0.95 if has_context else 0.5))

        seed_phrase = self._seed_phrase(payload)
        if seed_phrase:
            detections.append(self._detection(seed_phrase, 0.95))

        for pattern in EXFIL_INSTRUCTION_RES:
            instruction = pattern.search(payload)
            if instruction:
                detections.append(self._detection(instruction.group(), 0.80))
                break

        score = max((detection["confidence"] for detection in detections), default=0.0) * 100
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=["Secret exfiltration signal detected"] if detections else [],
            data={"detections": detections},
        )

    @staticmethod
    def _seed_phrase(payload: str) -> str:
        words = list(re.finditer(r"\b[a-z]{3,8}\b", payload.lower()))
        for start in range(0, max(0, len(words) - 11)):
            window = words[start : start + 12]
            if all(match.group() in BIP39_WORDS for match in window):
                return payload[window[0].start() : window[-1].end()]
        return ""

    @staticmethod
    def _detection(match: str, confidence: float) -> dict[str, object]:
        return {
            "class": ReasonCode.SECRET_EXFIL.value,
            "match": match,
            "confidence": confidence,
        }
