"""Detect payment redirection addresses inside agent payloads."""

import re

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

EVM_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}(?![a-fA-F0-9])")
SOLANA_ADDRESS_RE = re.compile(r"(?<![A-Za-z0-9])([1-9A-HJ-NP-Za-km-z]{32,44})(?![A-Za-z0-9])")
TRANSFER_INTENT_RE = re.compile(
    r"(?i)\b(send|transfer|pay|deposit|withdraw|recipient|payment|funds|to address"
    r"|move|redirect|payout|route|wallet\s+is|receiving address)\b"
)


class DrainAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "drain_address"

    @property
    def weight(self) -> float:
        return 0.30

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        payload = str(ctx.extra.get("payload") or "")
        if not payload.strip():
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0, data={"detections": []}
            )

        expected_addresses = ctx.extra.get("expected_addresses", [])
        has_expected = bool(expected_addresses)
        expected_evm = {
            str(address).lower()
            for address in expected_addresses
            if isinstance(address, str) and address.lower().startswith("0x")
        }
        expected_other = {
            str(address)
            for address in expected_addresses
            if isinstance(address, str) and not address.lower().startswith("0x")
        }

        detections = []
        for match in EVM_ADDRESS_RE.finditer(payload):
            address = match.group()
            confidence = self._confidence(
                payload,
                match.start(),
                match.end(),
                address.lower() in expected_evm,
                has_expected,
            )
            if confidence:
                detections.append(self._detection(address, confidence))

        for match in SOLANA_ADDRESS_RE.finditer(payload):
            address = match.group(1)
            if address in expected_other:
                continue
            confidence = self._confidence(
                payload, match.start(1), match.end(1), False, has_expected
            )
            if confidence:
                detections.append(self._detection(address, confidence))

        score = max((detection["confidence"] for detection in detections), default=0.0) * 100
        flags = [f"Payment redirection candidate: {detection['match']}" for detection in detections]
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={"detections": detections},
        )

    @staticmethod
    def _confidence(
        payload: str,
        start: int,
        end: int,
        is_expected: bool,
        has_expected: bool,
    ) -> float:
        if is_expected:
            return 0.0
        window = payload[max(0, start - 80) : min(len(payload), end + 80)]
        if not TRANSFER_INTENT_RE.search(window):
            return 0.0
        return 0.95 if has_expected else 0.80

    @staticmethod
    def _detection(address: str, confidence: float) -> dict[str, object]:
        return {
            "class": ReasonCode.DRAIN_ADDRESS.value,
            "match": address,
            "confidence": confidence,
        }
