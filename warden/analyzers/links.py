"""Detect malicious or deceptive links in agent payloads."""

import ipaddress
import re
from urllib.parse import urlparse

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

URL_RE = re.compile(r"(?i)\b(?:https?://[^\s<>'\")]+|data:[^\s<>'\")]+)")
CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
ASCII_ALPHA_RE = re.compile(r"[A-Za-z]")


class MaliciousLinkAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "malicious_link"

    @property
    def weight(self) -> float:
        return 0.20

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        payload = str(ctx.extra.get("payload") or "")
        if not payload.strip():
            return AnalyzerResult(name=self.name, weight=self.weight, score=0, data={"detections": []})

        detections = []
        for match in URL_RE.finditer(payload):
            url = match.group()
            confidence = self._confidence(url)
            if confidence:
                detections.append(
                    {
                        "class": ReasonCode.MALICIOUS_LINK.value,
                        "match": url,
                        "confidence": confidence,
                    }
                )

        score = max((detection["confidence"] for detection in detections), default=0.0) * 100
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=["Malicious link heuristic detected"] if detections else [],
            data={"detections": detections},
        )

    @staticmethod
    def _confidence(url: str) -> float:
        if url.lower().startswith("data:"):
            return 0.85

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return 0.0

        host_lower = host.lower()
        if "xn--" in host_lower:
            return 0.85

        try:
            ipaddress.ip_address(host)
        except ValueError:
            is_ip_literal = False
        else:
            is_ip_literal = True
        if is_ip_literal:
            return 0.85

        if CYRILLIC_RE.search(host) and ASCII_ALPHA_RE.search(host):
            return 0.75

        return 0.0
