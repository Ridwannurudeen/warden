"""Detect malicious or deceptive links in agent payloads."""

import ipaddress
import re
from urllib.parse import urlparse

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "buff.ly",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "rb.gy",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }
)
_SHORTENER_HOST_PATTERN = "|".join(re.escape(host) for host in sorted(SHORTENER_HOSTS))
URL_RE = re.compile(
    r"(?i)(?:\b(?:https?://[^\s<>'\")]+|"
    r"file:[^\s<>'\")]*|data:[^\s<>'\")]+)"
    r"|(?<![\w@.-])www\.[^\s<>'\")]+|"
    r"(?<![-\w+./:\x5c])"
    r"(?:j[\t\r\n]*a[\t\r\n]*v[\t\r\n]*a[\t\r\n]*s[\t\r\n]*c"
    r"[\t\r\n]*r[\t\r\n]*i[\t\r\n]*p[\t\r\n]*t|"
    r"v[\t\r\n]*b[\t\r\n]*s[\t\r\n]*c[\t\r\n]*r[\t\r\n]*i"
    r"[\t\r\n]*p[\t\r\n]*t):[^\s<>'\")]*"
    r")"
)
BARE_SHORTENER_RE = re.compile(rf"(?i)(?<![\w@./-])(?:{_SHORTENER_HOST_PATTERN})/[^\s<>'\")]+")
CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
ASCII_ALPHA_RE = re.compile(r"[A-Za-z]")
CONFUSABLE_BRANDS = frozenset(
    {
        "amazon",
        "apple",
        "binance",
        "coinbase",
        "github",
        "google",
        "metamask",
        "microsoft",
        "okx",
        "paypal",
    }
)
CONFUSABLE_ASCII = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0456": "i",
    "\u0458": "j",
    "\u0455": "s",
    "\u04bb": "h",
    "\u04cf": "l",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
}


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
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0, data={"detections": []}
            )

        detections = []
        for pattern in (URL_RE, BARE_SHORTENER_RE):
            for match in pattern.finditer(payload):
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
        lowered = url.replace("\t", "").replace("\r", "").replace("\n", "").lower()
        if lowered.startswith(("javascript:", "vbscript:")):
            return 0.95
        if lowered.startswith("file:"):
            return 0.95
        if lowered.startswith("data:"):
            return 0.85

        parsed = urlparse(url if "://" in url else f"https://{url}")
        try:
            host = parsed.hostname or ""
        except ValueError:
            return 0.85
        if not host:
            return 0.0

        host_lower = host.lower().rstrip(".")
        if "xn--" in host_lower:
            return 0.85

        if MaliciousLinkAnalyzer._is_legacy_ip_host(host_lower):
            return 0.90

        try:
            ipaddress.ip_address(host_lower)
        except ValueError:
            is_ip_literal = False
        else:
            is_ip_literal = True
        if is_ip_literal:
            return 0.85

        normalized_host = host_lower.removeprefix("www.")
        if normalized_host in SHORTENER_HOSTS:
            return 0.75

        if MaliciousLinkAnalyzer._is_confusable_idn(host_lower):
            return 0.85

        if any(
            CYRILLIC_RE.search(label) and ASCII_ALPHA_RE.search(label)
            for label in host.rstrip(".").split(".")
        ):
            return 0.75

        return 0.0

    @staticmethod
    def _is_legacy_ip_host(host: str) -> bool:
        if host.startswith("0x"):
            try:
                return int(host[2:], 16) <= 0xFFFFFFFF
            except ValueError:
                return False

        if host.isdecimal() and "." not in host:
            try:
                return int(host, 10) <= 0xFFFFFFFF
            except ValueError:
                return False

        parts = host.split(".")
        if len(parts) > 4 or not all(parts):
            return False
        legacy_component = len(parts) < 4
        for part in parts:
            base = 10
            digits = part
            if part.lower().startswith("0x"):
                base = 16
                digits = part[2:]
                legacy_component = True
            elif len(part) > 1 and part.startswith("0"):
                base = 8
                legacy_component = True
            try:
                value = int(digits, base)
            except ValueError:
                return False
            if value < 0 or value > 0xFFFFFFFF:
                return False
        return legacy_component

    @staticmethod
    def _is_confusable_idn(host: str) -> bool:
        for label in host.rstrip(".").split("."):
            if label.isascii():
                continue
            mapped = "".join(CONFUSABLE_ASCII.get(character, character) for character in label)
            if mapped == label or not mapped.isascii():
                continue
            is_brand_boundary = any(
                mapped == brand or mapped.startswith(f"{brand}-") for brand in CONFUSABLE_BRANDS
            )
            if ASCII_ALPHA_RE.search(label) or is_brand_boundary:
                return True
        return False
