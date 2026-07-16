"""Optional provider-neutral semantic classification for paid thorough scans."""

import asyncio
import math
import os
import re
from dataclasses import dataclass
from typing import Mapping, Protocol

import httpx

SEMANTIC_TIMEOUT_SECONDS = 2.0
MAX_SEMANTIC_RESPONSE_BYTES = 16_384
ENABLED_VALUES = frozenset({"1", "true", "yes", "on"})
HOST_RE = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


@dataclass(frozen=True)
class SemanticClassification:
    flagged: bool
    confidence: float
    reason: str


class SemanticAnalyzer(Protocol):
    async def classify(self, content: str) -> SemanticClassification: ...


class HttpSemanticAnalyzer:
    """Call a configured HTTPS endpoint using Warden's small JSON contract."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        timeout_seconds: float = SEMANTIC_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            url = httpx.URL(endpoint)
        except httpx.InvalidURL as exc:
            raise ValueError("semantic endpoint must be an absolute HTTPS URL") from exc
        if url.scheme != "https" or not url.host or HOST_RE.fullmatch(url.host) is None:
            raise ValueError("semantic endpoint must be an absolute HTTPS URL")
        if not api_key:
            raise ValueError("semantic API key is required")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("semantic timeout must be a positive finite number")

        self._endpoint = str(url)
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def classify(self, content: str) -> SemanticClassification:
        async with asyncio.timeout(self._timeout_seconds):
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
                trust_env=False,
            ) as client:
                response = await client.post(
                    self._endpoint,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={"task": "prompt_injection_detection", "content": content},
                )
                response.raise_for_status()

        if len(response.content) > MAX_SEMANTIC_RESPONSE_BYTES:
            raise ValueError("semantic response exceeds size limit")

        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("semantic response must be a JSON object")

        flagged = data.get("flagged")
        confidence = data.get("confidence")
        reason = data.get("reason")
        if not isinstance(flagged, bool):
            raise ValueError("semantic response flagged must be a boolean")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("semantic response confidence must be a number")
        confidence = float(confidence)
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("semantic response confidence must be between zero and one")
        if not isinstance(reason, str):
            raise ValueError("semantic response reason must be a string")

        return SemanticClassification(
            flagged=flagged,
            confidence=confidence,
            reason=reason[:200],
        )


def build_semantic_analyzer_from_env(
    environ: Mapping[str, str] | None = None,
) -> HttpSemanticAnalyzer | None:
    """Build the optional analyzer only inside an explicitly paid runtime."""
    values = os.environ if environ is None else environ
    enabled = values.get("WARDEN_SEMANTIC_ENABLED", "").strip().lower()
    endpoint = values.get("WARDEN_SEMANTIC_ENDPOINT", "").strip()
    api_key = values.get("WARDEN_SEMANTIC_API_KEY", "").strip()
    paywall_key = values.get("OKX_API_KEY", "").strip()
    if enabled not in ENABLED_VALUES or not endpoint or not api_key or not paywall_key:
        return None

    try:
        return HttpSemanticAnalyzer(endpoint=endpoint, api_key=api_key)
    except ValueError:
        return None
