"""Warden firewalling its own negotiation inbox.

Every untrusted buyer-authored message is scanned by the same engine Warden
sells, before any other component (including the negotiator) may read it.
"""

from warden.engine import WardenEngine
from warden.models import ScanResponse

_engine: WardenEngine | None = None


def _get_engine() -> WardenEngine:
    global _engine
    if _engine is None:
        _engine = WardenEngine()
    return _engine


async def screen_incoming(text: str) -> tuple[bool, dict[str, object]]:
    """Scan an incoming buyer message; returns (allowed, verdict_dict).

    allowed is False when the verdict is BLOCK. SANITIZE and ALLOW both pass,
    but callers must use the returned verdict dict's sanitized_payload when
    forwarding SANITIZE content onward.
    """
    verdict = await _get_engine().scan(text, depth="fast")
    verdict_dict = ScanResponse.from_verdict(verdict).model_dump()
    return verdict.verdict != "BLOCK", verdict_dict
