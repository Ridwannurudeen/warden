"""Negotiation boundary for the deterministic executor.

The deterministic layer never talks to an LLM. Anything that requires
judgement (counter-offers, scope discussion) is behind the Negotiator
protocol; the only implementation shipped here politely declines. A future
LLM-backed negotiator implements the same protocol in its own component and
is wired in via TaskExecutor's constructor — it is NOT part of this package.
"""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class NegotiationContext:
    job_id: str
    service_id: str
    buyer_message: str
    price_usdt: str
    verdict: dict[str, object] = field(default_factory=dict)


class Negotiator(Protocol):
    async def respond(self, context: NegotiationContext) -> str: ...


class RefuseNegotiator:
    """Default deterministic negotiator: always politely declines."""

    async def respond(self, context: NegotiationContext) -> str:
        return (
            "Thank you for your message. Warden fulfils listed services at their "
            "listed escrow price and does not negotiate terms in chat. Please "
            "publish or accept the job at the listed price and it will be "
            "executed automatically."
        )
