"""Index public marketplace descriptions through Warden's deterministic engine."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from warden.engine import WardenEngine
from warden.marketplace.fetch import MarketplaceAgent

VerdictLabel = Literal["ALLOW", "SANITIZE", "BLOCK"]
RiskLabel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_VERDICT_ORDER = {"ALLOW": 0, "SANITIZE": 1, "BLOCK": 2}
_RISK_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class IndexedAgent(BaseModel):
    agent: MarketplaceAgent
    verdict: VerdictLabel | None
    risk_level: RiskLabel | None
    threat_classes: list[str]
    fields_scanned: int
    rationale: str


async def index_agent(agent: MarketplaceAgent, engine: WardenEngine) -> IndexedAgent:
    public_text = []
    if agent.profile_description.strip():
        public_text.append(agent.profile_description)
    public_text.extend(
        service.service_description
        for service in agent.services
        if service.service_description.strip()
    )

    if not public_text:
        return IndexedAgent(
            agent=agent,
            verdict=None,
            risk_level=None,
            threat_classes=[],
            fields_scanned=0,
            rationale="No public description text was available to scan.",
        )

    verdicts = [await engine.scan(text, depth="fast") for text in public_text]
    verdict = max((result.verdict for result in verdicts), key=_VERDICT_ORDER.__getitem__)
    risk_level = max((result.risk_level for result in verdicts), key=_RISK_ORDER.__getitem__)
    threat_classes: list[str] = []
    for result in verdicts:
        for threat_class in result.threat_classes:
            if threat_class.value not in threat_classes:
                threat_classes.append(threat_class.value)

    if threat_classes:
        rationale = (
            "Public listing text contains patterns Warden classifies as "
            f"{', '.join(threat_classes)}."
        )
    else:
        suffix = "field" if len(public_text) == 1 else "fields"
        rationale = f"No injection patterns were detected in {len(public_text)} public description {suffix}."

    return IndexedAgent(
        agent=agent,
        verdict=verdict,
        risk_level=risk_level,
        threat_classes=threat_classes,
        fields_scanned=len(public_text),
        rationale=rationale,
    )


async def index_agents(
    agents: list[MarketplaceAgent],
    engine: WardenEngine,
) -> list[IndexedAgent]:
    return [await index_agent(agent, engine) for agent in agents]
