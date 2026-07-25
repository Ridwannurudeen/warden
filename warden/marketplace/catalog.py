"""Build the browser checkout catalog from a marketplace snapshot."""

from __future__ import annotations

from decimal import Decimal
from warden.marketplace.fetch import MarketplaceAgent, MarketplaceSnapshot


def _fee(value: str | float | int | None) -> str:
    if value is None:
        raise RuntimeError("Warden service is missing a fee amount")
    formatted = format(Decimal(str(value)), "f")
    return formatted.rstrip("0").rstrip(".") if "." in formatted else formatted


def build_hire_catalog(
    snapshot: MarketplaceSnapshot,
    provider_agent_id: str = "3808",
) -> dict[str, object]:
    provider = next(
        (agent for agent in snapshot.agents if agent.agent_id == provider_agent_id),
        None,
    )
    if provider is None:
        raise RuntimeError(f"Agent #{provider_agent_id} is missing from the marketplace snapshot")
    return _catalog(provider, snapshot.metadata.captured_at)


def build_hire_catalog_from_agent(
    provider: MarketplaceAgent,
    captured_at: str,
    provider_agent_id: str = "3808",
) -> dict[str, object]:
    """Build the catalog from the provider's own listing rather than the public census.

    `agent search` omits an agent whose listing is under review, so the census cannot
    describe our own services during that window. The provider's own `service-list`
    still can, and it is the authoritative source for our fees either way.
    """
    if provider.agent_id != provider_agent_id:
        raise RuntimeError(f"Expected agent #{provider_agent_id}, got #{provider.agent_id}")
    return _catalog(provider, captured_at)


def _catalog(provider: MarketplaceAgent, captured_at: str) -> dict[str, object]:
    service_copy = {
        "https://warden.gudman.xyz/scan": {
            "key": "scan",
            "taskTitle": "Warden payload scan",
            "taskDescription": "Scan an untrusted agent response with Warden",
            "serviceParams": "Scan one untrusted agent response",
            "requestBody": {
                "payload": "Review this untrusted agent response",
                "context": {"expected_addresses": []},
            },
        },
        "https://warden.gudman.xyz/audit": {
            "key": "audit",
            "taskTitle": "Warden endpoint audit",
            "taskDescription": "Audit an agent endpoint with Warden",
            "serviceParams": "Audit https://example.com/agent-endpoint",
            "requestBody": {
                "target_url": "https://example.com/agent-endpoint",
                "sample_prompts": [],
            },
        },
    }
    services = []
    for endpoint, copy in service_copy.items():
        matches = [service for service in provider.services if service.endpoint == endpoint]
        if len(matches) != 1:
            raise RuntimeError(f"Expected exactly one Warden service at {endpoint}")
        service = matches[0]
        if service.service_type != "A2MCP":
            raise RuntimeError(f"Warden service at {endpoint} must use A2MCP")
        if not service.fee_token:
            raise RuntimeError(f"Warden service at {endpoint} is missing its fee token")
        services.append(
            {
                "serviceId": service.service_id,
                "serviceName": service.service_name,
                "serviceType": service.service_type,
                "serviceDescription": service.service_description,
                "endpoint": service.endpoint,
                "feeAmount": _fee(service.fee_amount),
                "feeTokenAddress": service.fee_token,
                **copy,
            }
        )
    return {
        "schemaVersion": 1,
        "snapshotFetchedAt": captured_at,
        "providerAgentId": provider.agent_id,
        "providerName": provider.name,
        "services": services,
    }
