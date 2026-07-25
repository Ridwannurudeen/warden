"""Hire catalog and page contract tests."""

import json
from pathlib import Path

import pytest

from warden.marketplace.catalog import build_hire_catalog, build_hire_catalog_from_agent
from warden.marketplace.fetch import fetch_provider_agent, load_snapshot


ROOT = Path(__file__).resolve().parents[1]


def test_hire_catalog_is_derived_from_marketplace_snapshot():
    snapshot = load_snapshot(ROOT / "data" / "marketplace" / "agents-v1.jsonl")

    catalog = build_hire_catalog(snapshot)

    assert catalog["providerAgentId"] == "3808"
    assert catalog["schemaVersion"] == 1
    assert catalog["snapshotFetchedAt"] == "2026-07-18T18:35:07Z"
    assert [service["key"] for service in catalog["services"]] == ["scan", "audit"]
    assert [service["feeAmount"] for service in catalog["services"]] == ["0.5", "0.5"]
    service_ids = [service["serviceId"] for service in catalog["services"]]
    assert all(service_id.isdecimal() for service_id in service_ids)
    assert len(set(service_ids)) == len(service_ids)
    assert [service["endpoint"] for service in catalog["services"]] == [
        "https://warden.gudman.xyz/scan",
        "https://warden.gudman.xyz/audit",
    ]
    assert catalog["services"][0]["requestBody"] == {
        "payload": "Review this untrusted agent response",
        "context": {"expected_addresses": []},
    }
    assert catalog["services"][1]["requestBody"] == {
        "target_url": "https://example.com/agent-endpoint",
        "sample_prompts": [],
    }


def test_hire_catalog_uses_changed_snapshot_ids_instead_of_stale_constants():
    snapshot = load_snapshot(ROOT / "data" / "marketplace" / "agents-v1.jsonl").model_copy(
        deep=True
    )
    provider = next(agent for agent in snapshot.agents if agent.agent_id == "3808")
    provider.services[0].service_id = "99999"

    catalog = build_hire_catalog(snapshot)

    assert catalog["services"][0]["serviceId"] == "99999"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_type", "wrong_endpoint"])
def test_hire_catalog_rejects_incomplete_or_unexpected_services(mutation):
    snapshot = load_snapshot(ROOT / "data" / "marketplace" / "agents-v1.jsonl").model_copy(
        deep=True
    )
    provider = next(agent for agent in snapshot.agents if agent.agent_id == "3808")
    if mutation == "missing":
        provider.services.pop()
    elif mutation == "duplicate":
        provider.services[1].endpoint = provider.services[0].endpoint
    elif mutation == "wrong_type":
        provider.services[0].service_type = "A2A"
    else:
        provider.services[0].endpoint = "https://example.com/scan"

    with pytest.raises(RuntimeError):
        build_hire_catalog(snapshot)


def test_hire_page_is_task_first_and_contains_no_stale_service_ids():
    page = (ROOT / "site" / "hire.html").read_text(encoding="utf-8")

    assert "data-hire-service" in page
    assert "data-accepts-output" in page
    assert "data-shell" in page
    assert "data-verdict-confirmed" in page
    assert all(f'data-command-step="{step}"' in page for step in range(1, 5))
    assert "task flow" in page.lower()
    assert "18954" not in page
    assert "18955" not in page
    assert "data-purchase-summary" in page
    assert "data-hire-advanced" in page
    normalized_page = " ".join(page.lower().split())
    assert "never receives wallet credentials or signing material" in normalized_page


SERVICE_LIST_OUTPUT = json.dumps(
    {
        "ok": True,
        "data": [
            {
                "agentInfo": {"agentId": "3808", "name": "Warden"},
                "list": [
                    {
                        "id": 33460,
                        "serviceId": "c2783b5b-a932-4249-b0e2-4ccc6245fd63",
                        "serviceName": "Payload Security Scan",
                        "serviceDescription": "Scan an untrusted payload.",
                        "serviceType": "A2MCP",
                        "endpoint": "https://warden.gudman.xyz/scan",
                        "fee": "0.1",
                        "contractAddress": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
                    },
                    {
                        "id": 33461,
                        "serviceId": "dc289c2e-e280-4786-95d0-0c5dc7ac6cfc",
                        "serviceName": "Agent Endpoint Security Audit",
                        "serviceDescription": "Audit an agent endpoint.",
                        "serviceType": "A2MCP",
                        "endpoint": "https://warden.gudman.xyz/audit",
                        "fee": "0.1",
                        "contractAddress": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
                    },
                    {
                        "id": 35484,
                        "serviceId": "b04a04c0-442c-4cfc-ab64-cb914c64cbb7",
                        "serviceName": "Escrow Payload Security Scan",
                        "serviceDescription": "Escrowed scan.",
                        "serviceType": "A2A",
                        "endpoint": None,
                        "fee": None,
                        "contractAddress": None,
                    },
                ],
            }
        ],
    }
)


def test_provider_fetch_reads_the_listing_the_search_index_omits():
    # `agent search` drops an agent whose listing is under review, so the census cannot
    # describe our own services in that window; `service-list` still answers.
    agent = fetch_provider_agent("3808", command_runner=lambda command: SERVICE_LIST_OUTPUT)

    assert [service.service_id for service in agent.services] == ["33460", "33461", "35484"]
    # The CLI reports `id` as a JSON number and a null endpoint on the A2A row.
    assert all(isinstance(service.service_id, str) for service in agent.services)
    assert agent.services[2].endpoint == ""

    catalog = build_hire_catalog_from_agent(agent, "2026-07-25T14:00:00Z")

    assert catalog["snapshotFetchedAt"] == "2026-07-25T14:00:00Z"
    assert catalog["providerAgentId"] == "3808"
    assert [service["key"] for service in catalog["services"]] == ["scan", "audit"]
    assert [service["feeAmount"] for service in catalog["services"]] == ["0.1", "0.1"]
    assert [service["serviceId"] for service in catalog["services"]] == ["33460", "33461"]


def test_provider_catalog_rejects_a_mismatched_agent():
    agent = fetch_provider_agent("3808", command_runner=lambda command: SERVICE_LIST_OUTPUT)

    with pytest.raises(RuntimeError, match="Expected agent #4444"):
        build_hire_catalog_from_agent(agent, "2026-07-25T14:00:00Z", provider_agent_id="4444")
