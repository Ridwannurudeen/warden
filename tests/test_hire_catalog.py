"""Hire catalog and page contract tests."""

from pathlib import Path

import pytest

from warden.marketplace.catalog import build_hire_catalog
from warden.marketplace.fetch import load_snapshot


ROOT = Path(__file__).resolve().parents[1]


def test_hire_catalog_is_derived_from_marketplace_snapshot():
    snapshot = load_snapshot(ROOT / "data" / "marketplace" / "agents-v1.jsonl")

    catalog = build_hire_catalog(snapshot)

    assert catalog["providerAgentId"] == "3808"
    assert catalog["schemaVersion"] == 1
    assert catalog["snapshotFetchedAt"] == "2026-07-16T02:47:26Z"
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
    assert "private key" not in page.lower()
