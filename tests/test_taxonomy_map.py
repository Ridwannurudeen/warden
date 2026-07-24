"""Contracts for the Warden-to-external threat taxonomy map."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from warden.auditor import (
    AUDIT_BATTERY_PATH,
    AUDIT_BATTERY_SHA256,
    AUDIT_BATTERY_SIZE,
    AgentAuditor,
    AuditOutcome,
)
from warden.core.verdict import SCANNER_CATEGORY_REASON_CODES, ReasonCode
from warden.hardening import build_pack
from warden.taxonomy import mappings_for_probe, mappings_for_reason_code


ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "spec" / "taxonomy-map-v1.json"

TAXONOMY_MAP = json.loads(MAP_PATH.read_text(encoding="utf-8"))
BATTERY = json.loads(AUDIT_BATTERY_PATH.read_text(encoding="utf-8"))

TAXONOMIES = TAXONOMY_MAP["taxonomies"]
REASON_CODES = TAXONOMY_MAP["reason_codes"]
PROBES = TAXONOMY_MAP["probes"]

ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _resolved_mappings(probe: dict) -> dict:
    return probe.get("mappings") or REASON_CODES[probe["category"]]["mappings"]


def _all_mapping_entries() -> list[tuple[str, str, dict]]:
    entries: list[tuple[str, str, dict]] = []
    for name, entry in REASON_CODES.items():
        for taxonomy, mapping in entry["mappings"].items():
            entries.append((f"reason_code {name}", taxonomy, mapping))
    for probe_id, probe in PROBES.items():
        for taxonomy, mapping in _resolved_mappings(probe).items():
            entries.append((f"probe {probe_id}", taxonomy, mapping))
    return entries


def _prose() -> list[str]:
    collected: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(TAXONOMY_MAP)
    return collected


def test_map_is_schema_versioned_and_pinned_to_the_immutable_battery() -> None:
    assert TAXONOMY_MAP["map_id"] == "warden-taxonomy-map"
    assert TAXONOMY_MAP["schema_version"] == 1
    assert TAXONOMY_MAP["version"] == "v1"
    assert TAXONOMY_MAP["status"] == "public-draft"

    sources = TAXONOMY_MAP["warden_sources"]
    assert sources["reason_codes"] == "warden/core/verdict.py"
    assert sources["battery_id"] == BATTERY["battery_id"]
    assert sources["battery_version"] == BATTERY["version"]
    assert sources["battery_sha256"] == AUDIT_BATTERY_SHA256


def test_every_external_taxonomy_cites_a_source_url_and_a_retrieval_date() -> None:
    assert set(TAXONOMIES) == {"OWASP-ASI-2026", "OWASP-LLM-2025", "OWASP-MCP-2025"}

    for name, taxonomy in TAXONOMIES.items():
        assert taxonomy["title"], name
        assert taxonomy["publisher"], name
        assert taxonomy["source_url"].startswith("https://"), name
        assert taxonomy["document_url"].startswith("https://"), name
        assert ISO_DATE.match(taxonomy["retrieved_on"]), name
        assert taxonomy["attribution"], name

        pattern = re.compile(taxonomy["id_pattern"])
        categories = taxonomy["categories"]
        assert len(categories) == 10, name
        for category_id, title in categories.items():
            assert pattern.match(category_id), f"{name} {category_id}"
            assert title.strip(), f"{name} {category_id}"

    assert TAXONOMIES["OWASP-MCP-2025"]["license"] == "CC BY-NC-SA 4.0"


def test_every_reason_code_has_an_entry() -> None:
    assert set(REASON_CODES) == {reason.value for reason in ReasonCode}

    scanner_codes = {reason.value for reason in SCANNER_CATEGORY_REASON_CODES.values()}
    assert scanner_codes <= set(REASON_CODES)

    for name, entry in REASON_CODES.items():
        assert entry["description"].strip(), name
        assert set(entry["mappings"]) == set(TAXONOMIES), name


def test_every_battery_probe_and_probe_category_has_an_entry() -> None:
    battery_probes = {probe["id"]: probe["category"] for probe in BATTERY["probes"]}
    assert len(battery_probes) == AUDIT_BATTERY_SIZE == 20
    assert set(PROBES) == set(battery_probes)

    for probe_id, category in battery_probes.items():
        assert PROBES[probe_id]["category"] == category
        assert category in REASON_CODES
        assert set(_resolved_mappings(PROBES[probe_id])) == set(TAXONOMIES)

    assert {probe["category"] for probe in BATTERY["probes"]} <= set(REASON_CODES)


def test_no_entry_silently_defaults_to_a_real_category() -> None:
    for label, taxonomy, mapping in _all_mapping_entries():
        where = f"{label} / {taxonomy}"
        assert set(mapping) <= {"ids", "rationale", "unmapped_reason"}, where
        ids = mapping["ids"]

        if ids is None:
            assert "rationale" not in mapping, where
            continue

        assert isinstance(ids, list) and ids, where
        assert ids == sorted(set(ids)), where
        assert "unmapped_reason" not in mapping, where
        assert mapping["rationale"].strip(), where
        for category_id in ids:
            assert category_id in TAXONOMIES[taxonomy]["categories"], f"{where} {category_id}"


def test_unmapped_entries_carry_an_explicit_reason() -> None:
    unmapped = [
        (label, taxonomy, mapping)
        for label, taxonomy, mapping in _all_mapping_entries()
        if mapping["ids"] is None
    ]
    assert unmapped, "the map must record at least one honest non-mapping"

    for label, taxonomy, mapping in unmapped:
        reason = mapping["unmapped_reason"]
        assert isinstance(reason, str)
        assert len(reason.split()) >= 10, f"{label} / {taxonomy}"

    detector_provenance_codes = {"STATISTICAL_ANOMALY", "CORPUS_MATCH"}
    for name in detector_provenance_codes:
        for taxonomy, mapping in REASON_CODES[name]["mappings"].items():
            assert mapping["ids"] is None, f"{name} / {taxonomy}"


def test_a_probe_override_must_differ_from_its_category_and_justify_itself() -> None:
    for probe_id, probe in PROBES.items():
        override = probe.get("mappings")
        if override is None:
            continue

        inherited = REASON_CODES[probe["category"]]["mappings"]
        assert override != inherited, probe_id
        for taxonomy, mapping in override.items():
            justification = mapping.get("rationale") or mapping.get("unmapped_reason")
            assert justification and justification.strip(), f"{probe_id} / {taxonomy}"


def test_every_declared_taxonomy_is_actually_used() -> None:
    used = {
        taxonomy for _, taxonomy, mapping in _all_mapping_entries() if mapping["ids"] is not None
    }
    assert used == set(TAXONOMIES)


def test_wording_never_claims_certification_or_accredited_assessment() -> None:
    statement = TAXONOMY_MAP["evidence_statement"]

    assert "tested against OWASP ASI 2026 categories" in statement
    assert "It is not an OWASP assessment" in statement
    assert "it is not certification" in statement
    assert "not an accredited or Notified-Body assessment" in statement
    assert "point-in-time" in statement
    assert "does not mean the category is exhaustively tested" in TAXONOMY_MAP["coverage_semantics"]

    banned = (
        "owasp certified",
        "owasp-certified",
        "certified safe",
        "guaranteed safe",
        "guarantees safety",
        "fully compliant",
        "compliance certificate",
        "conformity assessment body",
        "notified body assessment of",
    )
    for text in _prose():
        lowered = text.lower()
        for phrase in banned:
            assert phrase not in lowered, f"{phrase!r} in {text!r}"


def test_runtime_reason_code_mapping_matches_the_versioned_data() -> None:
    assert mappings_for_reason_code("SECRET_EXFIL") == {
        "OWASP-ASI-2026": ["ASI01", "ASI03"],
        "OWASP-LLM-2025": ["LLM02:2025"],
        "OWASP-MCP-2025": ["MCP01:2025"],
    }
    assert mappings_for_reason_code("STATISTICAL_ANOMALY") == {
        "OWASP-ASI-2026": [],
        "OWASP-LLM-2025": [],
        "OWASP-MCP-2025": [],
    }
    assert mappings_for_reason_code("CUSTOM") == {}


def test_runtime_probe_mapping_honors_the_explicit_override() -> None:
    assert mappings_for_probe("audit-v1-020", "CORPUS_MATCH") == {
        "OWASP-ASI-2026": ["ASI01"],
        "OWASP-LLM-2025": ["LLM01:2025"],
        "OWASP-MCP-2025": ["MCP06:2025"],
    }
    assert mappings_for_probe("custom-001", "CUSTOM") == {}


@pytest.mark.asyncio
async def test_audit_result_surfaces_probe_specific_taxonomy_ids(monkeypatch) -> None:
    auditor = AgentAuditor()

    async def blocked(*args, **kwargs):
        return AuditOutcome.BLOCKED

    monkeypatch.setattr(auditor, "_target_outcome", blocked)
    results, outcomes = await auditor._run_battery(
        object(),
        "https://127.0.0.1/scan",
        "agent.example",
        "agent.example",
        [
            {
                "id": "audit-v1-020",
                "category": "CORPUS_MATCH",
                "payload": "fixed probe",
            }
        ],
    )

    assert outcomes == [AuditOutcome.BLOCKED]
    assert results[0].probe_id == "audit-v1-020"
    assert results[0].taxonomy_ids == {
        "OWASP-ASI-2026": ["ASI01"],
        "OWASP-LLM-2025": ["LLM01:2025"],
        "OWASP-MCP-2025": ["MCP06:2025"],
    }


def test_hardening_pack_surfaces_reason_code_taxonomy_ids() -> None:
    pack = build_pack(
        {
            "audit_id": "0123456789abcdef",
            "target_host": "agent.example",
            "battery_id": "warden-core-http",
            "battery_version": "2026-07",
            "observed_on": "2026-07-24",
            "findings": [
                {
                    "attack_class": "SECRET_EXFIL",
                    "total": 2,
                    "blocked": 1,
                    "missed": 1,
                }
            ],
        }
    )

    assert pack["remediation"][0]["taxonomy_ids"] == {
        "OWASP-ASI-2026": ["ASI01", "ASI03"],
        "OWASP-LLM-2025": ["LLM02:2025"],
        "OWASP-MCP-2025": ["MCP01:2025"],
    }
