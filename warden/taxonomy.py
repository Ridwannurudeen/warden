"""Deterministic access to Warden's versioned external-taxonomy map."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_MAP_PATH = ROOT / "spec" / "taxonomy-map-v1.json"


def _load_map() -> dict[str, object]:
    taxonomy_map = json.loads(TAXONOMY_MAP_PATH.read_text(encoding="utf-8"))
    if taxonomy_map.get("schema_version") != 1:
        raise ValueError("unsupported taxonomy map schema")
    return taxonomy_map


TAXONOMY_MAP = _load_map()


def _mapped_ids(mappings: Mapping[str, object]) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for taxonomy in sorted(mappings):
        mapping = mappings[taxonomy]
        if not isinstance(mapping, Mapping):
            raise ValueError("taxonomy mapping is malformed")
        ids = mapping.get("ids")
        if ids is None:
            resolved[taxonomy] = []
        elif isinstance(ids, list) and all(isinstance(value, str) for value in ids):
            resolved[taxonomy] = list(ids)
        else:
            raise ValueError("taxonomy mapping ids are malformed")
    return resolved


def mappings_for_reason_code(reason_code: str) -> dict[str, list[str]]:
    reason_codes = TAXONOMY_MAP.get("reason_codes")
    if not isinstance(reason_codes, Mapping):
        raise ValueError("taxonomy reason-code map is malformed")
    entry = reason_codes.get(reason_code)
    if entry is None:
        return {}
    if not isinstance(entry, Mapping) or not isinstance(entry.get("mappings"), Mapping):
        raise ValueError(f"taxonomy mapping is malformed for {reason_code}")
    return _mapped_ids(entry["mappings"])


def mappings_for_probe(probe_id: str, reason_code: str) -> dict[str, list[str]]:
    probes = TAXONOMY_MAP.get("probes")
    if not isinstance(probes, Mapping):
        raise ValueError("taxonomy probe map is malformed")
    probe = probes.get(probe_id)
    if probe is None:
        return mappings_for_reason_code(reason_code)
    if not isinstance(probe, Mapping) or probe.get("category") != reason_code:
        raise ValueError(f"taxonomy probe category does not match {probe_id}")
    mappings = probe.get("mappings")
    return (
        _mapped_ids(mappings)
        if isinstance(mappings, Mapping)
        else mappings_for_reason_code(reason_code)
    )
