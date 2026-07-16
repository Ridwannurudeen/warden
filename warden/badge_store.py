"""Persistent store for issued badge payloads."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

_STORE_PATH = Path(__file__).resolve().parents[1] / "badges" / "issued.jsonl"
_LOCK = Lock()


def _ensure_store() -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)


def _read_records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def record_badge(badge: dict[str, object]) -> None:
    _ensure_store()
    record = json.dumps(badge, ensure_ascii=False, sort_keys=True)
    with _LOCK:
        for existing in _read_records(_STORE_PATH):
            if existing.get("audit_id") != badge.get("audit_id"):
                continue
            if existing == badge:
                return
            raise ValueError("badge audit_id conflicts with an existing record")
        with _STORE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(record + "\n")


def get_badge(audit_id: str) -> dict[str, object] | None:
    with _LOCK:
        records = _read_records(_STORE_PATH)
    for record in reversed(records):
        if str(record.get("audit_id")) == audit_id:
            return record
    return None


def list_badges(store_path: Path | None = None) -> list[dict[str, object]]:
    path = store_path or _STORE_PATH
    with _LOCK:
        records = _read_records(path)

    return sorted(records, key=lambda record: str(record.get("issued_at", "")), reverse=True)
