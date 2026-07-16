"""Persistent store for issued badge payloads."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

_STORE_PATH = Path(__file__).resolve().parents[1] / "badges" / "issued.jsonl"
_LOCK = Lock()


def _ensure_store() -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)


def record_badge(badge: dict[str, object]) -> None:
    _ensure_store()
    record = json.dumps(badge, ensure_ascii=False, sort_keys=True)
    with _LOCK:
        if _STORE_PATH.exists():
            with _STORE_PATH.open(encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    existing = json.loads(line)
                    if existing.get("audit_id") != badge.get("audit_id"):
                        continue
                    if existing == badge:
                        return
                    raise ValueError("badge audit_id conflicts with an existing record")
        with _STORE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(record + "\n")


def get_badge(audit_id: str) -> dict[str, object] | None:
    if not _STORE_PATH.exists():
        return None
    with _LOCK:
        with _STORE_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if str(record.get("audit_id")) == audit_id:
                    return record
    return None


def list_badges(store_path: Path | None = None) -> list[dict[str, object]]:
    path = store_path or _STORE_PATH
    with _LOCK:
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]

    return sorted(records, key=lambda record: str(record.get("issued_at", "")), reverse=True)
