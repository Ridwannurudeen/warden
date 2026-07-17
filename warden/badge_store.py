"""Persistent store for issued badge payloads."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

_STORE_PATH = Path(__file__).resolve().parents[1] / "badges" / "issued.jsonl"
_LOCK = Lock()


@contextmanager
def _exclusive_store_lock() -> Iterator[None]:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_path = _STORE_PATH.with_name(f".{_STORE_PATH.name}.lock")
    with _LOCK, lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
    record = json.dumps(badge, ensure_ascii=False, sort_keys=True)
    with _exclusive_store_lock():
        for existing in _read_records(_STORE_PATH):
            if existing.get("audit_id") != badge.get("audit_id"):
                continue
            if existing == badge:
                return
            raise ValueError("badge audit_id conflicts with an existing record")
        with _STORE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(record + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def get_badge(audit_id: str) -> dict[str, object] | None:
    with _exclusive_store_lock():
        records = _read_records(_STORE_PATH)
    for record in reversed(records):
        if str(record.get("audit_id")) == audit_id:
            return record
    return None


def list_badges(store_path: Path | None = None) -> list[dict[str, object]]:
    path = store_path or _STORE_PATH
    with _exclusive_store_lock():
        records = _read_records(path)

    return sorted(records, key=lambda record: str(record.get("issued_at", "")), reverse=True)
