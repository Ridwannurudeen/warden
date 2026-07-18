"""Persistent store for issued badge payloads."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from uuid import uuid4

_STORE_PATH = Path(__file__).resolve().parents[1] / "badges" / "issued.jsonl"
_LOCK = Lock()
_MAX_RECORDS = 5_000


@contextmanager
def _exclusive_store_lock(store_path: Path = _STORE_PATH) -> Iterator[None]:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store_path.with_name(f".{store_path.name}.lock")
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


def _write_records(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _retained_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return records[-_MAX_RECORDS:]


def record_badge(badge: dict[str, object]) -> None:
    versioned = badge.get("badge_version") == 2
    if versioned:
        from warden.badges import verify_badge

        if not verify_badge(badge):
            raise ValueError("versioned audit badge failed integrity verification")
    already_stored = False
    with _exclusive_store_lock(_STORE_PATH):
        records = _read_records(_STORE_PATH)
        for existing in records:
            if existing.get("audit_id") != badge.get("audit_id"):
                continue
            if existing == badge:
                already_stored = True
                break
            raise ValueError("badge audit_id conflicts with an existing record")
        if not already_stored:
            records.append(badge)
        retained = _retained_records(records)
        if not already_stored or retained != records:
            _write_records(_STORE_PATH, retained)
    if versioned:
        from warden import audit_attestations

        audit_attestations.publish_from_badge(badge)


def get_badge(audit_id: str) -> dict[str, object] | None:
    with _exclusive_store_lock(_STORE_PATH):
        records = _read_records(_STORE_PATH)
    for record in reversed(records):
        if str(record.get("audit_id")) == audit_id:
            return record
    return None


def list_badges(store_path: Path | None = None) -> list[dict[str, object]]:
    path = store_path or _STORE_PATH
    with _exclusive_store_lock(path):
        records = _read_records(path)

    return sorted(records, key=lambda record: str(record.get("issued_at", "")), reverse=True)
