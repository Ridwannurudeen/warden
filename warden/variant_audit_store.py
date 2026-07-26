"""Persistent store for signed adversarial variant audit reports.

Reports are retained so a buyer can fetch one back by `report_id` and so a
later run against the same host can be compared with an earlier one. Only the
signed record is kept: it already carries counts alone, never probe payloads or
response bodies, so retaining it adds no exposure the report itself did not.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
_LOCK = Lock()
_MAX_RECORDS = 5_000
_REPORT_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def _store_path() -> Path:
    """Resolve the store path per call so a test can repoint it with an env var.

    `audit_findings` binds its path at import time, which makes the store
    impossible to redirect once the module is loaded.
    """
    configured = os.getenv("WARDEN_VARIANT_AUDIT_STORE", "").strip()
    return Path(configured) if configured else ROOT / "data" / "variant-audits" / "reports.jsonl"


@contextmanager
def _exclusive_store_lock(store_path: Path) -> Iterator[None]:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = store_path.with_name(f".{store_path.name}.lock")
    # Matches `feedback_store` and `gauntlet_store`: refuse to read or write
    # through a symlink, so anything able to plant one in the data directory
    # cannot redirect a read to another file the service can reach.
    for path in (store_path, lock_path):
        if path.is_symlink():
            raise ValueError("variant audit store must not be a symlink")
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


def record_report(report: dict[str, object]) -> None:
    """Retain one signed report.

    The report id is the hash of the signed *content*, and `issued_at` is not
    part of that content, so auditing the same host twice with an unchanged
    result yields the same id under a later timestamp and a fresh signature.
    That is the same evidence, not a conflict: the first record is kept and the
    later one is a no-op. Two records sharing an id but disagreeing about what
    was measured cannot both be genuine, so that is still refused.
    """
    from warden.variant_audit import CONTENT_FIELDS, verify_report

    if not verify_report(report):
        raise ValueError("variant audit report failed signature verification")
    report_id = str(report["report_id"])
    content = {field: report[field] for field in CONTENT_FIELDS}
    path = _store_path()
    with _exclusive_store_lock(path):
        records = _read_records(path)
        already_stored = False
        for existing in records:
            if existing.get("report_id") != report_id:
                continue
            if {field: existing.get(field) for field in CONTENT_FIELDS} == content:
                already_stored = True
                break
            raise ValueError("variant audit report_id conflicts with an existing record")
        if not already_stored:
            records.append(report)
        retained = records[-_MAX_RECORDS:]
        if not already_stored or retained != records:
            _write_records(path, retained)


def get_report(report_id: str) -> dict[str, object] | None:
    """Look one report up by id.

    Only lines containing the id are parsed. This route is free, unauthenticated
    and synchronous on the event loop, so deserializing every retained report on
    every lookup made a full store a denial-of-service lever rather than merely
    a slow read. A 64-hex id is specific enough that the substring test is a
    prefilter, never the decision: the match is still confirmed after parsing.
    """
    if not _REPORT_ID_RE.fullmatch(report_id):
        return None
    path = _store_path()
    with _exclusive_store_lock(path):
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as handle:
            candidates = [line for line in handle if report_id in line]
    for line in reversed(candidates):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and str(record.get("report_id")) == report_id:
            return record
    return None
