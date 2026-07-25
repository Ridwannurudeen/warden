"""Per-class endpoint-audit outcomes retained for targeted hardening packs."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def _configured_store_path() -> Path:
    configured = os.getenv("WARDEN_AUDIT_FINDINGS_STORE", "").strip()
    return Path(configured) if configured else ROOT / "data" / "audit-findings" / "findings.jsonl"


_STORE_PATH = _configured_store_path()
_LOCK = Lock()
_MAX_RECORDS = 5_000
_AUDIT_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_ATTACK_CLASS_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


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


def _normalized_findings(findings: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Validate per-class counts and drop everything that is not a count.

    Probe payload text is deliberately excluded: the battery is already public
    in `audit/`, so retaining what was sent per target would add an exposure
    surface without adding evidence.
    """
    if not findings:
        raise ValueError("audit findings must not be empty")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for finding in findings:
        attack_class = finding.get("attack_class")
        total = finding.get("total")
        blocked = finding.get("blocked")
        if not isinstance(attack_class, str) or not _ATTACK_CLASS_RE.fullmatch(attack_class):
            raise ValueError("audit finding has an invalid attack_class")
        if attack_class in seen:
            raise ValueError(f"audit findings contain duplicate class {attack_class}")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or not isinstance(blocked, int)
            or isinstance(blocked, bool)
            or total < 1
            or blocked < 0
            or blocked > total
        ):
            raise ValueError(f"audit finding for {attack_class} has invalid counts")
        seen.add(attack_class)
        normalized.append(
            {
                "attack_class": attack_class,
                "total": total,
                "blocked": blocked,
                "missed": total - blocked,
            }
        )
    normalized.sort(key=lambda finding: str(finding["attack_class"]))
    return normalized


def record_findings(
    audit_id: str,
    target_host: str,
    findings: Sequence[Mapping[str, object]],
    *,
    battery_id: str,
    battery_version: str,
    observed_on: str,
) -> dict[str, object]:
    """Retain per-class outcomes for one conclusive, consented audit.

    The audit id is stable for an identical audit result, so re-recording the
    same outcome is idempotent. A different outcome under an existing audit id
    is a conflict and is rejected rather than silently overwritten.
    """
    if not _AUDIT_ID_RE.fullmatch(audit_id):
        raise ValueError("audit_id must be 16 lowercase hex characters")
    host = target_host.strip()
    if not host:
        raise ValueError("target_host must not be blank")
    record: dict[str, object] = {
        "schema_version": 1,
        "audit_id": audit_id,
        "target_host": host,
        "battery_id": battery_id,
        "battery_version": battery_version,
        "observed_on": observed_on,
        "findings": _normalized_findings(findings),
    }
    with _exclusive_store_lock(_STORE_PATH):
        records = _read_records(_STORE_PATH)
        already_stored = False
        for existing in records:
            if existing.get("audit_id") != audit_id:
                continue
            if existing == record:
                already_stored = True
                break
            raise ValueError("audit findings conflict with an existing record")
        if not already_stored:
            records.append(record)
        retained = _retained_records(records)
        if not already_stored or retained != records:
            _write_records(_STORE_PATH, retained)
    return record


def get_findings(audit_id: str) -> dict[str, object] | None:
    if not _AUDIT_ID_RE.fullmatch(audit_id):
        return None
    with _exclusive_store_lock(_STORE_PATH):
        records = _read_records(_STORE_PATH)
    for record in reversed(records):
        if str(record.get("audit_id")) == audit_id:
            return record
    return None
