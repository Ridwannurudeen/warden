"""SQLite persistence for signed passports and task safety receipts."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from warden import protection_store

_LOCK = protection_store._LOCK
_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_passports (
    passport_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revoked_at INTEGER,
    log_seq INTEGER,
    revocation_log_seq INTEGER
);
CREATE TABLE IF NOT EXISTS task_safety_receipts (
    receipt_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revoked_at INTEGER,
    log_seq INTEGER,
    revocation_log_seq INTEGER
);
CREATE TABLE IF NOT EXISTS action_policies (
    policy_id TEXT PRIMARY KEY,
    record_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revoked_at INTEGER,
    log_seq INTEGER,
    revocation_log_seq INTEGER
);
"""
_INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_passports_log_seq
    ON security_passports (log_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_passports_revocation_log_seq
    ON security_passports (revocation_log_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_safety_receipts_log_seq
    ON task_safety_receipts (log_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_task_safety_receipts_revocation_log_seq
    ON task_safety_receipts (revocation_log_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_action_policies_log_seq
    ON action_policies (log_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_action_policies_revocation_log_seq
    ON action_policies (revocation_log_seq);
"""
_EVIDENCE_TYPES = {
    "security_passports": "security-passport",
    "task_safety_receipts": "task-safety-receipt",
    "action_policies": "action-policy",
}


def _db_path() -> Path:
    return protection_store._db_path()


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    with protection_store._connect() as connection:
        connection.executescript(_SCHEMA)
        for table in _EVIDENCE_TYPES:
            columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "log_seq" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN log_seq INTEGER")
            if "revocation_log_seq" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN revocation_log_seq INTEGER")
        connection.executescript(_INDEXES)
        yield connection


def _events(record_type: str) -> tuple[str, str]:
    if record_type == "security-passport":
        return "security-passport-issued", "security-passport-revoked"
    if record_type == "task-safety-receipt":
        return "task-safety-receipt-issued", "task-safety-receipt-revoked"
    if record_type == "action-policy":
        return "action-policy-registered", "action-policy-revoked"
    raise ValueError("signed evidence record type is invalid")


def _load_record(
    serialized: object,
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    try:
        record = json.loads(serialized)
    except (json.JSONDecodeError, TypeError) as exc:
        raise protection_store.ProtectionStateConflict(
            "stored signed evidence contains invalid JSON"
        ) from exc
    if not isinstance(record, dict) or not validator(record):
        # Every other integrity failure in this module raises ProtectionStateConflict,
        # which callers catch and turn into a deliberate response. A bare ValueError
        # escaped every handler and surfaced as an unhandled 500.
        raise protection_store.ProtectionStateConflict("stored signed evidence failed verification")
    return record


def _verify_log_binding(
    connection: sqlite3.Connection,
    record: dict[str, object],
    *,
    record_type: str,
    status: object,
    revoked_at: object,
    log_seq: object,
    revocation_log_seq: object,
) -> None:
    _, entries, head_hash = protection_store._read_log_head(connection)
    protection_store._read_anchored_checkpoint(connection, len(entries), head_hash)
    issued_at = record.get("issued_at")
    issued_event, revoked_event = _events(record_type)
    if (
        type(issued_at) is not int
        or type(log_seq) is not int
        or not 1 <= log_seq <= len(entries)
        or not protection_store._signed_evidence_log_entry_matches(
            entries[log_seq - 1],
            record,
            log_seq,
            record_type=record_type,
            event=issued_event,
            timestamp=issued_at,
        )
    ):
        raise protection_store.ProtectionStateConflict(
            "stored signed evidence has no matching transparency-log entry"
        )
    if status == "active":
        if revoked_at is not None or revocation_log_seq is not None:
            raise protection_store.ProtectionStateConflict(
                "stored signed evidence has an invalid revocation binding"
            )
        return
    if (
        status != "revoked"
        or type(revoked_at) is not int
        or revoked_at < issued_at
        or type(revocation_log_seq) is not int
        or not 1 <= revocation_log_seq <= len(entries)
        or not protection_store._signed_evidence_log_entry_matches(
            entries[revocation_log_seq - 1],
            record,
            revocation_log_seq,
            record_type=record_type,
            event=revoked_event,
            timestamp=revoked_at,
        )
    ):
        raise protection_store.ProtectionStateConflict(
            "stored signed evidence has an invalid revocation binding"
        )


def _store(
    table: str,
    record: dict[str, object],
    *,
    record_id_field: str,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    if not validator(record):
        raise ValueError("signed evidence failed verification")
    record_id = record.get(record_id_field)
    if not isinstance(record_id, str) or not record_id:
        raise ValueError("signed evidence has no valid identifier")
    record_type = _EVIDENCE_TYPES[table]
    issued_at = record.get("issued_at")
    if type(issued_at) is not int:
        raise ValueError("signed evidence issued_at is invalid")
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            f"SELECT record_json, status, revoked_at, log_seq, revocation_log_seq "
            f"FROM {table} WHERE {record_id_field} = ?",
            (record_id,),
        ).fetchone()
        if row is not None:
            existing = _load_record(row[0], validator=validator)
            if existing != record:
                raise ValueError("evidence identifier is already bound to another record")
            if row[3] is None:
                issued_entry = protection_store._append_signed_evidence_log(
                    connection,
                    existing,
                    record_type=record_type,
                    event=_events(record_type)[0],
                    timestamp=issued_at,
                )
                revocation_log_seq = row[4]
                if row[1] == "revoked":
                    if type(row[2]) is not int:
                        raise protection_store.ProtectionStateConflict(
                            "stored signed evidence has an invalid revocation binding"
                        )
                    revoked_entry = protection_store._append_signed_evidence_log(
                        connection,
                        existing,
                        record_type=record_type,
                        event=_events(record_type)[1],
                        timestamp=row[2],
                    )
                    revocation_log_seq = revoked_entry["seq"]
                _verify_log_binding(
                    connection,
                    existing,
                    record_type=record_type,
                    status=row[1],
                    revoked_at=row[2],
                    log_seq=issued_entry["seq"],
                    revocation_log_seq=revocation_log_seq,
                )
                connection.execute(
                    f"UPDATE {table} SET log_seq = ?, revocation_log_seq = ? "
                    f"WHERE {record_id_field} = ?",
                    (issued_entry["seq"], revocation_log_seq, record_id),
                )
            else:
                _verify_log_binding(
                    connection,
                    existing,
                    record_type=record_type,
                    status=row[1],
                    revoked_at=row[2],
                    log_seq=row[3],
                    revocation_log_seq=row[4],
                )
            return {"record": existing, "status": row[1], "revoked_at": row[2]}
        entry = protection_store._append_signed_evidence_log(
            connection,
            record,
            record_type=record_type,
            event=_events(record_type)[0],
            timestamp=issued_at,
        )
        connection.execute(
            f"INSERT INTO {table} "
            f"({record_id_field}, record_json, status, revoked_at, log_seq, revocation_log_seq) "
            "VALUES (?, ?, 'active', NULL, ?, NULL)",
            (
                record_id,
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                entry["seq"],
            ),
        )
    return {"record": record, "status": "active", "revoked_at": None}


def _get(
    table: str,
    record_id: str,
    *,
    record_id_field: str,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    if not record_id or len(record_id) > 128:
        return None
    record_type = _EVIDENCE_TYPES[table]
    with _LOCK, _connect() as connection:
        row = connection.execute(
            f"SELECT record_json, status, revoked_at, log_seq, revocation_log_seq "
            f"FROM {table} WHERE {record_id_field} = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        record = _load_record(row[0], validator=validator)
        _verify_log_binding(
            connection,
            record,
            record_type=record_type,
            status=row[1],
            revoked_at=row[2],
            log_seq=row[3],
            revocation_log_seq=row[4],
        )
        return {"record": record, "status": row[1], "revoked_at": row[2]}


def _revoke(
    table: str,
    record_id: str,
    *,
    record_id_field: str,
    revoked_at: int,
    validator: Callable[[dict[str, object]], bool],
) -> int:
    if type(revoked_at) is not int or revoked_at < 0:
        raise ValueError("revocation time is invalid")
    record_type = _EVIDENCE_TYPES[table]
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            f"SELECT record_json, status, revoked_at, log_seq, revocation_log_seq "
            f"FROM {table} WHERE {record_id_field} = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise ValueError("signed evidence not found")
        record = _load_record(row[0], validator=validator)
        _verify_log_binding(
            connection,
            record,
            record_type=record_type,
            status=row[1],
            revoked_at=row[2],
            log_seq=row[3],
            revocation_log_seq=row[4],
        )
        if row[1] == "revoked":
            return int(row[2])
        if revoked_at < int(record["issued_at"]):
            raise ValueError("revocation cannot predate issuance")
        entry = protection_store._append_signed_evidence_log(
            connection,
            record,
            record_type=record_type,
            event=_events(record_type)[1],
            timestamp=revoked_at,
        )
        connection.execute(
            f"UPDATE {table} SET status = 'revoked', revoked_at = ?, "
            f"revocation_log_seq = ? WHERE {record_id_field} = ?",
            (revoked_at, entry["seq"], record_id),
        )
    return revoked_at


def store_security_passport(
    record: dict[str, object],
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    return _store(
        "security_passports",
        record,
        record_id_field="passport_id",
        validator=validator,
    )


def get_security_passport(
    passport_id: str,
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    return _get(
        "security_passports",
        passport_id,
        record_id_field="passport_id",
        validator=validator,
    )


def revoke_security_passport(
    passport_id: str,
    *,
    revoked_at: int,
    validator: Callable[[dict[str, object]], bool],
) -> int:
    return _revoke(
        "security_passports",
        passport_id,
        record_id_field="passport_id",
        revoked_at=revoked_at,
        validator=validator,
    )


def store_task_safety_receipt(
    record: dict[str, object],
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    return _store(
        "task_safety_receipts",
        record,
        record_id_field="receipt_id",
        validator=validator,
    )


def get_task_safety_receipt(
    receipt_id: str,
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    return _get(
        "task_safety_receipts",
        receipt_id,
        record_id_field="receipt_id",
        validator=validator,
    )


def revoke_task_safety_receipt(
    receipt_id: str,
    *,
    revoked_at: int,
    validator: Callable[[dict[str, object]], bool],
) -> int:
    return _revoke(
        "task_safety_receipts",
        receipt_id,
        record_id_field="receipt_id",
        revoked_at=revoked_at,
        validator=validator,
    )


def store_action_policy(
    record: dict[str, object],
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    return _store(
        "action_policies",
        record,
        record_id_field="policy_id",
        validator=validator,
    )


def get_action_policy(
    policy_id: str,
    *,
    validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    return _get(
        "action_policies",
        policy_id,
        record_id_field="policy_id",
        validator=validator,
    )


def revoke_action_policy(
    policy_id: str,
    *,
    revoked_at: int,
    validator: Callable[[dict[str, object]], bool],
) -> int:
    return _revoke(
        "action_policies",
        policy_id,
        record_id_field="policy_id",
        revoked_at=revoked_at,
        validator=validator,
    )


def action_policy_log_seq(policy_id: str) -> int | None:
    """The transparency-log sequence a policy was anchored at.

    A decision receipt cites this, because the sequence is what lets an
    adjudicator place the registration before the action in the hash chain.
    """
    if not policy_id or len(policy_id) > 128:
        return None
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT log_seq FROM action_policies WHERE policy_id = ?",
            (policy_id,),
        ).fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])
