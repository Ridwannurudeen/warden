"""SQLite store for APA protection state: TOFU bindings, nonces, attestations, log.

SQLite transactions serialize the API workers and the separate periodic re-probe
process. The transparency log is hash-chained (`prev_hash` = SHA-256 of the
previous entry's canonical bytes) per APA-SPEC §7.2.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

from warden.badges import _canonical_json, b64u_decode, b64u_encode

NONCE_TTL_SECONDS = 3600
GENESIS_PREV_HASH = "0" * 64
MAX_SAFE_UNIX_SECONDS = 9_007_199_254_740_991
LOG_CHECKPOINT_FIELDS = {
    "spec_version",
    "issuer",
    "seq",
    "head_hash",
    "issued_at",
    "issuer_sig",
}
APA_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "attestation_id",
    "endpoint_host",
    "status",
    "record_hash",
    "prev_hash",
}
BREAKER_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "certificate_id",
    "benchmark_case_id",
    "record_hash",
    "prev_hash",
}
AUDIT_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "audit_id",
    "endpoint_host",
    "record_hash",
    "prev_hash",
}
HARDENING_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "pack_id",
    "audit_id",
    "record_hash",
    "prev_hash",
}
SECURITY_PASSPORT_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "passport_id",
    "record_hash",
    "prev_hash",
}
TASK_SAFETY_RECEIPT_LOG_ENTRY_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "receipt_id",
    "record_hash",
    "prev_hash",
}
_SIGNED_EVIDENCE_LOG_SPECS = {
    "security-passport": (
        "passport_id",
        "security-passport-issued",
        "security-passport-revoked",
    ),
    "task-safety-receipt": (
        "receipt_id",
        "task-safety-receipt-issued",
        "task-safety-receipt-revoked",
    ),
}

_LOCK = Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bindings (
    endpoint_host TEXT PRIMARY KEY,
    pub TEXT NOT NULL,
    bound_at INTEGER NOT NULL,
    key_changed INTEGER NOT NULL DEFAULT 0,
    pending_replacement_pub TEXT
);
CREATE TABLE IF NOT EXISTS nonces (
    endpoint_host TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nonces_unique ON nonces (endpoint_host, nonce);
CREATE TABLE IF NOT EXISTS attestations (
    attestation_id TEXT PRIMARY KEY,
    endpoint_host TEXT NOT NULL,
    status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_probed_at INTEGER
);
CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_checkpoint (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    checkpoint_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_anchor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    checkpoint_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS breaker_certificates (
    certificate_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL UNIQUE,
    confirmed_at INTEGER NOT NULL,
    log_seq INTEGER NOT NULL UNIQUE,
    record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_attestations (
    audit_id TEXT PRIMARY KEY,
    issued_at INTEGER NOT NULL,
    log_seq INTEGER NOT NULL UNIQUE,
    record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_revocations (
    audit_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL,
    log_seq INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (audit_id) REFERENCES audit_attestations(audit_id)
);
CREATE TABLE IF NOT EXISTS hardening_packs (
    pack_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL UNIQUE,
    issued_at INTEGER NOT NULL,
    log_seq INTEGER NOT NULL UNIQUE,
    record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hardening_revocations (
    pack_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL,
    log_seq INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (pack_id) REFERENCES hardening_packs(pack_id)
);
CREATE TABLE IF NOT EXISTS probe_leases (
    lease_id TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""

PROBE_ADMISSION_DB_TIMEOUT_SECONDS = 0.5


class ProtectionStateConflict(ValueError):
    """The binding or attestation changed before an atomic write completed."""


class NonceReplay(ValueError):
    """A signed request reused a nonce within the replay window."""


class LogCheckpointMissing(RuntimeError):
    """The transparency log has no complete locally anchored signed head."""


class ProbeAdmissionStorageUnavailable(RuntimeError):
    """The shared outbound-probe admission store cannot be used safely."""


def _db_path() -> Path:
    configured = os.getenv("WARDEN_PROTECTION_DB") or os.getenv("WARDEN_EVIDENCE_DB")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "protection.db"


@contextmanager
def _connect(*, timeout_seconds: float = 5.0) -> Iterator[sqlite3.Connection]:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=timeout_seconds)
    try:
        connection.executescript(_SCHEMA)
        attestation_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(attestations)").fetchall()
        }
        binding_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(bindings)").fetchall()
        }
        if (
            "last_probed_at" not in attestation_columns
            or "pending_replacement_pub" not in binding_columns
        ):
            connection.execute("BEGIN IMMEDIATE")
            attestation_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(attestations)").fetchall()
            }
            if "last_probed_at" not in attestation_columns:
                connection.execute("ALTER TABLE attestations ADD COLUMN last_probed_at INTEGER")
            binding_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(bindings)").fetchall()
            }
            if "pending_replacement_pub" not in binding_columns:
                connection.execute("ALTER TABLE bindings ADD COLUMN pending_replacement_pub TEXT")
            connection.commit()
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def acquire_probe_lease(
    lease_id: str,
    *,
    now: float,
    ttl_seconds: float,
    max_leases: int,
) -> bool:
    """Atomically acquire one anonymous, expiring outbound-probe slot."""
    if not lease_id or ttl_seconds <= 0 or max_leases < 1:
        raise ValueError("probe lease arguments are invalid")
    try:
        with _LOCK, _connect(timeout_seconds=PROBE_ADMISSION_DB_TIMEOUT_SECONDS) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM probe_leases WHERE expires_at <= ?",
                (now,),
            )
            active = int(connection.execute("SELECT COUNT(*) FROM probe_leases").fetchone()[0])
            if active >= max_leases:
                return False
            connection.execute(
                "INSERT INTO probe_leases (lease_id, expires_at) VALUES (?, ?)",
                (lease_id, now + ttl_seconds),
            )
    except (OSError, sqlite3.Error) as exc:
        raise ProbeAdmissionStorageUnavailable(
            "shared probe admission storage is unavailable"
        ) from exc
    return True


def release_probe_lease(lease_id: str) -> None:
    """Release one shared outbound-probe slot; crash leftovers expire on acquire."""
    if not lease_id:
        raise ValueError("probe lease_id is required")
    try:
        with _LOCK, _connect(timeout_seconds=PROBE_ADMISSION_DB_TIMEOUT_SECONDS) as connection:
            connection.execute(
                "DELETE FROM probe_leases WHERE lease_id = ?",
                (lease_id,),
            )
    except (OSError, sqlite3.Error) as exc:
        raise ProbeAdmissionStorageUnavailable(
            "shared probe admission storage is unavailable"
        ) from exc


def get_binding(endpoint_host: str) -> dict[str, object] | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT endpoint_host, pub, bound_at, key_changed, pending_replacement_pub "
            "FROM bindings "
            "WHERE endpoint_host = ?",
            (endpoint_host,),
        ).fetchone()
    if row is None:
        return None
    return {
        "endpoint_host": row[0],
        "pub": row[1],
        "bound_at": row[2],
        "key_changed": bool(row[3]),
        "pending_replacement_pub": row[4],
    }


def _record_nonce(
    connection: sqlite3.Connection,
    endpoint_host: str,
    nonce: str,
    *,
    now: int | None = None,
) -> bool:
    seen_at = int(time.time()) if now is None else now
    connection.execute(
        "DELETE FROM nonces WHERE seen_at < ?",
        (seen_at - NONCE_TTL_SECONDS,),
    )
    try:
        connection.execute(
            "INSERT INTO nonces (endpoint_host, nonce, seen_at) VALUES (?, ?, ?)",
            (endpoint_host, nonce, seen_at),
        )
    except sqlite3.IntegrityError:
        return False
    return True


def record_nonce(endpoint_host: str, nonce: str) -> bool:
    """Record a heartbeat nonce; returns False on replay. TTL-evicts old nonces."""
    with _LOCK, _connect() as connection:
        return _record_nonce(connection, endpoint_host, nonce)


def _store_attestation(
    connection: sqlite3.Connection,
    record: dict[str, object],
    *,
    last_probed_at: int | None = None,
) -> None:
    verified_at = record.get("verified_at")
    initial_last_probed_at = (
        last_probed_at
        if last_probed_at is not None
        else verified_at
        if isinstance(verified_at, int)
        else None
    )
    connection.execute(
        "INSERT INTO attestations "
        "(attestation_id, endpoint_host, status, record_json, created_at, last_probed_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(attestation_id) DO UPDATE SET "
        "endpoint_host = excluded.endpoint_host, status = excluded.status, "
        "record_json = excluded.record_json, "
        "last_probed_at = CASE WHEN ? THEN excluded.last_probed_at "
        "ELSE attestations.last_probed_at END",
        (
            str(record["attestation_id"]),
            str(record["endpoint_host"]),
            str(record["status"]),
            _canonical_json(record),
            int(time.time()),
            initial_last_probed_at,
            last_probed_at is not None,
        ),
    )


def store_attestation(record: dict[str, object]) -> None:
    with _LOCK, _connect() as connection:
        _store_attestation(connection, record)


def get_attestation(attestation_id: str) -> dict[str, object] | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT record_json FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def get_active_attestations(endpoint_host: str) -> list[dict[str, object]]:
    with _LOCK, _connect() as connection:
        return _active_attestations(connection, endpoint_host)


def _active_attestations(
    connection: sqlite3.Connection,
    endpoint_host: str,
) -> list[dict[str, object]]:
    rows = connection.execute(
        "SELECT record_json FROM attestations "
        "WHERE endpoint_host = ? AND status = 'active' "
        "ORDER BY created_at, attestation_id",
        (endpoint_host,),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


def list_reprobe_targets() -> list[dict[str, object]]:
    """Return recoverable attestations with their bound key and probe metadata."""
    with _LOCK, _connect() as connection:
        rows = connection.execute(
            "SELECT a.record_json, a.endpoint_host, a.last_probed_at, b.pub "
            "FROM attestations AS a "
            "JOIN bindings AS b ON b.endpoint_host = a.endpoint_host "
            "WHERE a.status IN ('active', 'stale', 'invalid') AND b.key_changed = 0 "
            "ORDER BY a.last_probed_at IS NOT NULL, a.last_probed_at, "
            "a.endpoint_host, a.created_at, a.attestation_id"
        ).fetchall()
    return [
        {
            "record": json.loads(row[0]),
            "endpoint_host": row[1],
            "last_probed_at": row[2],
            "bound_pub": row[3],
        }
        for row in rows
    ]


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_valid_log_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    fields = set(entry)
    record_type = entry.get("record_type")
    if record_type == "breaker-certificate":
        if (
            fields != BREAKER_LOG_ENTRY_FIELDS
            or entry.get("event") != "breaker-confirmed"
            or not _is_lower_hex(entry.get("certificate_id"), 32)
        ):
            return False
        benchmark_case_id = entry.get("benchmark_case_id")
        if (
            not isinstance(benchmark_case_id, str)
            or not benchmark_case_id.startswith("gauntlet-")
            or not _is_lower_hex(benchmark_case_id.removeprefix("gauntlet-"), 16)
        ):
            return False
    elif record_type == "endpoint-audit-attestation":
        if (
            fields != AUDIT_LOG_ENTRY_FIELDS
            or entry.get("event") not in {"audit-issued", "audit-revoked"}
            or not _is_lower_hex(entry.get("audit_id"), 16)
            or not isinstance(entry.get("endpoint_host"), str)
            or not entry["endpoint_host"]
        ):
            return False
    elif record_type == "hardening-pack":
        if (
            fields != HARDENING_LOG_ENTRY_FIELDS
            or entry.get("event")
            not in {"hardening-pack-issued", "hardening-pack-revoked"}
            or not _is_lower_hex(entry.get("pack_id"), 64)
            or not _is_lower_hex(entry.get("audit_id"), 16)
        ):
            return False
    elif record_type == "security-passport":
        if (
            fields != SECURITY_PASSPORT_LOG_ENTRY_FIELDS
            or entry.get("event")
            not in {"security-passport-issued", "security-passport-revoked"}
            or not _is_lower_hex(entry.get("passport_id"), 64)
        ):
            return False
    elif record_type == "task-safety-receipt":
        if (
            fields != TASK_SAFETY_RECEIPT_LOG_ENTRY_FIELDS
            or entry.get("event")
            not in {"task-safety-receipt-issued", "task-safety-receipt-revoked"}
            or not _is_lower_hex(entry.get("receipt_id"), 64)
        ):
            return False
    elif record_type is not None:
        return False
    elif fields != APA_LOG_ENTRY_FIELDS or any(
        not isinstance(entry.get(field), str) or not entry[field]
        for field in ("event", "attestation_id", "endpoint_host", "status")
    ):
        return False
    return (
        type(entry.get("seq")) is int
        and 1 <= entry["seq"] <= MAX_SAFE_UNIX_SECONDS
        and type(entry.get("ts")) is int
        and 0 <= entry["ts"] <= MAX_SAFE_UNIX_SECONDS
        and _is_lower_hex(entry.get("record_hash"), 64)
        and _is_lower_hex(entry.get("prev_hash"), 64)
    )


def _verified_log_head(entries: list[dict[str, object]]) -> str | None:
    previous_hash = GENESIS_PREV_HASH
    for expected_seq, entry in enumerate(entries, start=1):
        if (
            not _is_valid_log_entry(entry)
            or entry["seq"] != expected_seq
        ):
            return None
        if entry.get("prev_hash") != previous_hash:
            return None
        previous_hash = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
    return previous_hash


def _read_log_head(
    connection: sqlite3.Connection,
) -> tuple[list[tuple[int, str]], list[dict[str, object]], str]:
    rows = connection.execute("SELECT seq, entry_json FROM log ORDER BY seq ASC").fetchall()
    try:
        entries = [json.loads(row[1]) for row in rows]
    except (json.JSONDecodeError, TypeError) as exc:
        raise ProtectionStateConflict("transparency log contains invalid JSON") from exc
    if not all(isinstance(entry, dict) for entry in entries):
        raise ProtectionStateConflict("transparency log contains a non-object entry")
    head_hash = _verified_log_head(entries)
    if head_hash is None or any(row[0] != index for index, row in enumerate(rows, start=1)):
        raise ProtectionStateConflict("transparency log chain is not contiguous")
    return rows, entries, head_hash


def _checkpoint_hash(checkpoint: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(checkpoint).encode("utf-8")).hexdigest()


def _is_exportable_log_checkpoint(checkpoint: dict[str, object]) -> bool:
    if set(checkpoint) != LOG_CHECKPOINT_FIELDS:
        return False
    if checkpoint.get("spec_version") != "apa-log/0.1" or checkpoint.get("issuer") != "warden":
        return False
    seq = checkpoint.get("seq")
    issued_at = checkpoint.get("issued_at")
    head_hash = checkpoint.get("head_hash")
    signature = checkpoint.get("issuer_sig")
    if type(seq) is not int or not 0 <= seq <= MAX_SAFE_UNIX_SECONDS:
        return False
    if type(issued_at) is not int or not 0 <= issued_at <= MAX_SAFE_UNIX_SECONDS:
        return False
    if (
        not isinstance(head_hash, str)
        or len(head_hash) != 64
        or any(character not in "0123456789abcdef" for character in head_hash)
    ):
        return False
    if not isinstance(signature, str) or not signature.startswith("sig:"):
        return False
    try:
        decoded = b64u_decode(signature)
    except ValueError:
        return False
    return len(decoded) == 64 and b64u_encode(decoded, "sig") == signature


def _write_log_anchor(
    connection: sqlite3.Connection,
    checkpoint: dict[str, object],
) -> None:
    # This rollback marker is deliberately separate from the mutable head row,
    # but remains local SQLite state. A coherent replacement of the whole
    # database still needs an external witness to detect it.
    connection.execute(
        "INSERT INTO log_anchor (singleton, checkpoint_hash) VALUES (1, ?) "
        "ON CONFLICT(singleton) DO UPDATE SET checkpoint_hash = excluded.checkpoint_hash",
        (_checkpoint_hash(checkpoint),),
    )


def _write_log_checkpoint(
    connection: sqlite3.Connection,
    seq: int,
    head_hash: str,
    issued_at: int,
) -> dict[str, object]:
    from warden import protection

    checkpoint = protection.issue_log_checkpoint(
        seq,
        head_hash,
        issued_at=issued_at,
    )
    connection.execute(
        "INSERT INTO log_checkpoint (singleton, checkpoint_json) VALUES (1, ?) "
        "ON CONFLICT(singleton) DO UPDATE SET checkpoint_json = excluded.checkpoint_json",
        (_canonical_json(checkpoint),),
    )
    _write_log_anchor(connection, checkpoint)
    return checkpoint


def _read_anchored_checkpoint(
    connection: sqlite3.Connection,
    entry_count: int,
    head_hash: str,
    *,
    verify_signature: bool = True,
) -> dict[str, object]:
    anchor_row = connection.execute(
        "SELECT checkpoint_hash FROM log_anchor WHERE singleton = 1"
    ).fetchone()
    if anchor_row is None:
        raise LogCheckpointMissing(
            "transparency log anchor is uninitialized; run explicit migration"
        )
    checkpoint_row = connection.execute(
        "SELECT checkpoint_json FROM log_checkpoint WHERE singleton = 1"
    ).fetchone()
    if checkpoint_row is None:
        raise LogCheckpointMissing(
            "locally anchored transparency checkpoint is missing; restore trusted state"
        )
    try:
        checkpoint = json.loads(checkpoint_row[0])
    except (json.JSONDecodeError, TypeError) as exc:
        raise ProtectionStateConflict("transparency log checkpoint contains invalid JSON") from exc
    if not isinstance(checkpoint, dict):
        raise ProtectionStateConflict("transparency log checkpoint is not an object")

    if (
        anchor_row[0] != _checkpoint_hash(checkpoint)
        or not _is_exportable_log_checkpoint(checkpoint)
        or checkpoint.get("seq") != entry_count
        or checkpoint.get("head_hash") != head_hash
    ):
        raise ProtectionStateConflict(
            "transparency log checkpoint does not match the locally anchored head"
        )
    if verify_signature:
        from warden import protection

        if not protection.verify_log_checkpoint(checkpoint):
            raise ProtectionStateConflict(
                "transparency log checkpoint does not match the locally anchored head"
            )
    return checkpoint


def _next_log_position(
    connection: sqlite3.Connection,
) -> tuple[int, str]:
    rows, entries, head_hash = _read_log_head(connection)
    anchor_exists = (
        connection.execute("SELECT 1 FROM log_anchor WHERE singleton = 1").fetchone()
        is not None
    )
    checkpoint_row = connection.execute(
        "SELECT 1 FROM log_checkpoint WHERE singleton = 1"
    ).fetchone()
    pristine = not rows and not anchor_exists and checkpoint_row is None
    if pristine:
        prior_sequence = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'log'"
        ).fetchone()
        if prior_sequence is not None:
            raise LogCheckpointMissing(
                "empty transparency log retains prior sequence state; restore trusted state"
            )
    else:
        _read_anchored_checkpoint(connection, len(entries), head_hash)
    return len(entries) + 1, head_hash


def _write_log_entry(
    connection: sqlite3.Connection,
    entry: dict[str, object],
) -> dict[str, object]:
    sequence = int(entry["seq"])
    serialized = _canonical_json(entry)
    connection.execute(
        "INSERT INTO log (seq, entry_json) VALUES (?, ?)",
        (sequence, serialized),
    )
    _write_log_checkpoint(
        connection,
        sequence,
        hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        int(entry["ts"]),
    )
    return entry


def _append_log(
    connection: sqlite3.Connection,
    event: str,
    record: dict[str, object],
) -> dict[str, object]:
    next_seq, prev_hash = _next_log_position(connection)
    entry = {
        "seq": next_seq,
        "ts": int(time.time()),
        "event": event,
        "attestation_id": record.get("attestation_id"),
        "endpoint_host": record.get("endpoint_host"),
        "status": record.get("status"),
        "record_hash": hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "prev_hash": prev_hash,
    }
    return _write_log_entry(connection, entry)


def _signed_evidence_log_entry_matches(
    entry: dict[str, object],
    record: dict[str, object],
    log_seq: int,
    *,
    record_type: str,
    event: str,
    timestamp: int,
) -> bool:
    spec = _SIGNED_EVIDENCE_LOG_SPECS.get(record_type)
    if spec is None:
        return False
    record_id_field, issued_event, revoked_event = spec
    if event not in {issued_event, revoked_event}:
        return False
    return entry == {
        "seq": log_seq,
        "ts": timestamp,
        "event": event,
        "record_type": record_type,
        record_id_field: record.get(record_id_field),
        "record_hash": hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "prev_hash": entry.get("prev_hash"),
    }


def _append_signed_evidence_log(
    connection: sqlite3.Connection,
    record: dict[str, object],
    *,
    record_type: str,
    event: str,
    timestamp: int,
) -> dict[str, object]:
    spec = _SIGNED_EVIDENCE_LOG_SPECS.get(record_type)
    if spec is None:
        raise ValueError("signed evidence record type is invalid")
    record_id_field, issued_event, revoked_event = spec
    if (
        event not in {issued_event, revoked_event}
        or type(timestamp) is not int
        or not 0 <= timestamp <= MAX_SAFE_UNIX_SECONDS
        or not _is_lower_hex(record.get(record_id_field), 64)
    ):
        raise ValueError("signed evidence log fields are invalid")
    next_seq, prev_hash = _next_log_position(connection)
    entry = {
        "seq": next_seq,
        "ts": timestamp,
        "event": event,
        "record_type": record_type,
        record_id_field: record[record_id_field],
        "record_hash": hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "prev_hash": prev_hash,
    }
    if not _is_valid_log_entry(entry):
        raise ValueError("signed evidence log entry is invalid")
    return _write_log_entry(connection, entry)


def commit_attestation_events(
    events: list[tuple[str, dict[str, object]]],
    *,
    new_binding: tuple[str, str] | None = None,
    key_changed_host: str | None = None,
) -> list[dict[str, object]]:
    """Store binding, attestations, and ordered log events in one transaction."""
    with _LOCK, _connect() as connection:
        if new_binding is not None:
            endpoint_host, pub = new_binding
            connection.execute(
                "INSERT INTO bindings (endpoint_host, pub, bound_at, key_changed) "
                "VALUES (?, ?, ?, 0)",
                (endpoint_host, pub, int(time.time())),
            )
        if key_changed_host is not None:
            connection.execute(
                "UPDATE bindings SET key_changed = 1 WHERE endpoint_host = ?",
                (key_changed_host,),
            )
        entries = []
        for event, record in events:
            _store_attestation(connection, record)
            entries.append(_append_log(connection, event, record))
    return entries


def _breaker_log_entry_matches(
    entry: dict[str, object],
    record: dict[str, object],
    log_seq: int,
) -> bool:
    return entry == {
        "seq": log_seq,
        "ts": record.get("confirmed_at"),
        "event": "breaker-confirmed",
        "record_type": "breaker-certificate",
        "certificate_id": record.get("certificate_id"),
        "benchmark_case_id": record.get("benchmark_case_id"),
        "record_hash": hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest(),
        "prev_hash": entry.get("prev_hash"),
    }


def commit_breaker_certificate(
    *,
    claim_id: str,
    record_factory: Callable[[int], dict[str, object]],
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    """Sign, store, and hash-chain one confirmed BREAKER in one transaction."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing_row = connection.execute(
            "SELECT record_json, log_seq FROM breaker_certificates WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if existing_row is not None:
            try:
                existing = json.loads(existing_row[0])
            except (json.JSONDecodeError, TypeError) as exc:
                raise ProtectionStateConflict(
                    "stored breaker certificate contains invalid JSON"
                ) from exc
            if not isinstance(existing, dict) or not record_validator(existing):
                raise ProtectionStateConflict("stored breaker certificate failed verification")
            _, entries, head_hash = _read_log_head(connection)
            _read_anchored_checkpoint(connection, len(entries), head_hash)
            log_seq = existing_row[1]
            if type(log_seq) is not int or not 1 <= log_seq <= len(entries):
                raise ProtectionStateConflict(
                    "stored breaker certificate has no matching log entry"
                )
            entry = entries[log_seq - 1]
            if not _breaker_log_entry_matches(entry, existing, log_seq):
                raise ProtectionStateConflict(
                    "stored breaker certificate has no matching log entry"
                )
            return existing

        next_seq, prev_hash = _next_log_position(connection)
        record = record_factory(next_seq)
        if not isinstance(record, dict) or not record_validator(record):
            raise ValueError("breaker certificate failed issuer verification")
        if record.get("log_seq") != next_seq:
            raise ValueError("breaker certificate log_seq does not match reserved position")
        entry = {
            "seq": next_seq,
            "ts": record["confirmed_at"],
            "event": "breaker-confirmed",
            "record_type": "breaker-certificate",
            "certificate_id": record["certificate_id"],
            "benchmark_case_id": record["benchmark_case_id"],
            "record_hash": hashlib.sha256(
                _canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "prev_hash": prev_hash,
        }
        connection.execute(
            "INSERT INTO breaker_certificates "
            "(certificate_id, claim_id, confirmed_at, log_seq, record_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(record["certificate_id"]),
                claim_id,
                int(record["confirmed_at"]),
                next_seq,
                _canonical_json(record),
            ),
        )
        _write_log_entry(connection, entry)
    return record


def get_breaker_certificate(certificate_id: str) -> dict[str, object] | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT record_json FROM breaker_certificates WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def get_breaker_certificates_with_evidence(
    certificate_ids: list[str],
) -> list[dict[str, object]]:
    """Return signed certificates only while their anchored log evidence is intact."""
    if not certificate_ids:
        return []
    with _LOCK, _connect() as connection:
        from warden import protection

        _, entries, head_hash = _read_log_head(connection)
        _read_anchored_checkpoint(connection, len(entries), head_hash)
        records = []
        for certificate_id in certificate_ids:
            row = connection.execute(
                "SELECT record_json, log_seq FROM breaker_certificates "
                "WHERE certificate_id = ?",
                (certificate_id,),
            ).fetchone()
            if row is None:
                continue
            try:
                record = json.loads(row[0])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(record, dict) or not protection.verify_breaker_certificate(
                record
            ):
                continue
            log_seq = row[1]
            if type(log_seq) is not int or not 1 <= log_seq <= len(entries):
                raise ProtectionStateConflict(
                    "breaker certificate has no matching transparency-log entry"
                )
            entry = entries[log_seq - 1]
            if (
                record.get("log_seq") != log_seq
                or not _breaker_log_entry_matches(entry, record, log_seq)
            ):
                raise ProtectionStateConflict(
                    "breaker certificate has no matching transparency-log entry"
                )
            records.append(record)
        return records


def get_breaker_certificate_with_evidence(
    certificate_id: str,
) -> dict[str, object] | None:
    records = get_breaker_certificates_with_evidence([certificate_id])
    return records[0] if records else None


def _audit_log_entry_matches(
    entry: dict[str, object],
    record: dict[str, object],
    log_seq: int,
    *,
    event: str,
    timestamp: int,
) -> bool:
    return entry == {
        "seq": log_seq,
        "ts": timestamp,
        "event": event,
        "record_type": "endpoint-audit-attestation",
        "audit_id": record.get("audit_id"),
        "endpoint_host": record.get("endpoint_host"),
        "record_hash": hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "prev_hash": entry.get("prev_hash"),
    }


def commit_audit_attestation(
    *,
    audit_id: str,
    record_factory: Callable[[int], dict[str, object]],
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    """Sign, store, and hash-chain one immutable endpoint-audit attestation."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing_row = connection.execute(
            "SELECT record_json, log_seq FROM audit_attestations WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if existing_row is not None:
            try:
                existing = json.loads(existing_row[0])
            except (json.JSONDecodeError, TypeError) as exc:
                raise ProtectionStateConflict(
                    "stored endpoint-audit attestation contains invalid JSON"
                ) from exc
            if not isinstance(existing, dict) or not record_validator(existing):
                raise ProtectionStateConflict(
                    "stored endpoint-audit attestation failed verification"
                )
            _, entries, head_hash = _read_log_head(connection)
            _read_anchored_checkpoint(connection, len(entries), head_hash)
            log_seq = existing_row[1]
            if (
                type(log_seq) is not int
                or not 1 <= log_seq <= len(entries)
                or existing.get("log_seq") != log_seq
                or not _audit_log_entry_matches(
                    entries[log_seq - 1],
                    existing,
                    log_seq,
                    event="audit-issued",
                    timestamp=int(existing["issued_at"]),
                )
            ):
                raise ProtectionStateConflict(
                    "stored endpoint-audit attestation has no matching log entry"
                )
            return existing

        next_seq, prev_hash = _next_log_position(connection)
        record = record_factory(next_seq)
        if (
            not isinstance(record, dict)
            or record.get("audit_id") != audit_id
            or record.get("log_seq") != next_seq
            or not record_validator(record)
        ):
            raise ValueError("endpoint-audit attestation failed issuer verification")
        issued_at = record.get("issued_at")
        if type(issued_at) is not int:
            raise ValueError("endpoint-audit attestation issued_at is invalid")
        entry = {
            "seq": next_seq,
            "ts": issued_at,
            "event": "audit-issued",
            "record_type": "endpoint-audit-attestation",
            "audit_id": audit_id,
            "endpoint_host": record["endpoint_host"],
            "record_hash": hashlib.sha256(
                _canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "prev_hash": prev_hash,
        }
        connection.execute(
            "INSERT INTO audit_attestations "
            "(audit_id, issued_at, log_seq, record_json) VALUES (?, ?, ?, ?)",
            (audit_id, issued_at, next_seq, _canonical_json(record)),
        )
        _write_log_entry(connection, entry)
    return record


def revoke_audit_attestation(
    audit_id: str,
    *,
    revoked_at: int,
    record_validator: Callable[[dict[str, object]], bool],
) -> int:
    """Append one issuer-checkpointed revocation event for an immutable audit record."""
    if type(revoked_at) is not int or not 0 <= revoked_at <= MAX_SAFE_UNIX_SECONDS:
        raise ValueError("endpoint-audit revocation time is invalid")
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT record_json, log_seq FROM audit_attestations WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if row is None:
            raise ValueError("endpoint-audit attestation not found")
        try:
            record = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProtectionStateConflict(
                "stored endpoint-audit attestation contains invalid JSON"
            ) from exc
        if not isinstance(record, dict) or not record_validator(record):
            raise ProtectionStateConflict(
                "stored endpoint-audit attestation failed verification"
            )
        if revoked_at < int(record["issued_at"]):
            raise ValueError("endpoint-audit revocation cannot predate issuance")
        existing = connection.execute(
            "SELECT revoked_at, log_seq FROM audit_revocations WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if existing is not None:
            _, entries, head_hash = _read_log_head(connection)
            _read_anchored_checkpoint(connection, len(entries), head_hash)
            existing_at, log_seq = existing
            if (
                type(existing_at) is not int
                or type(log_seq) is not int
                or not 1 <= log_seq <= len(entries)
                or not _audit_log_entry_matches(
                    entries[log_seq - 1],
                    record,
                    log_seq,
                    event="audit-revoked",
                    timestamp=existing_at,
                )
            ):
                raise ProtectionStateConflict(
                    "endpoint-audit revocation has no matching log entry"
                )
            return existing_at

        next_seq, prev_hash = _next_log_position(connection)
        entry = {
            "seq": next_seq,
            "ts": revoked_at,
            "event": "audit-revoked",
            "record_type": "endpoint-audit-attestation",
            "audit_id": audit_id,
            "endpoint_host": record["endpoint_host"],
            "record_hash": hashlib.sha256(
                _canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "prev_hash": prev_hash,
        }
        connection.execute(
            "INSERT INTO audit_revocations (audit_id, revoked_at, log_seq) "
            "VALUES (?, ?, ?)",
            (audit_id, revoked_at, next_seq),
        )
        _write_log_entry(connection, entry)
    return revoked_at


def get_audit_attestation_with_evidence(
    audit_id: str,
    *,
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    """Return an audit record only while its issuance/revocation log evidence is intact."""
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT record_json, log_seq FROM audit_attestations WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            record = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProtectionStateConflict(
                "stored endpoint-audit attestation contains invalid JSON"
            ) from exc
        if not isinstance(record, dict) or not record_validator(record):
            raise ProtectionStateConflict(
                "stored endpoint-audit attestation failed verification"
            )
        _, entries, head_hash = _read_log_head(connection)
        _read_anchored_checkpoint(connection, len(entries), head_hash)
        issued_seq = row[1]
        if (
            type(issued_seq) is not int
            or not 1 <= issued_seq <= len(entries)
            or record.get("log_seq") != issued_seq
            or not _audit_log_entry_matches(
                entries[issued_seq - 1],
                record,
                issued_seq,
                event="audit-issued",
                timestamp=int(record["issued_at"]),
            )
        ):
            raise ProtectionStateConflict(
                "stored endpoint-audit attestation has no matching log entry"
            )
        revoked = connection.execute(
            "SELECT revoked_at, log_seq FROM audit_revocations WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if revoked is None:
            return {
                "attestation": record,
                "status": "active",
                "revoked_at": None,
            }
        revoked_at, revoked_seq = revoked
        if (
            type(revoked_at) is not int
            or type(revoked_seq) is not int
            or not 1 <= revoked_seq <= len(entries)
            or not _audit_log_entry_matches(
                entries[revoked_seq - 1],
                record,
                revoked_seq,
                event="audit-revoked",
                timestamp=revoked_at,
            )
        ):
            raise ProtectionStateConflict(
                "endpoint-audit revocation has no matching log entry"
            )
        return {
            "attestation": record,
            "status": "revoked",
            "revoked_at": revoked_at,
        }


def _hardening_log_entry_matches(
    entry: dict[str, object],
    record: dict[str, object],
    log_seq: int,
    *,
    event: str = "hardening-pack-issued",
    timestamp: int | None = None,
) -> bool:
    return entry == {
        "seq": log_seq,
        "ts": record.get("issued_at") if timestamp is None else timestamp,
        "event": event,
        "record_type": "hardening-pack",
        "pack_id": record.get("pack_id"),
        "audit_id": record.get("audit_id"),
        "record_hash": hashlib.sha256(
            _canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "prev_hash": entry.get("prev_hash"),
    }


def commit_hardening_pack(
    *,
    pack_id: str,
    audit_id: str,
    record_factory: Callable[[int], dict[str, object]],
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object]:
    """Sign, store, and hash-chain one immutable hardening pack atomically."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing_row = connection.execute(
            "SELECT record_json, log_seq, pack_id FROM hardening_packs WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        if existing_row is not None:
            try:
                existing = json.loads(existing_row[0])
            except (json.JSONDecodeError, TypeError) as exc:
                raise ProtectionStateConflict(
                    "stored hardening pack contains invalid JSON"
                ) from exc
            if (
                not isinstance(existing, dict)
                or existing.get("audit_id") != audit_id
                or existing.get("pack_id") != existing_row[2]
                or not record_validator(existing)
            ):
                raise ProtectionStateConflict("stored hardening pack failed verification")
            _, entries, head_hash = _read_log_head(connection)
            _read_anchored_checkpoint(connection, len(entries), head_hash)
            log_seq = existing_row[1]
            if (
                type(log_seq) is not int
                or not 1 <= log_seq <= len(entries)
                or existing.get("log_seq") != log_seq
                or not _hardening_log_entry_matches(
                    entries[log_seq - 1],
                    existing,
                    log_seq,
                )
            ):
                raise ProtectionStateConflict(
                    "stored hardening pack has no matching log entry"
                )
            return existing

        next_seq, prev_hash = _next_log_position(connection)
        record = record_factory(next_seq)
        if (
            not isinstance(record, dict)
            or record.get("pack_id") != pack_id
            or record.get("audit_id") != audit_id
            or record.get("log_seq") != next_seq
            or not record_validator(record)
        ):
            raise ValueError("hardening pack failed issuer verification")
        issued_at = record.get("issued_at")
        if type(issued_at) is not int:
            raise ValueError("hardening pack issued_at is invalid")
        entry = {
            "seq": next_seq,
            "ts": issued_at,
            "event": "hardening-pack-issued",
            "record_type": "hardening-pack",
            "pack_id": pack_id,
            "audit_id": audit_id,
            "record_hash": hashlib.sha256(
                _canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "prev_hash": prev_hash,
        }
        connection.execute(
            "INSERT INTO hardening_packs "
            "(pack_id, audit_id, issued_at, log_seq, record_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                pack_id,
                audit_id,
                issued_at,
                next_seq,
                _canonical_json(record),
            ),
        )
        _write_log_entry(connection, entry)
    return record


def get_hardening_pack_with_evidence(
    pack_id: str,
    *,
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    """Return a pack only while its signed record and anchored log binding are intact."""
    evidence = get_hardening_pack_evidence(
        pack_id,
        record_validator=record_validator,
    )
    return None if evidence is None else evidence["pack"]


def revoke_hardening_pack(
    pack_id: str,
    *,
    revoked_at: int,
    record_validator: Callable[[dict[str, object]], bool],
) -> int:
    """Append one checkpointed revocation for an immutable hardening pack."""
    if type(revoked_at) is not int or not 0 <= revoked_at <= MAX_SAFE_UNIX_SECONDS:
        raise ValueError("hardening pack revocation time is invalid")
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT record_json FROM hardening_packs WHERE pack_id = ?",
            (pack_id,),
        ).fetchone()
        if row is None:
            raise ValueError("hardening pack not found")
        try:
            record = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProtectionStateConflict(
                "stored hardening pack contains invalid JSON"
            ) from exc
        if not isinstance(record, dict) or not record_validator(record):
            raise ProtectionStateConflict("stored hardening pack failed verification")
        if revoked_at < int(record["issued_at"]):
            raise ValueError("hardening pack revocation cannot predate issuance")
        existing = connection.execute(
            "SELECT revoked_at, log_seq FROM hardening_revocations WHERE pack_id = ?",
            (pack_id,),
        ).fetchone()
        if existing is not None:
            _, entries, head_hash = _read_log_head(connection)
            _read_anchored_checkpoint(connection, len(entries), head_hash)
            existing_at, log_seq = existing
            if (
                type(existing_at) is not int
                or type(log_seq) is not int
                or not 1 <= log_seq <= len(entries)
                or not _hardening_log_entry_matches(
                    entries[log_seq - 1],
                    record,
                    log_seq,
                    event="hardening-pack-revoked",
                    timestamp=existing_at,
                )
            ):
                raise ProtectionStateConflict(
                    "hardening pack revocation has no matching log entry"
                )
            return existing_at

        next_seq, prev_hash = _next_log_position(connection)
        entry = {
            "seq": next_seq,
            "ts": revoked_at,
            "event": "hardening-pack-revoked",
            "record_type": "hardening-pack",
            "pack_id": pack_id,
            "audit_id": record["audit_id"],
            "record_hash": hashlib.sha256(
                _canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "prev_hash": prev_hash,
        }
        connection.execute(
            "INSERT INTO hardening_revocations (pack_id, revoked_at, log_seq) "
            "VALUES (?, ?, ?)",
            (pack_id, revoked_at, next_seq),
        )
        _write_log_entry(connection, entry)
    return revoked_at


def get_hardening_pack_evidence(
    pack_id: str,
    *,
    record_validator: Callable[[dict[str, object]], bool],
) -> dict[str, object] | None:
    """Return a pack with its current revocation and signed inclusion evidence."""
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT record_json, log_seq FROM hardening_packs WHERE pack_id = ?",
            (pack_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            record = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProtectionStateConflict(
                "stored hardening pack contains invalid JSON"
            ) from exc
        if (
            not isinstance(record, dict)
            or record.get("pack_id") != pack_id
            or not record_validator(record)
        ):
            raise ProtectionStateConflict("stored hardening pack failed verification")
        _, entries, head_hash = _read_log_head(connection)
        checkpoint = _read_anchored_checkpoint(connection, len(entries), head_hash)
        log_seq = row[1]
        if (
            type(log_seq) is not int
            or not 1 <= log_seq <= len(entries)
            or record.get("log_seq") != log_seq
            or not _hardening_log_entry_matches(
                entries[log_seq - 1],
                record,
                log_seq,
            )
        ):
            raise ProtectionStateConflict(
                "stored hardening pack has no matching log entry"
            )
        revoked = connection.execute(
            "SELECT revoked_at, log_seq FROM hardening_revocations WHERE pack_id = ?",
            (pack_id,),
        ).fetchone()
        revoked_at: int | None = None
        if revoked is not None:
            revoked_at, revoked_seq = revoked
            if (
                type(revoked_at) is not int
                or type(revoked_seq) is not int
                or not 1 <= revoked_seq <= len(entries)
                or not _hardening_log_entry_matches(
                    entries[revoked_seq - 1],
                    record,
                    revoked_seq,
                    event="hardening-pack-revoked",
                    timestamp=revoked_at,
                )
            ):
                raise ProtectionStateConflict(
                    "hardening pack revocation has no matching log entry"
                )
        return {
            "pack": record,
            "status": "revoked" if revoked_at is not None else "active",
            "revoked_at": revoked_at,
            "log_suffix": entries[log_seq - 1 :],
            "checkpoint": checkpoint,
        }


def commit_registration(
    *,
    endpoint_host: str,
    probed_pub: str,
    record_factory: Callable[[str], dict[str, object]],
    record_refresher: Callable[[dict[str, object]], dict[str, object]],
    record_validator: Callable[[dict[str, object]], bool],
    status_signer: Callable[[dict[str, object], str], dict[str, object]],
) -> dict[str, object]:
    """Atomically apply TOFU, key-change, or an explicitly authorized rotation."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        binding = connection.execute(
            "SELECT pub, key_changed, pending_replacement_pub FROM bindings "
            "WHERE endpoint_host = ?",
            (endpoint_host,),
        ).fetchone()

        if binding is None:
            connection.execute(
                "INSERT INTO bindings "
                "(endpoint_host, pub, bound_at, key_changed, pending_replacement_pub) "
                "VALUES (?, ?, ?, 0, NULL)",
                (endpoint_host, probed_pub, int(time.time())),
            )
            record = record_factory("active")
            event = "issued"
        elif binding[2] == probed_pub:
            active_priors = _active_attestations(connection, endpoint_host)
            if any(not record_validator(prior) for prior in active_priors):
                raise ProtectionStateConflict(
                    "active attestation failed issuer verification during rotation"
                )
            for prior in active_priors:
                retired = status_signer(prior, "revoked")
                _store_attestation(connection, retired)
                _append_log(connection, "revoked", retired)
            connection.execute(
                "UPDATE bindings SET pub = ?, bound_at = ?, key_changed = 0, "
                "pending_replacement_pub = NULL WHERE endpoint_host = ?",
                (probed_pub, int(time.time()), endpoint_host),
            )
            record = record_factory("active")
            event = "rotated"
        elif binding[0] == probed_pub and not bool(binding[1]):
            active_priors = _active_attestations(connection, endpoint_host)
            if any(
                not record_validator(prior) or prior.get("pub") != probed_pub
                for prior in active_priors
            ):
                raise ProtectionStateConflict(
                    "active attestation failed issuer verification during registration"
                )
            if active_priors:
                record = max(
                    active_priors,
                    key=lambda prior: int(prior["verified_at"]),
                )
                if int(time.time()) <= int(record["expires_at"]):
                    return record
                record = record_refresher(record)
                _store_attestation(connection, record)
                _append_log(connection, "refreshed", record)
                return record
            record = record_factory("active")
            event = "issued"
        else:
            for prior in _active_attestations(connection, endpoint_host):
                if not record_validator(prior):
                    continue
                changed = status_signer(prior, "key-changed")
                _store_attestation(connection, changed)
                _append_log(connection, "key-changed", changed)
            connection.execute(
                "UPDATE bindings SET key_changed = 1 WHERE endpoint_host = ?",
                (endpoint_host,),
            )
            record = record_factory("key-changed")
            event = "issued"

        _store_attestation(connection, record)
        _append_log(connection, event, record)
    return record


def commit_revocation(
    *,
    attestation_id: str,
    endpoint_host: str,
    bound_pub: str,
    nonce: str,
    replacement_pub: str | None,
    record_validator: Callable[[dict[str, object]], bool],
    status_signer: Callable[[dict[str, object], str], dict[str, object]],
) -> dict[str, object]:
    """Atomically consume a signed nonce, revoke, and optionally authorize rotation."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        binding = connection.execute(
            "SELECT pub, pending_replacement_pub FROM bindings WHERE endpoint_host = ?",
            (endpoint_host,),
        ).fetchone()
        if binding is None or binding[0] != bound_pub:
            raise ProtectionStateConflict("endpoint key binding changed during revocation")

        row = connection.execute(
            "SELECT endpoint_host, record_json FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
        if row is None or row[0] != endpoint_host:
            raise ProtectionStateConflict("attestation binding changed during revocation")
        record = json.loads(row[1])
        if record.get("attestation_id") != attestation_id:
            raise ProtectionStateConflict("attestation binding changed during revocation")
        if not record_validator(record):
            raise ProtectionStateConflict("attestation failed issuer verification")
        if replacement_pub is not None and record.get("pub") != bound_pub:
            raise ProtectionStateConflict(
                "rotation authorization must reference an attestation for the bound key"
            )
        if not _record_nonce(connection, endpoint_host, nonce):
            raise NonceReplay("revocation nonce was replayed")
        if record.get("status") == "revoked" and (
            replacement_pub is None or binding[1] == replacement_pub
        ):
            return record

        updated = status_signer(record, "revoked")
        _store_attestation(connection, updated)
        if replacement_pub is not None:
            connection.execute(
                "UPDATE bindings SET pending_replacement_pub = ? WHERE endpoint_host = ?",
                (replacement_pub, endpoint_host),
            )
        event = "rotation-authorized" if replacement_pub is not None else "revoked"
        _append_log(connection, event, updated)
    return updated


def commit_reprobe_results(
    results: list[
        tuple[str | None, dict[str, object], dict[str, object]]
    ],
    *,
    endpoint_host: str,
    bound_pub: str,
    last_probed_at: int,
    key_changed_host: str | None = None,
) -> tuple[int, list[dict[str, object]]]:
    """Persist one endpoint probe across its attestations in one transaction."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        binding = connection.execute(
            "SELECT pub, key_changed FROM bindings WHERE endpoint_host = ?",
            (endpoint_host,),
        ).fetchone()
        if binding is None or binding[0] != bound_pub or bool(binding[1]):
            return 0, []
        entries = []
        updated = 0
        for event, record, expected_record in results:
            current = connection.execute(
                "SELECT status, record_json FROM attestations WHERE attestation_id = ?",
                (str(record["attestation_id"]),),
            ).fetchone()
            if (
                current is None
                or current[0] not in {"active", "stale", "invalid"}
                or current[1] != _canonical_json(expected_record)
            ):
                continue
            _store_attestation(connection, record, last_probed_at=last_probed_at)
            updated += 1
            if event is not None:
                entries.append(_append_log(connection, event, record))
        if key_changed_host is not None and updated:
            connection.execute(
                "UPDATE bindings SET key_changed = 1 WHERE endpoint_host = ?",
                (key_changed_host,),
            )
    return updated, entries


def read_log() -> list[dict[str, object]]:
    with _LOCK, _connect() as connection:
        rows = connection.execute("SELECT entry_json FROM log ORDER BY seq ASC").fetchall()
    return [json.loads(row[0]) for row in rows]


def read_log_page(
    cursor: int,
    limit: int,
) -> tuple[list[dict[str, object]], int, int | None]:
    with _LOCK, _connect() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM log").fetchone()[0])
        rows = connection.execute(
            "SELECT seq, entry_json FROM log WHERE seq > ? ORDER BY seq ASC LIMIT ?",
            (cursor, limit + 1),
        ).fetchall()
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    entries = [json.loads(row[1]) for row in page_rows]
    next_cursor = int(page_rows[-1][0]) if has_more and page_rows else None
    return entries, total, next_cursor


def read_log_checkpoint() -> dict[str, object]:
    """Return the verified local head; reads never initialize or re-sign it."""
    with _LOCK, _connect() as connection:
        _, entries, head_hash = _read_log_head(connection)
        return _read_anchored_checkpoint(connection, len(entries), head_hash)


def read_log_checkpoint_for_external_publish() -> dict[str, object]:
    """Read the exact locally anchored head without loading signing material."""
    with _LOCK, _connect() as connection:
        _, entries, head_hash = _read_log_head(connection)
        return _read_anchored_checkpoint(
            connection,
            len(entries),
            head_hash,
            verify_signature=False,
        )


def migrate_log_checkpoint() -> dict[str, object]:
    """Explicitly initialize or anchor one verified pre-anchor database."""
    with _LOCK, _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        anchor = connection.execute(
            "SELECT 1 FROM log_anchor WHERE singleton = 1"
        ).fetchone()
        if anchor is not None:
            raise ProtectionStateConflict("transparency log anchor already exists")

        rows, entries, head_hash = _read_log_head(connection)
        existing = connection.execute(
            "SELECT checkpoint_json FROM log_checkpoint WHERE singleton = 1"
        ).fetchone()
        if existing is not None:
            try:
                checkpoint = json.loads(existing[0])
            except (json.JSONDecodeError, TypeError) as exc:
                raise ProtectionStateConflict(
                    "legacy transparency log checkpoint contains invalid JSON"
                ) from exc
            if not isinstance(checkpoint, dict):
                raise ProtectionStateConflict(
                    "legacy transparency log checkpoint is not an object"
                )
            from warden import protection

            if (
                not protection.verify_log_checkpoint(checkpoint)
                or checkpoint.get("seq") != len(entries)
                or checkpoint.get("head_hash") != head_hash
            ):
                raise ProtectionStateConflict(
                    "legacy transparency log checkpoint does not match the current head"
                )
            _write_log_anchor(connection, checkpoint)
            return checkpoint

        if not rows:
            prior_sequence = connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'log'"
            ).fetchone()
            if prior_sequence is not None:
                raise ProtectionStateConflict(
                    "empty transparency log retains prior sequence state"
                )
        return _write_log_checkpoint(
            connection,
            len(entries),
            head_hash,
            int(time.time()),
        )


def verify_log_chain(
    entries: list[dict[str, object]],
    checkpoint: dict[str, object] | None = None,
) -> bool:
    """Verify contiguous entries against the issuer-signed stored head."""
    head_hash = _verified_log_head(entries)
    if head_hash is None:
        return False
    try:
        signed_head = read_log_checkpoint() if checkpoint is None else checkpoint
    except (LogCheckpointMissing, ProtectionStateConflict):
        return False
    from warden import protection

    return (
        protection.verify_log_checkpoint(signed_head)
        and signed_head.get("seq") == len(entries)
        and signed_head.get("head_hash") == head_hash
    )


def verify_log_prefix(
    entries: list[dict[str, object]],
    checkpoint: dict[str, object],
) -> bool:
    """Verify that a signed historical checkpoint is the prefix of a later log."""
    from warden import protection

    seq = checkpoint.get("seq") if isinstance(checkpoint, dict) else None
    if (
        type(seq) is not int
        or seq < 0
        or seq > len(entries)
        or not protection.verify_log_checkpoint(checkpoint)
    ):
        return False
    prefix_head = _verified_log_head(entries[:seq])
    return prefix_head is not None and checkpoint.get("head_hash") == prefix_head
