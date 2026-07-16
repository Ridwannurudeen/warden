"""SQLite store for APA protection state: TOFU bindings, nonces, attestations, log.

The deployed API runs one uvicorn worker; SQLite transactions also serialize
the separate periodic re-probe process. The transparency log is hash-chained
(`prev_hash` = SHA-256 of the previous entry's canonical bytes) per APA-SPEC §7.2.
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

from warden.badges import _canonical_json

NONCE_TTL_SECONDS = 3600
GENESIS_PREV_HASH = "0" * 64

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
"""


class ProtectionStateConflict(ValueError):
    """The binding or attestation changed before an atomic write completed."""


class NonceReplay(ValueError):
    """A signed request reused a nonce within the replay window."""


def _db_path() -> Path:
    configured = os.getenv("WARDEN_PROTECTION_DB")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "protection.db"


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
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


def _append_log(
    connection: sqlite3.Connection,
    event: str,
    record: dict[str, object],
) -> dict[str, object]:
    row = connection.execute("SELECT seq, entry_json FROM log ORDER BY seq DESC LIMIT 1").fetchone()
    if row is None:
        next_seq = 1
        prev_hash = GENESIS_PREV_HASH
    else:
        next_seq = row[0] + 1
        prev_hash = hashlib.sha256(row[1].encode("utf-8")).hexdigest()
    entry = {
        "seq": next_seq,
        "ts": int(time.time()),
        "event": event,
        "attestation_id": record.get("attestation_id"),
        "endpoint_host": record.get("endpoint_host"),
        "status": record.get("status"),
        "record_hash": hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest(),
        "prev_hash": prev_hash,
    }
    connection.execute(
        "INSERT INTO log (seq, entry_json) VALUES (?, ?)",
        (next_seq, _canonical_json(entry)),
    )
    return entry


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


def commit_registration(
    *,
    endpoint_host: str,
    probed_pub: str,
    record_factory: Callable[[str], dict[str, object]],
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
            "SELECT pub FROM bindings WHERE endpoint_host = ?",
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
    results: list[tuple[str | None, dict[str, object]]],
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
        if key_changed_host is not None:
            connection.execute(
                "UPDATE bindings SET key_changed = 1 WHERE endpoint_host = ?",
                (key_changed_host,),
            )
        entries = []
        updated = 0
        for event, record in results:
            current = connection.execute(
                "SELECT status FROM attestations WHERE attestation_id = ?",
                (str(record["attestation_id"]),),
            ).fetchone()
            if current is None or current[0] not in {"active", "stale", "invalid"}:
                continue
            _store_attestation(connection, record, last_probed_at=last_probed_at)
            updated += 1
            if event is not None:
                entries.append(_append_log(connection, event, record))
    return updated, entries


def read_log() -> list[dict[str, object]]:
    with _LOCK, _connect() as connection:
        rows = connection.execute("SELECT entry_json FROM log ORDER BY seq ASC").fetchall()
    return [json.loads(row[0]) for row in rows]


def verify_log_chain(entries: list[dict[str, object]]) -> bool:
    """Recompute the hash chain over canonical entry bytes; True iff unbroken."""
    prev_hash = GENESIS_PREV_HASH
    for entry in entries:
        if entry.get("prev_hash") != prev_hash:
            return False
        prev_hash = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
    return True
