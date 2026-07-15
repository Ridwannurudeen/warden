"""SQLite store for APA protection state: TOFU bindings, nonces, attestations, log.

Single-worker assumption: the deployed service runs one uvicorn worker, so a
process-wide lock around one sqlite database is sufficient (matching the
existing JSONL stores). The transparency log is hash-chained (`prev_hash` =
SHA-256 of the previous entry's canonical bytes) per APA-SPEC §7.2.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
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
    key_changed INTEGER NOT NULL DEFAULT 0
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
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_json TEXT NOT NULL
);
"""


def _db_path() -> Path:
    configured = os.getenv("WARDEN_PROTECTION_DB")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[1] / "data" / "protection.db"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(_SCHEMA)
    return connection


def get_binding(endpoint_host: str) -> dict[str, object] | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT endpoint_host, pub, bound_at, key_changed FROM bindings "
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
    }


def bind_host(endpoint_host: str, pub: str) -> None:
    """Trust-on-first-use: record the first pub seen for a host."""
    with _LOCK, _connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO bindings (endpoint_host, pub, bound_at, key_changed) "
            "VALUES (?, ?, ?, 0)",
            (endpoint_host, pub, int(time.time())),
        )


def flag_key_changed(endpoint_host: str) -> None:
    with _LOCK, _connect() as connection:
        connection.execute(
            "UPDATE bindings SET key_changed = 1 WHERE endpoint_host = ?",
            (endpoint_host,),
        )


def record_nonce(endpoint_host: str, nonce: str) -> bool:
    """Record a heartbeat nonce; returns False on replay. TTL-evicts old nonces."""
    now = int(time.time())
    with _LOCK, _connect() as connection:
        connection.execute("DELETE FROM nonces WHERE seen_at < ?", (now - NONCE_TTL_SECONDS,))
        try:
            connection.execute(
                "INSERT INTO nonces (endpoint_host, nonce, seen_at) VALUES (?, ?, ?)",
                (endpoint_host, nonce, now),
            )
        except sqlite3.IntegrityError:
            return False
    return True


def store_attestation(record: dict[str, object]) -> None:
    with _LOCK, _connect() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO attestations "
            "(attestation_id, endpoint_host, status, record_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(record["attestation_id"]),
                str(record["endpoint_host"]),
                str(record["status"]),
                _canonical_json(record),
                int(time.time()),
            ),
        )


def get_attestation(attestation_id: str) -> dict[str, object] | None:
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT record_json FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def set_attestation_status(attestation_id: str, status: str) -> dict[str, object] | None:
    """Update the stored status column and record JSON status field (unsigned metadata).

    The original `issuer_sig` covers the issuance-time record; a post-issuance
    status change is issuer metadata, so the record keeps its signature and the
    transparency log carries the status transition.
    """
    record = get_attestation(attestation_id)
    if record is None:
        return None
    record["status"] = status
    with _LOCK, _connect() as connection:
        connection.execute(
            "UPDATE attestations SET status = ?, record_json = ? WHERE attestation_id = ?",
            (status, _canonical_json(record), attestation_id),
        )
    return record


def append_log(event: str, record: dict[str, object]) -> dict[str, object]:
    """Append a hash-chained transparency-log entry for an issuance/status change."""
    with _LOCK, _connect() as connection:
        row = connection.execute(
            "SELECT seq, entry_json FROM log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
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
