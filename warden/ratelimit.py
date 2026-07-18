"""Process-safe fixed-window rate limiting for Warden HTTP requests."""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory


def _time_now() -> float:
    return time.time()


_WINDOW_SECONDS = 60
_VERIFIED_TTL_SECONDS = 600
_STORAGE_WARNING_LOCK = threading.Lock()
_STORAGE_WARNING_EMITTED = False
_LOCAL_DATABASE_DIRECTORY = TemporaryDirectory(prefix="warden-rate-limit-")
_LOCAL_DATABASE_PATH = Path(_LOCAL_DATABASE_DIRECTORY.name) / "rate-limit.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS rate_windows (
    scope TEXT NOT NULL,
    client TEXT NOT NULL,
    window_id INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 1),
    PRIMARY KEY (scope, client, window_id)
);
CREATE TABLE IF NOT EXISTS verified_payers (
    client TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


def _db_path() -> Path:
    configured = os.getenv("WARDEN_RATE_LIMIT_DB", "").strip()
    if configured:
        return Path(configured)
    return _LOCAL_DATABASE_PATH


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=1.0)
    try:
        connection.execute("PRAGMA busy_timeout = 1000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(_SCHEMA)
    except BaseException:
        connection.close()
        raise
    return connection


def _warn_storage_unavailable() -> None:
    global _STORAGE_WARNING_EMITTED
    with _STORAGE_WARNING_LOCK:
        if _STORAGE_WARNING_EMITTED:
            return
        _STORAGE_WARNING_EMITTED = True
    print(
        "Warden rate-limit persistence is unavailable; protected routes fail closed.",
        file=sys.stderr,
        flush=True,
    )


def _client_ip(request: object) -> str:
    request_client = request.client
    if not request_client or not request_client.host:
        return "unknown"

    peer = request_client.host.strip()
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer

    if peer_ip.is_loopback:
        real_ip = request.headers.get("x-real-ip", "").strip()
        try:
            return str(ipaddress.ip_address(real_ip))
        except ValueError:
            return str(peer_ip)
    return str(peer_ip)


def _window_id(timestamp: float) -> int:
    return int(timestamp // _WINDOW_SECONDS)


def check_rate_limit(request: object, limit_per_minute: int, scope: str = "paid") -> bool:
    """
    Return ``True`` when the caller is over quota or shared storage is unavailable.
    """
    if limit_per_minute <= 0:
        return False

    client = _client_ip(request)
    window_id = _window_id(_time_now())
    try:
        with closing(_connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM rate_windows WHERE window_id < ?",
                (window_id - 1,),
            )
            connection.execute(
                """
                INSERT INTO rate_windows (scope, client, window_id, count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(scope, client, window_id) DO UPDATE SET
                    count = rate_windows.count + 1
                """,
                (scope, client, window_id),
            )
            row = connection.execute(
                "SELECT count FROM rate_windows WHERE scope = ? AND client = ? AND window_id = ?",
                (scope, client, window_id),
            ).fetchone()
            connection.commit()
    except (OSError, sqlite3.Error):
        _warn_storage_unavailable()
        return True
    return row is None or int(row[0]) > limit_per_minute


def mark_verified_payer(request: object) -> None:
    """Record that ``request``'s client just completed a verified settlement."""
    client = _client_ip(request)
    now = _time_now()
    try:
        with closing(_connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM verified_payers WHERE expires_at <= ?",
                (now,),
            )
            connection.execute(
                """
                INSERT INTO verified_payers (client, expires_at)
                VALUES (?, ?)
                ON CONFLICT(client) DO UPDATE SET expires_at = excluded.expires_at
                """,
                (client, now + _VERIFIED_TTL_SECONDS),
            )
            connection.commit()
    except (OSError, sqlite3.Error):
        _warn_storage_unavailable()


def is_verified_payer(request: object) -> bool:
    """Return ``True`` when the client has a live verified-settlement grant."""
    client = _client_ip(request)
    now = _time_now()
    try:
        with closing(_connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM verified_payers WHERE expires_at <= ?",
                (now,),
            )
            row = connection.execute(
                "SELECT 1 FROM verified_payers WHERE client = ? AND expires_at > ?",
                (client, now),
            ).fetchone()
            connection.commit()
    except (OSError, sqlite3.Error):
        _warn_storage_unavailable()
        return False
    return row is not None


def retry_after_seconds() -> int:
    now = _time_now()
    remaining = _WINDOW_SECONDS - (int(now) % _WINDOW_SECONDS)
    if remaining <= 0:
        return 1
    return remaining


def _reset_state() -> None:
    global _STORAGE_WARNING_EMITTED
    try:
        with closing(_connect()) as connection:
            with connection:
                connection.execute("DELETE FROM rate_windows")
                connection.execute("DELETE FROM verified_payers")
    except (OSError, sqlite3.Error):
        _warn_storage_unavailable()
    with _STORAGE_WARNING_LOCK:
        _STORAGE_WARNING_EMITTED = False
