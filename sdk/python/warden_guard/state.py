"""Persistent lifetime and rolling scan counters.

The lifetime counter remains monotonic for compatibility. The APA heartbeat
reads an exact rolling 24-hour total from companion SQLite second buckets.
Both advance only after a real scan returns a valid verdict. Migrating a
positive or unreadable lifetime-only state starts a persisted 24-hour warmup;
the rolling count is unavailable until that window is fully observed.

State lives at `$WARDEN_GUARD_STATE` (default `~/.warden/state.json`, `0600`).
The JSON file mirrors the lifetime total; `<state>.windows.sqlite3` stores the
rolling buckets. An exclusive lock serializes updates across processes on one
host. All workers sharing these files report one combined count for the guard
key.
"""

from __future__ import annotations

from contextlib import closing
import json
import os
import sqlite3
import time
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_STATE_ENV = "WARDEN_GUARD_STATE"
_LOCK_SUFFIX = ".lock"
_LOCK_TIMEOUT_S = 5.0
_APA_WINDOW_S = 86_400
_ROLLING_COMPLETE_AFTER = "rolling_complete_after"


def state_path() -> Path:
    return Path(os.environ.get(_STATE_ENV) or Path.home() / ".warden" / "state.json")


def _read_json_count(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    count = data.get("scans_served") if isinstance(data, dict) else None
    return count if type(count) is int and count >= 0 else 0


def _legacy_window_is_incomplete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    count = data.get("scans_served") if isinstance(data, dict) else None
    return type(count) is not int or count < 0 or count > 0


def _window_state_path(path: Path) -> Path:
    return path.with_name(path.name + ".windows.sqlite3")


def _create_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS scan_buckets "
        "(bucket_s INTEGER PRIMARY KEY, scans INTEGER NOT NULL CHECK (scans > 0))"
    )


def _initialize_counter_state(
    connection: sqlite3.Connection,
    path: Path,
    current: int,
) -> None:
    initialized = connection.execute(
        "SELECT value FROM counters WHERE name = 'lifetime'"
    ).fetchone()
    if initialized is not None:
        return
    connection.execute(
        "INSERT INTO counters (name, value) VALUES ('lifetime', ?)",
        (_read_json_count(path),),
    )
    if _legacy_window_is_incomplete(path):
        connection.execute(
            "INSERT INTO counters (name, value) VALUES (?, ?)",
            (_ROLLING_COMPLETE_AFTER, current + _APA_WINDOW_S),
        )


class _FileLock:
    """Cross-platform advisory lock released automatically if its process exits."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> "_FileLock":
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        if os.name == "nt" and os.fstat(self.fd).st_size == 0:
            os.write(self.fd, b"\0")
        while True:
            try:
                if os.name == "nt":
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise TimeoutError("timed out waiting for scan counter lock") from exc
                time.sleep(0.01)

    def __exit__(self, *exc: object) -> None:
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None


def get_scan_count() -> int:
    """Current monotonic scan count (0 if no state yet)."""
    path = state_path()
    database = _window_state_path(path)
    if not path.exists() and not database.exists():
        return 0
    with _FileLock(path.with_name(path.name + _LOCK_SUFFIX)):
        if database.exists():
            with closing(sqlite3.connect(database, timeout=_LOCK_TIMEOUT_S)) as connection:
                has_counters = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'counters'"
                ).fetchone()
                if has_counters is not None:
                    row = connection.execute(
                        "SELECT value FROM counters WHERE name = 'lifetime'"
                    ).fetchone()
                else:
                    row = None
            if row is not None and type(row[0]) is int and row[0] >= 0:
                return row[0]
        return _read_json_count(path)


def get_window_scan_count(*, window_s: int = _APA_WINDOW_S, now: int | None = None) -> int | None:
    """Count scans in the window, or return None while legacy coverage warms up."""
    if type(window_s) is not int or window_s != _APA_WINDOW_S:
        raise ValueError("window_s must be 86400")
    current = int(time.time()) if now is None else now
    if type(current) is not int:
        raise ValueError("now must be an integer Unix timestamp")
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    database = _window_state_path(path)
    cutoff = current - window_s
    with _FileLock(path.with_name(path.name + _LOCK_SUFFIX)):
        with closing(sqlite3.connect(database, timeout=_LOCK_TIMEOUT_S)) as connection:
            with connection:
                _create_tables(connection)
                _initialize_counter_state(connection, path, current)
                warmup = connection.execute(
                    "SELECT value FROM counters WHERE name = ?", (_ROLLING_COMPLETE_AFTER,)
                ).fetchone()
                if warmup is not None and current <= warmup[0]:
                    count = None
                else:
                    row = connection.execute(
                        "SELECT COALESCE(SUM(scans), 0) FROM scan_buckets "
                        "WHERE bucket_s BETWEEN ? AND ?",
                        (cutoff, current),
                    ).fetchone()
                    count = int(row[0])
    os.chmod(database, 0o600)
    return count


def increment_scan_count() -> int:
    """Atomically increment the counter by one real scan; returns the new count."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _FileLock(path.with_name(path.name + _LOCK_SUFFIX)):
        now = int(time.time())
        cutoff = now - _APA_WINDOW_S
        database = _window_state_path(path)
        with closing(sqlite3.connect(database, timeout=_LOCK_TIMEOUT_S)) as connection:
            with connection:
                _create_tables(connection)
                _initialize_counter_state(connection, path, now)
                connection.execute("UPDATE counters SET value = value + 1 WHERE name = 'lifetime'")
                connection.execute(
                    "INSERT INTO scan_buckets (bucket_s, scans) VALUES (?, 1) "
                    "ON CONFLICT(bucket_s) DO UPDATE SET scans = scans + 1",
                    (now,),
                )
                connection.execute("DELETE FROM scan_buckets WHERE bucket_s < ?", (cutoff,))
                count = int(
                    connection.execute(
                        "SELECT value FROM counters WHERE name = 'lifetime'"
                    ).fetchone()[0]
                )
        os.chmod(database, 0o600)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps({"scans_served": count, "updated_at": now}),
            encoding="utf-8",
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return count
