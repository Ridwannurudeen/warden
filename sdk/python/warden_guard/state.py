"""Persistent, atomic, monotonic scan counter.

The counter is the honest-usage linchpin of the APA heartbeat: `scans_served`
MUST only increase when `scan()` actually runs (APA §3). It is therefore
settable ONLY via :func:`increment_scan_count`, which the client calls on every
real scan — never via API parameter, env var, or config.

State lives at `$WARDEN_GUARD_STATE` (default `~/.warden/state.json`, `0600`).
Writes are atomic (temp file + `os.replace`) under an exclusive lock file, so
one shared counter file is safe across processes on one host. Multi-worker
honesty note: all workers sharing this file report one combined count for the
guard key — the heartbeat wording is "payloads this guard has signed".
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

_STATE_ENV = "WARDEN_GUARD_STATE"
_LOCK_SUFFIX = ".lock"
_LOCK_TIMEOUT_S = 5.0


def state_path() -> Path:
    return Path(os.environ.get(_STATE_ENV) or Path.home() / ".warden" / "state.json")


def _read_count(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    count = data.get("scans_served") if isinstance(data, dict) else None
    return count if isinstance(count, int) and count >= 0 else 0


class _FileLock:
    """Minimal cross-platform exclusive lock via O_CREAT|O_EXCL on a lock file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> "_FileLock":
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    # Stale lock (crashed holder): break it rather than deadlock.
                    try:
                        os.unlink(self.path)
                    except OSError:
                        pass
                    deadline = time.monotonic() + _LOCK_TIMEOUT_S
                time.sleep(0.01)

    def __exit__(self, *exc: object) -> None:
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.unlink(self.path)
        except OSError:
            pass


def get_scan_count() -> int:
    """Current monotonic scan count (0 if no state yet)."""
    return _read_count(state_path())


def increment_scan_count() -> int:
    """Atomically increment the counter by one real scan; returns the new count."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _FileLock(path.with_name(path.name + _LOCK_SUFFIX)):
        count = _read_count(path) + 1
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps({"scans_served": count, "updated_at": int(time.time())}),
            encoding="utf-8",
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return count
