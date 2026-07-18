"""Bounded scan metrics and opt-in metadata-only JSON events."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import statistics
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Sequence
from contextlib import closing
from enum import Enum
from pathlib import Path

_TRUTHY = {"1", "true", "yes", "on"}
_LATENCY_WINDOW = 1_024


class RuntimeMetrics:
    """Bounded counters for completed HTTP scans, optionally shared through SQLite."""

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self._started_at = time.monotonic()
        self._lock = threading.Lock()
        self._database_lock = threading.RLock()
        configured_path = os.getenv("WARDEN_METRICS_DB") if db_path is None else db_path
        self._database_path = str(Path(configured_path).resolve()) if configured_path else None
        self._database_initialized = False
        self._persistence_warning_emitted = False
        self._scans = 0
        self._blocks_by_class: Counter[str] = Counter()
        self._latencies: deque[float] = deque(maxlen=_LATENCY_WINDOW)
        self._pending_scans = 0
        self._pending_blocks_by_class: Counter[str] = Counter()
        self._pending_latencies: deque[float] = deque(maxlen=_LATENCY_WINDOW)

    def _connect(self) -> sqlite3.Connection:
        if self._database_path is None:
            raise RuntimeError("persistent metrics are not configured")
        connection = sqlite3.connect(self._database_path, timeout=1.0)
        connection.execute("PRAGMA busy_timeout = 1000")
        return connection

    def _warn_persistence_unavailable(self) -> None:
        with self._database_lock:
            if self._persistence_warning_emitted:
                return
            self._persistence_warning_emitted = True
        print(
            "Warden runtime metrics persistence is unavailable; using process-local counters.",
            file=sys.stderr,
            flush=True,
        )

    def _ensure_database(self) -> bool:
        if self._database_path is None:
            return False
        with self._database_lock:
            if self._database_initialized:
                return True
            try:
                with closing(self._connect()) as connection:
                    connection.execute("PRAGMA journal_mode = WAL")
                    with connection:
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS runtime_totals (
                                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                                scans INTEGER NOT NULL CHECK (scans >= 0)
                            )
                            """
                        )
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS runtime_blocks (
                                threat_class TEXT PRIMARY KEY,
                                count INTEGER NOT NULL CHECK (count >= 0)
                            )
                            """
                        )
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS runtime_latencies (
                                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                                latency_ms REAL NOT NULL CHECK (latency_ms >= 0)
                            )
                            """
                        )
                        connection.execute(
                            "INSERT OR IGNORE INTO runtime_totals (singleton, scans) VALUES (1, 0)"
                        )
            except (OSError, sqlite3.Error):
                self._warn_persistence_unavailable()
                return False
            self._database_initialized = True
            return True

    def _flush_pending_locked(self) -> bool:
        if self._pending_scans == 0:
            return True
        if not self._ensure_database():
            return False
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "UPDATE runtime_totals SET scans = scans + ? WHERE singleton = 1",
                        (self._pending_scans,),
                    )
                    connection.executemany(
                        """
                        INSERT INTO runtime_blocks (threat_class, count)
                        VALUES (?, ?)
                        ON CONFLICT(threat_class) DO UPDATE SET count = count + excluded.count
                        """,
                        sorted(self._pending_blocks_by_class.items()),
                    )
                    connection.executemany(
                        "INSERT INTO runtime_latencies (latency_ms) VALUES (?)",
                        ((latency,) for latency in self._pending_latencies),
                    )
                    connection.execute(
                        """
                        DELETE FROM runtime_latencies
                        WHERE sequence <= COALESCE(
                            (
                                SELECT sequence
                                FROM runtime_latencies
                                ORDER BY sequence DESC
                                LIMIT 1 OFFSET ?
                            ),
                            0
                        )
                        """,
                        (_LATENCY_WINDOW,),
                    )
        except (OSError, sqlite3.Error):
            self._warn_persistence_unavailable()
            return False
        self._pending_scans = 0
        self._pending_blocks_by_class.clear()
        self._pending_latencies.clear()
        return True

    def _record_persistent(
        self,
        verdict: str,
        latency_ms: float,
        threat_classes: set[str],
    ) -> None:
        if self._database_path is None:
            return
        with self._database_lock:
            self._pending_scans += 1
            self._pending_latencies.append(latency_ms)
            if verdict == "BLOCK":
                self._pending_blocks_by_class.update(threat_classes)
            self._flush_pending_locked()

    def _persistent_snapshot(self) -> tuple[int, dict[str, int], tuple[float, ...]] | None:
        with self._database_lock:
            if not self._ensure_database():
                return None
            self._flush_pending_locked()
            pending_scans = self._pending_scans
            pending_blocks = self._pending_blocks_by_class.copy()
            pending_latencies = tuple(self._pending_latencies)
            try:
                with closing(self._connect()) as connection:
                    scans_row = connection.execute(
                        "SELECT scans FROM runtime_totals WHERE singleton = 1"
                    ).fetchone()
                    blocks_by_class = Counter(
                        dict(
                            connection.execute(
                                "SELECT threat_class, count FROM runtime_blocks ORDER BY threat_class"
                            )
                        )
                    )
                    latencies = tuple(
                        row[0]
                        for row in connection.execute(
                            "SELECT latency_ms FROM runtime_latencies ORDER BY sequence"
                        )
                    )
            except (OSError, sqlite3.Error):
                self._warn_persistence_unavailable()
                return None
            blocks_by_class.update(pending_blocks)
            combined_latencies = (latencies + pending_latencies)[-_LATENCY_WINDOW:]
            return (
                int(scans_row[0]) + pending_scans,
                dict(sorted(blocks_by_class.items())),
                combined_latencies,
            )

    def record_scan(
        self,
        verdict: str,
        latency_ms: float,
        threat_classes: Sequence[str | Enum],
    ) -> None:
        latency = float(latency_ms)
        classes = {
            str(threat_class.value if isinstance(threat_class, Enum) else threat_class)
            for threat_class in threat_classes
        }
        with self._lock:
            self._scans += 1
            self._latencies.append(latency)
            if verdict == "BLOCK":
                self._blocks_by_class.update(classes)
        self._record_persistent(verdict, latency, classes)

        if os.getenv("WARDEN_JSON_LOGS", "").strip().lower() in _TRUTHY:
            print(
                json.dumps(
                    {
                        "request_id": secrets.token_hex(16),
                        "verdict": verdict,
                        "latency_ms": latency,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )

    def snapshot(self) -> dict[str, object]:
        persistent = self._persistent_snapshot()
        if persistent is None:
            with self._lock:
                scans = self._scans
                blocks_by_class = dict(sorted(self._blocks_by_class.items()))
                latencies = tuple(self._latencies)
        else:
            scans, blocks_by_class, latencies = persistent
        return {
            "uptime_seconds": max(0.0, time.monotonic() - self._started_at),
            "scans": scans,
            "blocks_by_class": blocks_by_class,
            "p50_latency_ms": statistics.median(latencies) if latencies else None,
        }


runtime_metrics = RuntimeMetrics()
