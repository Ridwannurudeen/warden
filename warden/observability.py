"""Process-local scan metrics and opt-in metadata-only JSON events."""

from __future__ import annotations

import json
import os
import secrets
import statistics
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Sequence
from enum import Enum

_TRUTHY = {"1", "true", "yes", "on"}
_LATENCY_WINDOW = 1_024


class RuntimeMetrics:
    """Bounded process-local counters for completed HTTP scans."""

    def __init__(self) -> None:
        self._started_at = time.monotonic()
        self._lock = threading.Lock()
        self._scans = 0
        self._blocks_by_class: Counter[str] = Counter()
        self._latencies: deque[float] = deque(maxlen=_LATENCY_WINDOW)

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
        with self._lock:
            scans = self._scans
            blocks_by_class = dict(sorted(self._blocks_by_class.items()))
            latencies = tuple(self._latencies)
        return {
            "uptime_seconds": max(0.0, time.monotonic() - self._started_at),
            "scans": scans,
            "blocks_by_class": blocks_by_class,
            "p50_latency_ms": statistics.median(latencies) if latencies else None,
        }


runtime_metrics = RuntimeMetrics()
