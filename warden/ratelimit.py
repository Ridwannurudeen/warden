"""Simple in-process fixed-window rate limiting for Warden HTTP requests."""

from __future__ import annotations

import threading
import time


def _time_now() -> float:
    return time.time()


_WINDOW_SECONDS = 60
_STATE: dict[tuple[str, str], tuple[int, int]] = {}
_STATE_LOCK = threading.Lock()


def _client_ip(request: object) -> str:
    headers = request.headers
    real_ip = headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip

    request_client = request.client
    if request_client and request_client.host:
        return request_client.host
    return "unknown"


def _window_id(timestamp: float) -> int:
    return int(timestamp // _WINDOW_SECONDS)


def check_rate_limit(request: object, limit_per_minute: int, scope: str = "paid") -> bool:
    """
    Return ``True`` when the caller is over quota.
    """
    if limit_per_minute <= 0:
        return False

    client = _client_ip(request)
    state_key = (scope, client)
    window_id = _window_id(_time_now())
    with _STATE_LOCK:
        for known_client, (start, _) in list(_STATE.items()):
            if start < window_id:
                del _STATE[known_client]

        start, count = _STATE.get(state_key, (window_id, 0))
        if start != window_id:
            start = window_id
            count = 0

        count += 1
        _STATE[state_key] = (start, count)
        return count > limit_per_minute


def retry_after_seconds() -> int:
    now = _time_now()
    remaining = _WINDOW_SECONDS - (int(now) % _WINDOW_SECONDS)
    if remaining <= 0:
        return 1
    return remaining


def _reset_state() -> None:
    with _STATE_LOCK:
        _STATE.clear()
