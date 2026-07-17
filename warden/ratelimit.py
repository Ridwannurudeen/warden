"""Simple in-process fixed-window rate limiting for Warden HTTP requests."""

from __future__ import annotations

import ipaddress
import threading
import time


def _time_now() -> float:
    return time.time()


_WINDOW_SECONDS = 60
_STATE: dict[tuple[str, str], tuple[int, int]] = {}
_STATE_LOCK = threading.Lock()

# A client is granted the elevated payment bucket only after it has completed at
# least one verified x402 settlement. This keeps a forged/unverified payment
# header from unlocking elevated throughput before the facilitator confirms.
_VERIFIED_TTL_SECONDS = 600
_VERIFIED_PAYERS: dict[str, float] = {}


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


def mark_verified_payer(request: object) -> None:
    """Record that ``request``'s client just completed a verified settlement."""
    client = _client_ip(request)
    with _STATE_LOCK:
        _VERIFIED_PAYERS[client] = _time_now() + _VERIFIED_TTL_SECONDS


def is_verified_payer(request: object) -> bool:
    """Return ``True`` when the client has a live verified-settlement grant."""
    client = _client_ip(request)
    now = _time_now()
    with _STATE_LOCK:
        for known_client, expires_at in list(_VERIFIED_PAYERS.items()):
            if expires_at <= now:
                del _VERIFIED_PAYERS[known_client]
        return client in _VERIFIED_PAYERS


def retry_after_seconds() -> int:
    now = _time_now()
    remaining = _WINDOW_SECONDS - (int(now) % _WINDOW_SECONDS)
    if remaining <= 0:
        return 1
    return remaining


def _reset_state() -> None:
    with _STATE_LOCK:
        _STATE.clear()
        _VERIFIED_PAYERS.clear()
