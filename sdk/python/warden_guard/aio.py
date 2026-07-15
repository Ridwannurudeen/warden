"""Async Warden client — the same surface as WardenClient, with `await`."""

from __future__ import annotations

import httpx

from warden_guard.client import (
    DEFAULT_BASE_URL,
    FREE_PATH,
    PAID_PATH,
    LocalEngine,
    ScanResult,
    WardenBlocked,
    WardenError,
    build_scan_body,
)
from warden_guard.state import increment_scan_count


class AsyncWardenClient:
    """Async client for the Warden payload firewall.

    Same tiers and defaults as :class:`warden_guard.WardenClient`: the free
    hosted tier is best-effort telemetry (`fail_open=True`); use `local=True`
    for in-process enforcement-grade verdicts or `paid=True` for hosted volume.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        paid: bool = False,
        local: bool = False,
        timeout: float = 8.0,
        fail_open: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.path = PAID_PATH if paid else FREE_PATH
        self.local = local
        self.timeout = timeout
        self.fail_open = fail_open
        self._engine = LocalEngine() if local else None

    async def scan(
        self,
        payload: str,
        *,
        expected_addresses: list[str] | None = None,
        depth: str = "fast",
    ) -> ScanResult:
        """Scan one untrusted payload and return a Warden verdict."""
        increment_scan_count()
        if self._engine is not None:
            data = await self._engine.scan(
                payload, depth=depth, expected_addresses=expected_addresses
            )
            return ScanResult.from_response(data)
        body = build_scan_body(payload, depth=depth, expected_addresses=expected_addresses)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.base_url + self.path, json=body)
                response.raise_for_status()
                return ScanResult.from_response(response.json())
        except httpx.HTTPError as exc:
            if self.fail_open:
                return ScanResult(verdict="ALLOW", risk_level="NONE", raw={"error": str(exc)})
            raise WardenError(f"Warden scan failed: {exc}") from exc

    async def guard(self, payload: str, **kwargs: object) -> str:
        """Scan and enforce: return the safe payload to act on, or raise on BLOCK."""
        result = await self.scan(payload, **kwargs)  # type: ignore[arg-type]
        if result.blocked:
            raise WardenBlocked(result)
        if result.sanitized and result.sanitized_payload is not None:
            return result.sanitized_payload
        return payload
