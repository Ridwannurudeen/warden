"""Framework-agnostic ASGI middleware — scans request bodies, blocks poison.

Works on any ASGI app (FastAPI, Starlette, Quart, ...):

    app.add_middleware(WardenGuard, client=WardenClient(local=True))

For each request with a body, the configured `extract` callable pulls the
untrusted text; a BLOCK verdict short-circuits with HTTP 400 + the verdict
JSON. ALLOW passes through unchanged; SANITIZE replaces the replayed body with
the scanner's sanitized payload or blocks when a custom extractor cannot be
safely mapped back to the body.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import ScanResult, WardenClient

Extract = Callable[[bytes, dict], str | None]


def _default_extract(body: bytes, scope: dict) -> str | None:
    if not body:
        return None
    return body.decode("utf-8")


class WardenGuard:
    """ASGI middleware that runs every request body through Warden.

    Args:
        app: The wrapped ASGI app.
        client: A WardenClient or AsyncWardenClient (sync clients run in a
            worker thread). Defaults to the free hosted tier — best-effort
            telemetry; use `WardenClient(local=True)` for enforcement.
        extract: `(body_bytes, scope) -> str | None`; return None to skip the
            scan for that request. Default: the whole body as UTF-8 text.
        on_block: Optional `(result) -> dict` to customize the 400 response
            body; default returns the raw verdict JSON.
        max_body_bytes: Maximum request-body size buffered for scanning.
    """

    def __init__(
        self,
        app: Callable[[dict, Callable, Callable], Awaitable[None]],
        *,
        client: WardenClient | AsyncWardenClient | None = None,
        extract: Extract = _default_extract,
        on_block: Callable[[ScanResult], dict] | None = None,
        max_body_bytes: int = 1_000_000,
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive")
        self.app = app
        self.client = client or WardenClient()
        self.extract = extract
        self.on_block = on_block
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return

        encodings = [
            coding.strip().lower()
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-encoding"
            for coding in value.split(b",")
        ]
        if any(encoding != b"identity" for encoding in encodings):
            await self._reject_request(send, 415, "request body content encoding is not supported")
            return

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if not isinstance(message, dict):
                await self._reject_request(send, 400, "invalid ASGI request stream")
                return
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                await self._reject_request(send, 400, "invalid ASGI request stream")
                return
            chunk = message.get("body", b"")
            more_body = message.get("more_body", False)
            if not isinstance(chunk, bytes) or not isinstance(more_body, bool):
                await self._reject_request(send, 400, "invalid ASGI request stream")
                return
            if len(chunk) > self.max_body_bytes - len(body):
                await self._reject_request(send, 413, "request body too large")
                return
            body.extend(chunk)
            more = more_body
        body_bytes = bytes(body)

        try:
            body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            await self._reject_request(send, 415, "request body must be UTF-8")
            return

        payload = self.extract(body_bytes, scope)
        if payload:
            result = await self._scan(payload)
            if result.sanitized:
                if self.extract is not _default_extract or result.sanitized_payload is None:
                    await self._reject(send, result)
                    return
                body_bytes = result.sanitized_payload.encode("utf-8")
                headers = [
                    (name, value)
                    for name, value in scope.get("headers", [])
                    if name.lower() != b"content-length"
                ]
                headers.append((b"content-length", str(len(body_bytes)).encode()))
                scope = {**scope, "headers": headers}
            elif result.blocked:
                await self._reject(send, result)
                return

        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        await self.app(scope, replay, send)

    async def _scan(self, payload: str) -> ScanResult:
        if isinstance(self.client, AsyncWardenClient):
            return await self.client.scan(payload)
        return await asyncio.to_thread(self.client.scan, payload)

    @staticmethod
    async def _reject_request(send: Callable, status: int, detail: str) -> None:
        body = json.dumps({"error": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _reject(self, send: Callable, result: ScanResult) -> None:
        detail = self.on_block(result) if self.on_block else dict(result.raw)
        body = json.dumps({"error": "payload blocked by Warden", "verdict": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
