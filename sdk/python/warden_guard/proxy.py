"""Fail-closed standalone ASGI reverse proxy guarded by Warden."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import WardenBlocked, WardenClient, WardenError

_HOP_BY_HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}


def _host_identity(value: str, scheme: str) -> tuple[str, int] | None:
    try:
        parsed = urlsplit(f"{scheme}://{value}")
        if not parsed.hostname:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    return parsed.hostname.casefold(), port


def _filtered_headers(
    headers: list[tuple[bytes, bytes]],
    *,
    strip_host: bool = False,
    strip_content_length: bool = False,
) -> list[tuple[bytes, bytes]]:
    connection_tokens: set[bytes] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            connection_tokens.update(
                token.strip().lower() for token in value.split(b",") if token.strip()
            )
    denied = _HOP_BY_HOP_HEADERS | connection_tokens
    if strip_host:
        denied.add(b"host")
    if strip_content_length:
        denied.add(b"content-length")
    return [(name, value) for name, value in headers if name.lower() not in denied]


class WardenReverseProxy:
    """ASGI reverse proxy that scans every non-empty request body before forwarding."""

    def __init__(
        self,
        upstream: str,
        *,
        client: WardenClient | AsyncWardenClient | None = None,
        max_body_bytes: int = 1_000_000,
        max_response_bytes: int = 10_000_000,
        upstream_timeout: float = 8.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(upstream)
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError("upstream must be a valid HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("upstream must be a valid HTTP(S) origin")
        if max_body_bytes < 1 or max_response_bytes < 1:
            raise ValueError("proxy body limits must be positive")
        if not 0 < upstream_timeout <= 60:
            raise ValueError("upstream_timeout must be greater than zero and no more than 60")

        configured_client = client or AsyncWardenClient(fail_open=False)
        if configured_client.fail_open:
            raise ValueError("reverse-proxy enforcement requires a client with fail_open=False")
        self.client = configured_client
        upstream_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        self.upstream = httpx.URL(
            f"{parsed.scheme}://{upstream_host}"
            + (f":{parsed_port}" if parsed_port is not None else "")
        )
        self.upstream_identity = (
            parsed.hostname.casefold(),
            parsed_port or (443 if parsed.scheme == "https" else 80),
        )
        self.max_body_bytes = max_body_bytes
        self.max_response_bytes = max_response_bytes
        self.upstream_timeout = upstream_timeout
        self.transport = transport

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1003})
            return

        headers = list(scope.get("headers", []))
        host = next(
            (value.decode("latin-1") for name, value in headers if name.lower() == b"host"),
            "",
        )
        if _host_identity(host, str(scope.get("scheme", "http"))) == self.upstream_identity:
            await self._json_response(send, 508, "proxy loop detected")
            return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await self._json_response(send, 400, "invalid ASGI request stream")
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_body_bytes:
                await self._json_response(send, 413, "request body too large")
                return
            more_body = bool(message.get("more_body", False))

        body_bytes = bytes(body)
        if body_bytes:
            try:
                payload = body_bytes.decode("utf-8")
            except UnicodeDecodeError:
                await self._json_response(send, 415, "request body must be UTF-8")
                return
            try:
                guarded = await self._guard(payload)
            except WardenBlocked:
                await self._json_response(send, 400, "payload blocked by Warden")
                return
            except WardenError:
                await self._json_response(send, 503, "Warden scanner unavailable")
                return
            body_bytes = guarded.encode("utf-8")

        raw_path = scope.get("raw_path")
        if not isinstance(raw_path, bytes):
            raw_path = str(scope.get("path", "/")).encode("utf-8")
        query = scope.get("query_string", b"")
        if not isinstance(query, bytes):
            query = b""
        target = self.upstream.copy_with(
            raw_path=raw_path + (b"?" + query if query else b"")
        )
        upstream_headers = _filtered_headers(
            headers,
            strip_host=True,
            strip_content_length=True,
        )
        upstream_headers.append((b"content-length", str(len(body_bytes)).encode("ascii")))

        try:
            async with httpx.AsyncClient(
                timeout=self.upstream_timeout,
                follow_redirects=False,
                transport=self.transport,
                trust_env=False,
            ) as upstream_client:
                async with upstream_client.stream(
                    str(scope["method"]),
                    target,
                    headers=upstream_headers,
                    content=body_bytes,
                ) as upstream_response:
                    response_body = bytearray()
                    if upstream_response.is_stream_consumed:
                        response_body.extend(upstream_response.content)
                    else:
                        async for chunk in upstream_response.aiter_raw():
                            response_body.extend(chunk)
                            if len(response_body) > self.max_response_bytes:
                                await self._json_response(send, 502, "upstream response too large")
                                return
                    if len(response_body) > self.max_response_bytes:
                        await self._json_response(send, 502, "upstream response too large")
                        return
                    response_headers = _filtered_headers(
                        list(upstream_response.headers.raw),
                        strip_content_length=scope["method"] != "HEAD",
                    )
                    if scope["method"] != "HEAD":
                        response_headers.append(
                            (b"content-length", str(len(response_body)).encode("ascii"))
                        )
                    await send(
                        {
                            "type": "http.response.start",
                            "status": upstream_response.status_code,
                            "headers": response_headers,
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": bytes(response_body),
                            "more_body": False,
                        }
                    )
        except httpx.TimeoutException:
            await self._json_response(send, 504, "upstream timed out")
        except httpx.HTTPError:
            await self._json_response(send, 502, "upstream unavailable")

    async def _guard(self, payload: str) -> str:
        if isinstance(self.client, AsyncWardenClient):
            return await self.client.guard(payload)
        return await asyncio.to_thread(self.client.guard, payload)

    @staticmethod
    async def _json_response(
        send: Callable[[dict], Awaitable[None]], status: int, detail: str
    ) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    @staticmethod
    async def _lifespan(
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
