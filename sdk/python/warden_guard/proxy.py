"""Fail-closed standalone ASGI reverse proxy guarded by Warden."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from warden_guard.aio import AsyncWardenClient
from warden_guard.apa import sign_document
from warden_guard.client import (
    FREE_PATH,
    ScanResult,
    WardenBlocked,
    WardenClient,
)
from warden_guard.keys import load_or_create_key, public_key_str

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
_HEALTH_PATH = "/healthz"
_METRICS_PATH = "/metrics"


class _GatewayMetrics:
    def __init__(self) -> None:
        self.started_at = time.monotonic()
        self.decisions = 0
        self.blocks = 0
        self.sanitizations = 0
        self.failures = 0
        self.scanner_latency_count = 0
        self.scanner_latency_sum = 0.0
        self.upstream_latency_count = 0
        self.upstream_latency_sum = 0.0

    def observe_decision(self, result: ScanResult) -> None:
        self.decisions += 1
        if result.verdict == "BLOCK":
            self.blocks += 1
        elif result.verdict == "SANITIZE":
            self.sanitizations += 1

    def observe_failure(self) -> None:
        self.failures += 1

    def observe_scanner_latency(self, elapsed: float) -> None:
        self.scanner_latency_count += 1
        self.scanner_latency_sum += elapsed

    def observe_upstream_latency(self, elapsed: float) -> None:
        self.upstream_latency_count += 1
        self.upstream_latency_sum += elapsed

    def render(self, in_flight: int) -> bytes:
        uptime = max(0.0, time.monotonic() - self.started_at)
        lines = (
            "# HELP warden_gateway_decisions_total Scanner decisions returned.",
            "# TYPE warden_gateway_decisions_total counter",
            f"warden_gateway_decisions_total {self.decisions}",
            "# HELP warden_gateway_blocks_total Requests blocked before upstream forwarding.",
            "# TYPE warden_gateway_blocks_total counter",
            f"warden_gateway_blocks_total {self.blocks}",
            "# HELP warden_gateway_sanitizations_total Sanitized requests forwarded upstream.",
            "# TYPE warden_gateway_sanitizations_total counter",
            f"warden_gateway_sanitizations_total {self.sanitizations}",
            "# HELP warden_gateway_failures_total Gateway failures that prevented forwarding.",
            "# TYPE warden_gateway_failures_total counter",
            f"warden_gateway_failures_total {self.failures}",
            "# HELP warden_gateway_scanner_latency_seconds Scanner call latency.",
            "# TYPE warden_gateway_scanner_latency_seconds summary",
            (f"warden_gateway_scanner_latency_seconds_count {self.scanner_latency_count}"),
            (f"warden_gateway_scanner_latency_seconds_sum {self.scanner_latency_sum:.9f}"),
            "# HELP warden_gateway_upstream_latency_seconds Upstream request latency.",
            "# TYPE warden_gateway_upstream_latency_seconds summary",
            (f"warden_gateway_upstream_latency_seconds_count {self.upstream_latency_count}"),
            (f"warden_gateway_upstream_latency_seconds_sum {self.upstream_latency_sum:.9f}"),
            "# HELP warden_gateway_in_flight_requests Requests currently being handled.",
            "# TYPE warden_gateway_in_flight_requests gauge",
            f"warden_gateway_in_flight_requests {in_flight}",
            "# HELP warden_gateway_uptime_seconds Process uptime.",
            "# TYPE warden_gateway_uptime_seconds gauge",
            f"warden_gateway_uptime_seconds {uptime:.3f}",
        )
        return ("\n".join(lines) + "\n").encode("ascii")


def _write_signed_verdict(record: dict[str, object]) -> None:
    print(
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        flush=True,
    )


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
        max_body_bytes: int = 100_000,
        max_response_bytes: int = 10_000_000,
        upstream_timeout: float = 8.0,
        transport: httpx.AsyncBaseTransport | None = None,
        verdict_log: Callable[[dict[str, object]], None] = _write_signed_verdict,
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

        if client is None:
            raise ValueError("reverse-proxy enforcement requires an explicit enforcement client")
        configured_client = client
        if configured_client.fail_open:
            raise ValueError("reverse-proxy enforcement requires a client with fail_open=False")
        if getattr(configured_client, "path", None) == FREE_PATH and not getattr(
            configured_client, "local", False
        ):
            raise ValueError("reverse-proxy enforcement cannot use the free hosted demo client")
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
        self.verdict_log = verdict_log
        self.signing_key = load_or_create_key()
        self.guard_pub = public_key_str(self.signing_key)
        self.metrics = _GatewayMetrics()
        self._closing = False
        self._in_flight = 0
        self._drained = asyncio.Event()
        self._drained.set()

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

        if await self._internal_response(scope, send):
            return
        if self._closing:
            await self._failure_response(send, 503, "gateway is shutting down")
            return

        self._in_flight += 1
        self._drained.clear()
        try:
            await self._proxy_request(scope, receive, send)
        finally:
            self._in_flight -= 1
            if self._in_flight == 0:
                self._drained.set()

    async def _proxy_request(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        headers = list(scope.get("headers", []))
        host = next(
            (value.decode("latin-1") for name, value in headers if name.lower() == b"host"),
            "",
        )
        if _host_identity(host, str(scope.get("scheme", "http"))) == self.upstream_identity:
            await self._failure_response(send, 508, "proxy loop detected")
            return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await self._failure_response(send, 400, "invalid ASGI request stream")
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_body_bytes:
                await self._failure_response(send, 413, "request body too large")
                return
            more_body = bool(message.get("more_body", False))

        body_bytes = bytes(body)
        if body_bytes:
            request_id = secrets.token_hex(16)
            try:
                payload = body_bytes.decode("utf-8")
            except UnicodeDecodeError:
                await self._failure_response(send, 415, "request body must be UTF-8")
                return
            try:
                guarded = await self._guard(payload, request_id=request_id)
            except WardenBlocked:
                await self._json_response(send, 403, "payload blocked by Warden")
                return
            except Exception:
                await self._failure_response(send, 503, "Warden scanner unavailable")
                return
            body_bytes = guarded.encode("utf-8")

        raw_path = scope.get("raw_path")
        if not isinstance(raw_path, bytes):
            raw_path = str(scope.get("path", "/")).encode("utf-8")
        query = scope.get("query_string", b"")
        if not isinstance(query, bytes):
            query = b""
        target = self.upstream.copy_with(raw_path=raw_path + (b"?" + query if query else b""))
        upstream_headers = _filtered_headers(
            headers,
            strip_host=True,
            strip_content_length=True,
        )
        upstream_headers.append((b"content-length", str(len(body_bytes)).encode("ascii")))

        upstream_started_at = time.monotonic()
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
                                await self._failure_response(
                                    send,
                                    502,
                                    "upstream response too large",
                                )
                                return
                    if len(response_body) > self.max_response_bytes:
                        await self._failure_response(send, 502, "upstream response too large")
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
            await self._failure_response(send, 504, "upstream timed out")
        except httpx.HTTPError:
            await self._failure_response(send, 502, "upstream unavailable")
        finally:
            self.metrics.observe_upstream_latency(time.monotonic() - upstream_started_at)

    async def _guard(self, payload: str, *, request_id: str) -> str:
        scanner_started_at = time.monotonic()
        try:
            if isinstance(self.client, AsyncWardenClient):
                result = await self.client.scan(payload)
            else:
                result = await asyncio.to_thread(self.client.scan, payload)
        except WardenBlocked as exc:
            result = exc.result
            self.metrics.observe_decision(result)
            self._log_verdict(result, request_id=request_id)
            raise
        finally:
            self.metrics.observe_scanner_latency(time.monotonic() - scanner_started_at)
        self.metrics.observe_decision(result)
        self._log_verdict(result, request_id=request_id)
        if result.blocked:
            raise WardenBlocked(result)
        if result.sanitized and result.sanitized_payload is not None:
            return result.sanitized_payload
        return payload

    def _log_verdict(self, result: ScanResult, *, request_id: str) -> None:
        record = sign_document(
            {
                "event": "warden.gateway.verdict",
                "request_id": request_id,
                "ts": int(time.time()),
                "verdict": result.verdict,
                "risk_level": result.risk_level,
                "threat_classes": list(result.threat_classes),
                "latency_ms": result.latency_ms,
                "guard_pub": self.guard_pub,
            },
            self.signing_key,
            sig_field="sig",
        )
        self.verdict_log(record)

    async def _internal_response(
        self,
        scope: dict,
        send: Callable[[dict], Awaitable[None]],
    ) -> bool:
        path = scope.get("path")
        if path not in {_HEALTH_PATH, _METRICS_PATH}:
            return False
        if scope.get("method") != "GET":
            await self._json_response(send, 405, "method not allowed")
            return True
        if path == _HEALTH_PATH:
            status = 503 if self._closing else 200
            detail = "shutting_down" if self._closing else "ok"
            body = json.dumps({"status": detail}, separators=(",", ":")).encode("ascii")
            await self._response(send, status, b"application/json", body)
            return True
        body = self.metrics.render(self._in_flight)
        await self._response(
            send,
            200,
            b"text/plain; version=0.0.4; charset=utf-8",
            body,
        )
        return True

    async def _failure_response(
        self,
        send: Callable[[dict], Awaitable[None]],
        status: int,
        detail: str,
    ) -> None:
        self.metrics.observe_failure()
        await self._json_response(send, status, detail)

    @staticmethod
    async def _json_response(
        send: Callable[[dict], Awaitable[None]], status: int, detail: str
    ) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await WardenReverseProxy._response(send, status, b"application/json", body)

    @staticmethod
    async def _response(
        send: Callable[[dict], Awaitable[None]],
        status: int,
        content_type: bytes,
        body: bytes,
    ) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _lifespan(
        self,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self._closing = True
                await self._drained.wait()
                await send({"type": "lifespan.shutdown.complete"})
                return
