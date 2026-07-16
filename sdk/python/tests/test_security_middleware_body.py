"""Security regressions for WardenGuard request-body handling."""

from __future__ import annotations

from collections.abc import Iterable

from warden_guard import AsyncWardenClient, ScanResult, WardenGuard


class RecordingClient(AsyncWardenClient):
    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def scan(
        self,
        payload: str,
        *,
        expected_addresses: list[str] | None = None,
        depth: str = "fast",
    ) -> ScanResult:
        self.payloads.append(payload)
        return ScanResult(verdict="ALLOW", risk_level="NONE", raw={"verdict": "ALLOW"})


async def _run_request(
    messages: Iterable[dict],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    max_body_bytes: int | None = None,
) -> tuple[list[dict], list[str], list[bytes]]:
    queued = iter(messages)
    responses: list[dict] = []
    delivered: list[bytes] = []
    client = RecordingClient()

    async def receive() -> dict:
        return next(queued, {"type": "http.disconnect"})

    async def send(message: dict) -> None:
        responses.append(message)

    async def downstream(scope: dict, receive_downstream, send_downstream) -> None:  # noqa: ANN001
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive_downstream()
            body.extend(message.get("body", b""))
            more_body = bool(message.get("more_body", False))
        delivered.append(bytes(body))
        await send_downstream({"type": "http.response.start", "status": 204, "headers": []})
        await send_downstream({"type": "http.response.body", "body": b""})

    middleware = WardenGuard(downstream, client=client)
    if max_body_bytes is not None:
        middleware = WardenGuard(downstream, client=client, max_body_bytes=max_body_bytes)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": headers or [],
        },
        receive,
        send,
    )
    return responses, client.payloads, delivered


async def test_non_identity_content_encoding_is_rejected_before_scan_or_downstream() -> None:
    responses, scanned, delivered = await _run_request(
        [{"type": "http.request", "body": b"compressed", "more_body": False}],
        headers=[(b"content-encoding", b"gzip")],
    )

    assert responses[0]["status"] == 415
    assert scanned == []
    assert delivered == []


async def test_invalid_utf8_is_rejected_before_scan_or_downstream() -> None:
    responses, scanned, delivered = await _run_request(
        [{"type": "http.request", "body": b"safe\xffpoison", "more_body": False}]
    )

    assert responses[0]["status"] == 415
    assert scanned == []
    assert delivered == []


async def test_oversized_stream_is_rejected_before_scan_or_downstream() -> None:
    responses, scanned, delivered = await _run_request(
        [
            {"type": "http.request", "body": b"abcd", "more_body": True},
            {"type": "http.request", "body": b"e", "more_body": False},
        ],
        max_body_bytes=4,
    )

    assert responses[0]["status"] == 413
    assert scanned == []
    assert delivered == []


async def test_premature_disconnect_aborts_before_scan_or_downstream() -> None:
    responses, scanned, delivered = await _run_request(
        [
            {"type": "http.request", "body": b"partial", "more_body": True},
            {"type": "http.disconnect"},
        ]
    )

    assert responses == []
    assert scanned == []
    assert delivered == []


async def test_invalid_asgi_message_is_rejected_before_scan_or_downstream() -> None:
    responses, scanned, delivered = await _run_request(
        [{"type": "websocket.receive", "bytes": b"not an HTTP request"}]
    )

    assert responses[0]["status"] == 400
    assert scanned == []
    assert delivered == []


async def test_allow_scans_and_forwards_the_same_utf8_bytes() -> None:
    body = 'payment note: café'.encode()
    responses, scanned, delivered = await _run_request(
        [
            {"type": "http.request", "body": body[:10], "more_body": True},
            {"type": "http.request", "body": body[10:], "more_body": False},
        ],
        headers=[(b"content-encoding", b"identity")],
        max_body_bytes=len(body),
    )

    assert responses[0]["status"] == 204
    assert [payload.encode() for payload in scanned] == [body]
    assert delivered == [body]
