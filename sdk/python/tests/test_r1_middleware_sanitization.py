"""R1 integration coverage for middleware SANITIZE enforcement."""

from __future__ import annotations

import json

from warden_guard import ScanResult, WardenClient, WardenGuard


class StubClient(WardenClient):
    def __init__(self, sanitized_payload: str | None) -> None:
        self.result = ScanResult(
            verdict="SANITIZE",
            risk_level="HIGH",
            sanitized_payload=sanitized_payload,
            raw={"verdict": "SANITIZE"},
        )

    def scan(self, payload: str, **kwargs: object) -> ScanResult:  # type: ignore[override]
        return self.result


async def _request(app, body: bytes) -> tuple[list[dict], list[bytes], list[dict]]:  # noqa: ANN001
    sent = False
    responses: list[dict] = []
    delivered: list[bytes] = []
    delivered_scopes: list[dict] = []

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        responses.append(message)

    async def downstream(scope: dict, receive_downstream, send_downstream) -> None:  # noqa: ANN001
        message = await receive_downstream()
        delivered.append(message["body"])
        delivered_scopes.append(scope)
        await send_downstream({"type": "http.response.start", "status": 204, "headers": []})
        await send_downstream({"type": "http.response.body", "body": b""})

    middleware = app(downstream)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-length", str(len(body)).encode())],
        },
        receive,
        send,
    )
    return responses, delivered, delivered_scopes


async def test_downstream_receives_only_the_sanitized_body() -> None:
    responses, delivered, scopes = await _request(
        lambda downstream: WardenGuard(downstream, client=StubClient("safe")),
        b"dirty payload",
    )

    assert responses[0]["status"] == 204
    assert delivered == [b"safe"]
    assert dict(scopes[0]["headers"])[b"content-length"] == b"4"


async def test_custom_extraction_blocks_when_the_body_cannot_be_safely_rewritten() -> None:
    responses, delivered, _ = await _request(
        lambda downstream: WardenGuard(
            downstream,
            client=StubClient("safe"),
            extract=lambda body, _scope: json.loads(body)["message"],
        ),
        b'{"message":"dirty payload"}',
    )

    assert responses[0]["status"] == 400
    assert delivered == []
