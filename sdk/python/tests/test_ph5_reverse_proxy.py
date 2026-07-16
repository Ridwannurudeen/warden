"""PH5 standalone reverse-proxy boundary regressions."""

from __future__ import annotations

import httpx
import pytest

from warden_guard import AsyncWardenClient, ScanResult, WardenBlocked, WardenClient, WardenError
from warden_guard.cli import main as cli_main
from warden_guard.proxy import WardenReverseProxy


class StubGuard(AsyncWardenClient):
    def __init__(self, safe_payload: str | None = None, error: Exception | None = None) -> None:
        self.fail_open = False
        self.safe_payload = safe_payload
        self.error = error
        self.payloads: list[str] = []

    async def guard(self, payload: str, **kwargs: object) -> str:
        self.payloads.append(payload)
        if self.error is not None:
            raise self.error
        return payload if self.safe_payload is None else self.safe_payload


def _blocked() -> WardenBlocked:
    return WardenBlocked(
        ScanResult(
            verdict="BLOCK",
            risk_level="HIGH",
            threat_classes=["PROMPT_INJECTION"],
            sanitized_payload="",
            raw={"verdict": "BLOCK"},
        )
    )


async def _request(app: WardenReverseProxy, method: str = "POST", **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy.test",
    ) as client:
        return await client.request(method, "/v1/run?mode=fast", **kwargs)


async def test_allow_preserves_method_path_query_and_strips_hop_headers():
    upstream_requests: list[httpx.Request] = []

    async def upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            201,
            content=b"accepted",
            headers={"connection": "close", "x-upstream": "yes"},
        )

    guard = StubGuard()
    app = WardenReverseProxy(
        "http://upstream.test",
        client=guard,
        transport=httpx.MockTransport(upstream),
    )
    response = await _request(
        app,
        content=b"safe request",
        headers={"connection": "x-remove", "x-remove": "secret", "x-keep": "yes"},
    )

    assert response.status_code == 201
    assert response.content == b"accepted"
    assert response.headers["x-upstream"] == "yes"
    assert "connection" not in response.headers
    [request] = upstream_requests
    assert request.method == "POST"
    assert request.url == "http://upstream.test/v1/run?mode=fast"
    assert request.content == b"safe request"
    assert request.headers["x-keep"] == "yes"
    assert "x-remove" not in request.headers
    assert request.headers["content-length"] == str(len(b"safe request"))
    assert guard.payloads == ["safe request"]


async def test_sanitize_forwards_only_the_rewritten_body_once():
    delivered: list[bytes] = []

    async def upstream(request: httpx.Request) -> httpx.Response:
        delivered.append(await request.aread())
        return httpx.Response(204)

    app = WardenReverseProxy(
        "http://upstream.test",
        client=StubGuard("clean"),
        transport=httpx.MockTransport(upstream),
    )
    response = await _request(app, content=b"dirty")

    assert response.status_code == 204
    assert delivered == [b"clean"]


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [(_blocked(), 400), (WardenError("scanner unavailable"), 503)],
)
async def test_block_or_scanner_failure_never_reaches_upstream(error, expected_status):
    upstream_calls = 0

    async def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    app = WardenReverseProxy(
        "http://upstream.test",
        client=StubGuard(error=error),
        transport=httpx.MockTransport(upstream),
    )
    response = await _request(app, content=b"untrusted")

    assert response.status_code == expected_status
    assert upstream_calls == 0


async def test_oversize_and_non_utf8_bodies_fail_before_scanning_or_forwarding():
    upstream_calls = 0

    async def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    guard = StubGuard()
    app = WardenReverseProxy(
        "http://upstream.test",
        client=guard,
        max_body_bytes=4,
        transport=httpx.MockTransport(upstream),
    )

    oversize = await _request(app, content=b"12345")
    invalid = await _request(app, content=b"\xff")

    assert oversize.status_code == 413
    assert invalid.status_code == 415
    assert upstream_calls == 0
    assert guard.payloads == []


async def test_upstream_timeout_is_bounded_and_reported_as_gateway_timeout():
    async def upstream(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow upstream", request=request)

    app = WardenReverseProxy(
        "http://upstream.test",
        client=StubGuard(),
        upstream_timeout=0.25,
        transport=httpx.MockTransport(upstream),
    )

    response = await _request(app, content=b"safe")

    assert response.status_code == 504


async def test_proxy_loop_is_rejected_before_forwarding():
    upstream_calls = 0

    async def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200)

    app = WardenReverseProxy(
        "http://proxy.test",
        client=StubGuard(),
        transport=httpx.MockTransport(upstream),
    )

    response = await _request(app, content=b"safe")

    assert response.status_code == 508
    assert upstream_calls == 0


def test_proxy_rejects_fail_open_scanners_and_non_origin_upstreams():
    with pytest.raises(ValueError, match="fail_open=False"):
        WardenReverseProxy("http://upstream.test", client=WardenClient())
    for upstream in (
        "ftp://upstream.test",
        "http://user:secret@upstream.test",
        "http://upstream.test/prefix",
        "http://upstream.test?query=1",
    ):
        with pytest.raises(ValueError, match="upstream"):
            WardenReverseProxy(upstream, client=StubGuard())


def test_proxy_cli_builds_a_fail_closed_app_without_starting_network(monkeypatch):
    started: list[tuple[WardenReverseProxy, str, int]] = []

    def run(app, *, host, port):
        started.append((app, host, port))

    monkeypatch.setattr("uvicorn.run", run)

    result = cli_main(
        [
            "proxy",
            "--upstream",
            "http://upstream.test",
            "--warden-url",
            "http://warden.test",
            "--listen",
            "127.0.0.1",
            "--port",
            "9080",
        ]
    )

    assert result == 0
    [(app, host, port)] = started
    assert isinstance(app, WardenReverseProxy)
    assert app.client.fail_open is False
    assert host == "127.0.0.1"
    assert port == 9080
