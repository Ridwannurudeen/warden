"""Hosted-client verdict mapping, guard() enforcement, and fail_open semantics."""

from __future__ import annotations

import json

import httpx
import pytest

from warden_guard import AsyncWardenClient, WardenBlocked, WardenClient, WardenError
from warden_guard.state import get_scan_count

_REAL_CLIENT = httpx.Client
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _verdict_body(verdict: str, **extra: object) -> dict[str, object]:
    return {
        "verdict": verdict,
        "risk_level": "HIGH" if verdict != "ALLOW" else "NONE",
        "threat_classes": ["SECRET_EXFIL"] if verdict == "BLOCK" else [],
        "detections": [],
        "sanitized_payload": extra.get("sanitized_payload", ""),
        "recommendation": "test",
        "checks": {"injection": "pass"},
        "latency_ms": 0.5,
        **extra,
    }


def _mock_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    transport = httpx.MockTransport(handler)

    def client_factory(**kwargs: object) -> httpx.Client:
        return _REAL_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    def async_client_factory(**kwargs: object) -> httpx.AsyncClient:
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(httpx, "AsyncClient", async_client_factory)


def _static_handler(body: dict[str, object]):  # noqa: ANN202
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return handler


def test_scan_maps_block_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("BLOCK")))
    result = WardenClient().scan("evil")
    assert result.blocked and not result.allowed and not result.sanitized
    assert result.threat_classes == ["SECRET_EXFIL"]
    assert result.safe_payload is None
    assert get_scan_count() == 1


def test_scan_maps_sanitize_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(
        monkeypatch, _static_handler(_verdict_body("SANITIZE", sanitized_payload="clean text"))
    )
    result = WardenClient().scan("dirty")
    assert result.sanitized
    assert result.safe_payload == "clean text"


def test_scan_maps_allow_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("ALLOW")))
    result = WardenClient().scan("hello")
    assert result.allowed


def test_guard_raises_on_block(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("BLOCK")))
    with pytest.raises(WardenBlocked) as excinfo:
        WardenClient().guard("evil")
    assert "SECRET_EXFIL" in str(excinfo.value)


def test_guard_returns_sanitized_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("SANITIZE", sanitized_payload="clean")))
    assert WardenClient().guard("dirty") == "clean"


def test_guard_passes_allow_through(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("ALLOW")))
    assert WardenClient().guard("hello") == "hello"


def test_fail_open_default_returns_allow_on_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _mock_httpx(monkeypatch, handler)
    client = WardenClient()
    assert client.fail_open is True  # free tier = best-effort, not enforcement
    result = client.scan("anything")
    assert result.allowed
    assert "down" in str(result.raw["error"])
    assert get_scan_count() == 0


def test_fail_closed_raises_on_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _mock_httpx(monkeypatch, handler)
    with pytest.raises(WardenError):
        WardenClient(fail_open=False).scan("anything")
    assert get_scan_count() == 0


def test_malformed_success_response_is_not_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler({"risk_level": "NONE"}))
    with pytest.raises(WardenError, match="verdict"):
        WardenClient().scan("anything")
    assert get_scan_count() == 0


def test_request_body_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=_verdict_body("ALLOW"))

    _mock_httpx(monkeypatch, handler)
    WardenClient().scan("hello", expected_addresses=["0xabc"])
    assert seen["path"] == "/api/demo/scan"
    assert seen["body"] == {
        "payload": "hello",
        "depth": "fast",
        "context": {"expected_addresses": ["0xabc"]},
    }


def test_paid_client_uses_scan_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json=_verdict_body("ALLOW"))

    _mock_httpx(monkeypatch, handler)
    WardenClient(paid=True).scan("hello")
    assert seen["path"] == "/scan"


async def test_async_client_same_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("SANITIZE", sanitized_payload="clean")))
    client = AsyncWardenClient()
    assert client.fail_open is True
    result = await client.scan("dirty")
    assert result.sanitized
    assert await client.guard("dirty") == "clean"


async def test_async_guard_raises_on_block(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_httpx(monkeypatch, _static_handler(_verdict_body("BLOCK")))
    with pytest.raises(WardenBlocked):
        await AsyncWardenClient().guard("evil")


async def test_async_fail_open_outage_is_not_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _mock_httpx(monkeypatch, handler)
    result = await AsyncWardenClient().scan("anything")
    assert result.allowed
    assert get_scan_count() == 0


async def test_async_malformed_success_response_is_not_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_httpx(monkeypatch, _static_handler({"verdict": "MAYBE"}))
    with pytest.raises(WardenError, match="verdict"):
        await AsyncWardenClient().scan("anything")
    assert get_scan_count() == 0
