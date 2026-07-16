"""Paid-path HTTP semantics never mistake payment-required for an allow verdict."""

from __future__ import annotations

import httpx
import pytest

from warden_guard import AsyncWardenClient, WardenClient, WardenError

_REAL_CLIENT = httpx.Client
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _install_payment_required_transport(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(402, json={"error": "payment required"})

    transport = httpx.MockTransport(handler)

    def client_factory(**kwargs: object) -> httpx.Client:
        return _REAL_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    def async_client_factory(**kwargs: object) -> httpx.AsyncClient:
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(httpx, "AsyncClient", async_client_factory)
    return paths


def test_paid_sync_client_never_fail_opens_http_402(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _install_payment_required_transport(monkeypatch)

    with pytest.raises(WardenError, match="requires x402 payment"):
        WardenClient(paid=True, fail_open=True).scan("untrusted payload")

    assert paths == ["/scan"]


async def test_paid_async_client_never_fail_opens_http_402(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _install_payment_required_transport(monkeypatch)

    with pytest.raises(WardenError, match="requires x402 payment"):
        await AsyncWardenClient(paid=True, fail_open=True).scan("untrusted payload")

    assert paths == ["/scan"]
