import httpx
import pytest

from warden_guard import AsyncWardenClient, WardenClient, WardenError


def test_free_sync_client_rejects_thorough_depth_before_network(monkeypatch):
    def unexpected_client(**kwargs):
        raise AssertionError("free thorough requests must not reach the network")

    monkeypatch.setattr(httpx, "Client", unexpected_client)

    with pytest.raises(WardenError, match="free hosted"):
        WardenClient(fail_open=False).scan("payload", depth="thorough")


@pytest.mark.asyncio
async def test_free_async_client_rejects_thorough_depth_before_network(monkeypatch):
    def unexpected_client(**kwargs):
        raise AssertionError("free thorough requests must not reach the network")

    monkeypatch.setattr(httpx, "AsyncClient", unexpected_client)

    with pytest.raises(WardenError, match="free hosted"):
        await AsyncWardenClient(fail_open=False).scan("payload", depth="thorough")
