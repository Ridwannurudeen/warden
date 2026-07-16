"""Regression tests for guarded parameters that use function defaults."""

from __future__ import annotations

from warden_guard import AsyncWardenClient, WardenClient, guard


class StubClient(WardenClient):
    def __init__(self) -> None:
        self.payloads: list[str] = []

    def guard(self, payload: str, **kwargs: object) -> str:
        self.payloads.append(payload)
        return "clean"


class AsyncStubClient(AsyncWardenClient):
    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def guard(self, payload: str, **kwargs: object) -> str:
        self.payloads.append(payload)
        return "clean"


def test_sync_decorator_guards_a_defaulted_argument() -> None:
    client = StubClient()

    @guard(client, field="payload")
    def handle(prefix: str, payload: str = "unsafe") -> str:
        return f"{prefix}:{payload}"

    assert handle("result") == "result:clean"
    assert client.payloads == ["unsafe"]


async def test_async_decorator_guards_a_defaulted_argument() -> None:
    client = AsyncStubClient()

    @guard(client, field="payload")
    async def handle(prefix: str, payload: str = "unsafe") -> str:
        return f"{prefix}:{payload}"

    assert await handle("result") == "result:clean"
    assert client.payloads == ["unsafe"]
