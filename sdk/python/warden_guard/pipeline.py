"""Strict framework-neutral callables for text-processing pipelines."""

from __future__ import annotations

from typing import NewType

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import WardenClient

GuardedText = NewType("GuardedText", str)


class TextGuard:
    """Turn an explicit synchronous Warden client into a one-input text callable."""

    def __init__(self, client: WardenClient) -> None:
        self.client = client

    def __call__(self, payload: str) -> GuardedText:
        if not isinstance(payload, str):
            raise TypeError("payload must be a string")
        return GuardedText(self.client.guard(payload))


class AsyncTextGuard:
    """Turn an explicit asynchronous Warden client into an awaitable text callable."""

    def __init__(self, client: AsyncWardenClient) -> None:
        self.client = client

    async def __call__(self, payload: str) -> GuardedText:
        if not isinstance(payload, str):
            raise TypeError("payload must be a string")
        return GuardedText(await self.client.guard(payload))
