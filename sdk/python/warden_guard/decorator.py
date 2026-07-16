"""`@guard(...)` — wrap any function that takes untrusted text.

    from warden_guard import WardenClient, guard

    warden = WardenClient(local=True)

    @guard(warden, field="payload")
    def handle(payload: str) -> str:
        return act_on(payload)

The named argument is scanned before the function runs: BLOCK raises
WardenBlocked, SANITIZE substitutes the sanitized text, ALLOW passes through.
Async functions are supported with an AsyncWardenClient.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import TypeVar

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import WardenClient

F = TypeVar("F", bound=Callable)


def guard(
    client: WardenClient | AsyncWardenClient | None = None,
    *,
    field: str = "payload",
) -> Callable[[F], F]:
    """Decorator factory: scan the `field` argument through Warden before the call."""

    def decorate(fn: F) -> F:
        signature = inspect.signature(fn)
        if field not in signature.parameters:
            raise TypeError(f"@guard: {fn.__name__} has no parameter '{field}'")

        if inspect.iscoroutinefunction(fn):
            guard_client = client or AsyncWardenClient()
            if not isinstance(guard_client, AsyncWardenClient):
                raise TypeError("@guard on an async function requires an AsyncWardenClient")

            @functools.wraps(fn)
            async def async_wrapper(*args: object, **kwargs: object) -> object:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                bound.arguments[field] = await guard_client.guard(str(bound.arguments[field]))
                return await fn(*bound.args, **bound.kwargs)

            return async_wrapper  # type: ignore[return-value]

        sync_client = client or WardenClient()
        if isinstance(sync_client, AsyncWardenClient):
            raise TypeError("@guard on a sync function requires a sync WardenClient")

        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            bound.arguments[field] = sync_client.guard(str(bound.arguments[field]))
            return fn(*bound.args, **bound.kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
