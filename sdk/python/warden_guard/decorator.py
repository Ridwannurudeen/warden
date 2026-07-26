"""`@guard(...)` and `@guard_output(...)` — wrap any function around untrusted text.

    from warden_guard import WardenClient, guard, guard_output

    warden = WardenClient(local=True)

    @guard(warden, field="payload")           # scans an INPUT argument
    def handle(payload: str) -> str:
        return act_on(payload)

    @guard_output(warden)                      # scans the RETURN value
    def fetch_tool_result(query: str) -> str:
        return call_untrusted_tool(query)

`@guard` scans the named argument before the function runs. `@guard_output`
scans the function's return value before it is handed back — the dominant agent
pattern, where a tool's output re-enters the model context. Both map the verdict
the same way: BLOCK raises WardenBlocked, SANITIZE substitutes the sanitized
text, ALLOW passes through. Async functions are supported with an
AsyncWardenClient.
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


def guard_output(
    client: WardenClient | AsyncWardenClient | None = None,
) -> Callable[[F], F]:
    """Decorator factory: scan the function's return value before handing it back.

    Use this on a tool whose output re-enters the model context — the dominant
    agent pattern (guard what the tool *returned*, not what it was called with).
    The return value is coerced to text and scanned: BLOCK raises WardenBlocked,
    SANITIZE returns the sanitized text, ALLOW returns the original text. Async
    functions are supported with an AsyncWardenClient.
    """

    def decorate(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):
            guard_client = client or AsyncWardenClient()
            if not isinstance(guard_client, AsyncWardenClient):
                raise TypeError("@guard_output on an async function requires an AsyncWardenClient")

            @functools.wraps(fn)
            async def async_wrapper(*args: object, **kwargs: object) -> object:
                result = await fn(*args, **kwargs)
                return await guard_client.guard(str(result))

            return async_wrapper  # type: ignore[return-value]

        sync_client = client or WardenClient()
        if isinstance(sync_client, AsyncWardenClient):
            raise TypeError("@guard_output on a sync function requires a sync WardenClient")

        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            result = fn(*args, **kwargs)
            return sync_client.guard(str(result))

        return wrapper  # type: ignore[return-value]

    return decorate
