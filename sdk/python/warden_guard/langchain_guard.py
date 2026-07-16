"""LangChain adapter — guard untrusted text inside an LCEL chain.

Optional integration. Requires LangChain:

    pip install warden-guard[langchain]

Drop the guard between an untrusted source and the model so poisoned input never
reaches the LLM:

    from warden_guard import WardenClient
    from warden_guard.langchain_guard import WardenGuardRunnable

    guard = WardenGuardRunnable(WardenClient(local=True, fail_open=False))
    chain = retriever | guard | prompt | model

`invoke` returns the safe text (original on ALLOW, sanitized on SANITIZE) and
raises `WardenBlocked` on BLOCK, stopping the chain. Async chains work through
the inherited `ainvoke`, which runs the guard in a worker thread.
"""

from __future__ import annotations

from typing import Any

try:
    from langchain_core.runnables import Runnable, RunnableConfig
except ImportError as exc:  # pragma: no cover - exercised only without LangChain
    raise ImportError(
        "warden_guard.langchain_guard requires LangChain; install warden-guard[langchain]"
    ) from exc

from warden_guard.client import WardenClient


class WardenGuardRunnable(Runnable[str, str]):
    """An LCEL Runnable that enforces a Warden verdict on a text input."""

    def __init__(self, client: WardenClient) -> None:
        self.client = client

    def invoke(self, input: str, config: RunnableConfig | None = None, **kwargs: Any) -> str:
        if not isinstance(input, str):
            raise TypeError("input must be a string")
        return self.client.guard(input)
