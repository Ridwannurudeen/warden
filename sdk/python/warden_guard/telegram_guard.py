"""Telegram adapter — guard untrusted chat text before a bot acts on it.

A Telegram bot reads text written by strangers and then does things: calls tools,
moves funds, answers with a model. That is exactly the boundary Warden exists to
sit on. This decorator puts the check between the message arriving and the handler
running.

    from warden_guard import AsyncWardenClient
    from warden_guard.telegram_guard import guard_message

    guard = AsyncWardenClient()

    @guard_message(guard)
    async def handle(update, context, safe_text: str) -> None:
        await update.message.reply_text(f"acting on: {safe_text}")

    app.add_handler(MessageHandler(filters.TEXT, handle))

The handler is called with ``safe_text`` — the original on ALLOW, the sanitized
text on SANITIZE — and is **not called at all** on BLOCK. The keyword is required
rather than optional on purpose: `telegram.Message` is frozen, so the raw
`update.message.text` still holds the poisoned string, and a handler that reads it
out of habit would defeat the guard. Taking `safe_text` explicitly makes the safe
value the obvious one to use.

Nothing here imports `python-telegram-bot` at runtime — the decorator only needs
``update.effective_message``. That keeps the adapter testable without the optional
dependency installed, and lets it work with any object of the same shape. Install
the real thing for the bot itself:

    pip install warden-agent-guard[telegram]

Both client types work. `AsyncWardenClient` is the right choice for hosted
scanning, where a synchronous call would block the event loop for the duration of
a network round trip; a local `WardenClient` is in-process and fast enough that
either is fine.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from warden_guard.client import WardenBlocked

if TYPE_CHECKING:  # pragma: no cover - typing only
    from telegram import Update
    from telegram.ext import ContextTypes

    OnBlock = Callable[[Update, ContextTypes.DEFAULT_TYPE, WardenBlocked], Awaitable[None]]


def _untrusted_text(update: Any, *, guard_captions: bool) -> str | None:
    """The strongest untrusted string on this update, or None if there is none.

    Captions ride on photos and documents and are just as attacker-controlled as
    a plain message, so they are guarded by default.
    """
    message = getattr(update, "effective_message", None)
    if message is None:
        return None
    text = getattr(message, "text", None)
    if isinstance(text, str) and text.strip():
        return text
    if guard_captions:
        caption = getattr(message, "caption", None)
        if isinstance(caption, str) and caption.strip():
            return caption
    return None


def guard_message(
    client: Any,
    *,
    on_block: Any = None,
    guard_captions: bool = True,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a Telegram handler so it only ever runs on Warden-approved text.

    ``on_block`` is awaited with ``(update, context, blocked)`` when a message is
    refused; ``blocked.result.threat_classes`` says why. It defaults to None —
    silence — because replying "blocked: DRAIN_ADDRESS" tells an attacker exactly
    which probe tripped the detector and lets them tune the next one.

    Updates carrying no text at all (a sticker, a join event) are passed through
    untouched: there is nothing to scan, and swallowing them would break the bot
    rather than protect it.
    """

    def decorator(handler: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(handler)
        async def wrapper(update: Any, context: Any, *args: Any, **kwargs: Any) -> Any:
            text = _untrusted_text(update, guard_captions=guard_captions)
            if text is None:
                return await handler(update, context, *args, **kwargs)

            try:
                # The call itself must be inside the try: a synchronous client
                # raises here, not at the await, so guarding only the await would
                # let a BLOCK escape to the caller on exactly the sync path.
                verdict = client.guard(text)
                safe_text = await verdict if inspect.isawaitable(verdict) else verdict
            except WardenBlocked as blocked:
                if on_block is not None:
                    await on_block(update, context, blocked)
                return None

            return await handler(update, context, *args, safe_text=safe_text, **kwargs)

        return wrapper

    return decorator
