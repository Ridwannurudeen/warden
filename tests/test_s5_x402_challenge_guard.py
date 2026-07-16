"""Regression coverage for malformed x402 challenge pass-through."""

import base64

import pytest
from fastapi import Request
from fastapi.responses import Response

from warden.api import payment_required_schema_middleware


def _encoded(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "challenge",
    [
        "not-base64%%",
        _encoded("not-json"),
        _encoded("[" * 3000 + "]" * 3000),
        _encoded("[]"),
        _encoded('{"resource":{}}'),
        _encoded('{"resource":{"url":1},"accepts":[]}'),
        _encoded(
            '{"resource":{"url":"https://warden.gudman.xyz/scan"},"accepts":null}'
        ),
    ],
)
async def test_malformed_payment_challenge_passes_original_response_through(challenge):
    original = Response(
        content=b"payment required",
        status_code=402,
        headers={"PAYMENT-REQUIRED": challenge},
    )

    async def call_next(request: Request) -> Response:
        return original

    result = await payment_required_schema_middleware(None, call_next)

    assert result is original
    assert result.status_code == 402
    assert result.headers["PAYMENT-REQUIRED"] == challenge
    assert result.body == b"payment required"
