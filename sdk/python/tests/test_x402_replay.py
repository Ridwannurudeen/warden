"""Opt-in x402 signing and one-replay lifecycle coverage."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import warden_guard.client as client_module

from warden_guard import (
    AsyncWardenClient,
    WardenClient,
    WardenError,
    X402Challenge,
)

_REAL_CLIENT = httpx.Client
_REAL_ASYNC_CLIENT = httpx.AsyncClient
_RESOURCE_URL = "https://warden.gudman.xyz/scan"
_PAY_TO = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51"
_NOW = 1_700_000_000


def _encode(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(raw).decode("ascii")


def _requirement(**changes: object) -> dict[str, object]:
    return {
        "scheme": "exact",
        "network": "eip155:196",
        "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
        "amount": "100000",
        "payTo": _PAY_TO,
        "maxTimeoutSeconds": 300,
        "extra": {"name": "USD₮0", "version": "1"},
        **changes,
    }


def _challenge(**changes: object) -> str:
    document: dict[str, object] = {
        "x402Version": 2,
        "error": "Payment required",
        "resource": {
            "url": _RESOURCE_URL,
            "description": "Warden payload security scan",
            "mimeType": "application/json",
        },
        "accepts": [_requirement()],
    }
    document.update(changes)
    return _encode(document)


def _payment_header(
    challenge: X402Challenge,
    *,
    accepted_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    resource_url: str | None = None,
) -> str:
    accepted = challenge.requirement.to_dict()
    accepted.update(accepted_changes or {})
    authorization = {
        "from": "0x1111111111111111111111111111111111111111",
        "to": challenge.requirement.pay_to,
        "value": challenge.requirement.amount,
        "validAfter": str(_NOW - 600),
        "validBefore": str(_NOW + 300),
        "nonce": "0x" + "22" * 32,
    }
    authorization.update(authorization_changes or {})
    return _encode(
        {
            "x402Version": 2,
            "payload": {
                "authorization": authorization,
                "signature": "0x" + "33" * 65,
            },
            "accepted": accepted,
            "resource": {"url": resource_url or challenge.resource_url},
        }
    )


def _settlement_header(**changes: object) -> str:
    document: dict[str, object] = {
        "success": True,
        "payer": "0x1111111111111111111111111111111111111111",
        "transaction": "0x" + "44" * 32,
        "network": "eip155:196",
    }
    document.update(changes)
    return _encode(document)


def _scan_response() -> dict[str, object]:
    return {
        "verdict": "ALLOW",
        "risk_level": "NONE",
        "threat_classes": [],
        "detections": [],
        "sanitized_payload": "",
        "recommendation": "No implemented detector fired.",
        "checks": {"injection": "pass"},
        "latency_ms": 0.5,
    }


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler,
) -> None:  # noqa: ANN001
    transport = httpx.MockTransport(handler)

    def client_factory(**kwargs: object) -> httpx.Client:
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return _REAL_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    def async_client_factory(**kwargs: object) -> httpx.AsyncClient:
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "Client", client_factory)
    monkeypatch.setattr(httpx, "AsyncClient", async_client_factory)
    monkeypatch.setattr(client_module, "_current_unix_time", lambda: _NOW)


def test_sync_payment_handler_receives_validated_terms_and_replays_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    callbacks: list[X402Challenge] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                402,
                headers={"PAYMENT-REQUIRED": _challenge()},
            )
        return httpx.Response(
            200,
            headers={"PAYMENT-RESPONSE": _settlement_header()},
            json=_scan_response(),
        )

    def payment_handler(challenge: X402Challenge) -> str:
        callbacks.append(challenge)
        return _payment_header(challenge)

    _install_transport(monkeypatch, handler)
    result = WardenClient(
        paid=True,
        fail_open=True,
        payment_handler=payment_handler,
    ).scan("untrusted", expected_addresses=["0xabc"], depth="thorough")

    assert result.allowed
    assert len(callbacks) == 1
    assert callbacks[0].to_dict() == {
        "x402Version": 2,
        "resource": {"url": _RESOURCE_URL},
        "accepts": [_requirement()],
    }
    assert [str(request.url) for request in requests] == [_RESOURCE_URL, _RESOURCE_URL]
    assert requests[0].content == requests[1].content
    assert requests[0].headers.get("PAYMENT-SIGNATURE") is None
    assert requests[1].headers["PAYMENT-SIGNATURE"] == _payment_header(callbacks[0])
    assert json.loads(requests[1].content) == {
        "payload": "untrusted",
        "depth": "thorough",
        "context": {"expected_addresses": ["0xabc"]},
    }


async def test_async_payment_handler_has_the_same_bounded_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []
    callbacks: list[X402Challenge] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})
        return httpx.Response(
            200,
            headers={"PAYMENT-RESPONSE": _settlement_header()},
            json=_scan_response(),
        )

    async def payment_handler(challenge: X402Challenge) -> str:
        callbacks.append(challenge)
        return _payment_header(challenge)

    _install_transport(monkeypatch, handler)
    result = await AsyncWardenClient(
        paid=True,
        fail_open=True,
        payment_handler=payment_handler,
    ).scan("untrusted")

    assert result.allowed
    assert len(callbacks) == 1
    assert len(requests) == 2
    assert requests[0].content == requests[1].content


async def test_async_callback_failure_is_fail_closed_without_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})

    async def payment_handler(challenge: X402Challenge) -> str:
        raise RuntimeError("wallet rejected request")

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="payment handler failed"):
        await AsyncWardenClient(
            paid=True,
            fail_open=True,
            payment_handler=payment_handler,
        ).scan("untrusted")

    assert requests == 1


@pytest.mark.parametrize(
    "challenge_header",
    [
        None,
        "not-base64",
        _challenge(x402Version=1),
        _challenge(resource={"url": "https://attacker.invalid/scan"}),
        _encode(
            {
                "x402Version": 2,
                "resource": {"url": _RESOURCE_URL},
                "accepts": [_requirement(amount="1")],
            }
        ),
        _encode(
            {
                "x402Version": 2,
                "resource": {"url": _RESOURCE_URL},
                "accepts": [_requirement(extra={"name": "USDT", "version": "1"})],
            }
        ),
    ],
)
def test_malformed_or_noncanonical_challenge_fails_before_callback(
    monkeypatch: pytest.MonkeyPatch,
    challenge_header: str | None,
) -> None:
    callback_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {} if challenge_header is None else {"PAYMENT-REQUIRED": challenge_header}
        return httpx.Response(402, headers=headers)

    def payment_handler(challenge: X402Challenge) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return _payment_header(challenge)

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="challenge"):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=payment_handler,
        ).scan("untrusted")

    assert callback_calls == 0


@pytest.mark.parametrize("returned", ["", "not-base64", _encode([])])
def test_malformed_callback_header_never_reaches_replay(
    monkeypatch: pytest.MonkeyPatch,
    returned: str,
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="payment handler"):
        WardenClient(
            paid=True,
            payment_handler=lambda challenge: returned,
        ).scan("untrusted")

    assert requests == 1


def test_callback_exception_fails_closed_without_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})

    def payment_handler(challenge: X402Challenge) -> str:
        raise RuntimeError("wallet rejected request")

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="payment handler failed"):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=payment_handler,
        ).scan("untrusted")

    assert requests == 1


@pytest.mark.parametrize(
    "payment_handler",
    [
        lambda challenge: _payment_header(
            challenge,
            accepted_changes={"amount": "1"},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"to": "0x2222222222222222222222222222222222222222"},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"value": "1"},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"validBefore": "9" * 79},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"validBefore": str(_NOW + 5)},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"validAfter": str(_NOW + 1)},
        ),
        lambda challenge: _payment_header(
            challenge,
            authorization_changes={"validBefore": str(_NOW + 306)},
        ),
        lambda challenge: _payment_header(
            challenge,
            resource_url="https://attacker.invalid/scan",
        ),
    ],
)
def test_payment_header_must_be_bound_to_the_validated_challenge(
    monkeypatch: pytest.MonkeyPatch,
    payment_handler,
) -> None:  # noqa: ANN001
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="payment handler"):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=payment_handler,
        ).scan("untrusted")

    assert requests == 1


@pytest.mark.parametrize(
    ("second_header", "message"),
    [
        (_challenge(), "one paid replay"),
        (
            _encode(
                {
                    "x402Version": 2,
                    "resource": {"url": _RESOURCE_URL},
                    "accepts": [_requirement(amount="1")],
                }
            ),
            "changed",
        ),
        ("not-base64", "changed"),
    ],
)
def test_second_402_never_invokes_the_callback_again(
    monkeypatch: pytest.MonkeyPatch,
    second_header: str,
    message: str,
) -> None:
    requests = 0
    callbacks = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        challenge_header = _challenge() if requests == 1 else second_header
        return httpx.Response(402, headers={"PAYMENT-REQUIRED": challenge_header})

    def payment_handler(challenge: X402Challenge) -> str:
        nonlocal callbacks
        callbacks += 1
        return _payment_header(challenge)

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match=message):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=payment_handler,
        ).scan("untrusted")

    assert requests == 2
    assert callbacks == 1


@pytest.mark.parametrize(
    ("status", "headers", "message"),
    [
        (302, {"location": "https://attacker.invalid/capture"}, "redirect"),
        (200, {}, "PAYMENT-RESPONSE"),
        (200, {"PAYMENT-RESPONSE": "not-base64"}, "PAYMENT-RESPONSE"),
        (
            200,
            {"PAYMENT-RESPONSE": _settlement_header(success=False)},
            "settlement",
        ),
        (
            200,
            {"PAYMENT-RESPONSE": _settlement_header(network="eip155:1")},
            "settlement",
        ),
    ],
)
def test_replay_redirect_or_invalid_settlement_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    headers: dict[str, str],
    message: str,
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})
        return httpx.Response(status, headers=headers, json=_scan_response())

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match=message):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=_payment_header,
        ).scan("untrusted")

    assert requests == 2


def test_paid_replay_rejects_a_malformed_scan_result_after_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})
        return httpx.Response(
            200,
            headers={"PAYMENT-RESPONSE": _settlement_header()},
            json={"verdict": "MAYBE"},
        )

    _install_transport(monkeypatch, handler)
    with pytest.raises(WardenError, match="verdict"):
        WardenClient(
            paid=True,
            fail_open=True,
            payment_handler=_payment_header,
        ).scan("untrusted")

    assert requests == 2


def test_payment_handler_requires_explicit_paid_hosted_mode() -> None:
    with pytest.raises(WardenError, match="paid=True"):
        WardenClient(payment_handler=_payment_header)
    with pytest.raises(WardenError, match="local=False"):
        WardenClient(paid=True, local=True, payment_handler=_payment_header)
