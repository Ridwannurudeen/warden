"""Paid variant-audit client surface: option marshalling, x402 replay, validation."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from warden_guard import WardenClient, WardenError

REPORT_ID = "a" * 64
RESOURCE_URL = "https://warden.gudman.xyz/variant-audit"
PAY_TO = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51"


def _encode(value: object) -> str:
    return base64.b64encode(json.dumps(value).encode("utf-8")).decode("ascii")


def _requirement() -> dict[str, object]:
    return {
        "scheme": "exact",
        "network": "eip155:196",
        "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
        "amount": "100000",
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 300,
        "extra": {"name": "USD₮0", "version": "1"},
    }


def _challenge() -> str:
    return _encode(
        {
            "x402Version": 2,
            "error": "Payment required",
            "resource": {
                "url": RESOURCE_URL,
                "description": "Warden adversarial variant audit",
                "mimeType": "application/json",
            },
            "accepts": [_requirement()],
        }
    )


def _payment_header(challenge: object) -> str:
    return _encode(
        {
            "x402Version": 2,
            "payload": {
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": challenge.requirement.pay_to,
                    "value": challenge.requirement.amount,
                    "validAfter": "1699999400",
                    "validBefore": "1700000300",
                    "nonce": "0x" + "22" * 32,
                },
                "signature": "0x" + "33" * 65,
            },
            "accepted": challenge.requirement.to_dict(),
            "resource": {"url": challenge.resource_url},
        }
    )


def _settlement_header() -> str:
    return _encode(
        {
            "success": True,
            "payer": "0x1111111111111111111111111111111111111111",
            "transaction": "0x" + "44" * 32,
            "network": "eip155:196",
        }
    )


def _class_entry(**changes: object) -> dict[str, object]:
    return {
        "threat_class": "DRAIN_ADDRESS",
        "total": 4,
        "detected": 4,
        "missed": 0,
        "inconclusive": 0,
        "conclusive": 4,
        "detection_rate": 100.0,
        "grade": "A",
        **changes,
    }


def _report(**changes: object) -> dict[str, object]:
    return {
        "schema_version": 2,
        "target_host": "agent.example",
        "corpus_fingerprint": "sha256:" + "0" * 64,
        "generator": "warden-adversarial-variants/4",
        "caps": {
            "depth": "standard",
            "max_variants_per_class": 25,
            "max_total_variants": 150,
            "probe_timeout_seconds": 5.0,
            "total_timeout_seconds": 180.0,
            "max_response_bytes": 100000,
        },
        "per_class": [_class_entry()],
        "totals": {**_class_entry(), "threat_classes": 1, "variants_sent": 4},
        "consent_verified": True,
        "limitations": ["Point-in-time evidence."],
        "delta": None,
        "report_id": REPORT_ID,
        "issuer": "warden",
        "issued_at": 1700000000,
        "issuer_sig": "sig:AAAA",
        **changes,
    }


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch):
    """Record requests and answer the 402 handshake without a socket."""
    sent: list[httpx.Request] = []
    state = {"report": _report(), "replay_status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if "PAYMENT-SIGNATURE" not in request.headers:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": _challenge()})
        return httpx.Response(
            state["replay_status"],
            json=state["report"],
            headers={"PAYMENT-RESPONSE": _settlement_header()},
        )

    real_client = httpx.Client

    def _client(*args: object, **kwargs: object) -> httpx.Client:
        kwargs.pop("trust_env", None)
        return real_client(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("warden_guard.client.httpx.Client", _client)
    # The payment header carries a validity window, so the clock must be pinned
    # inside it or every replay is rejected as expired.
    monkeypatch.setattr("warden_guard.client._current_unix_time", lambda: 1_700_000_000)
    return sent, state


def _client() -> WardenClient:
    return WardenClient(paid=True, payment_handler=_payment_header)


def test_variant_audit_pays_and_returns_the_signed_report(transport) -> None:
    sent, _state = transport

    report = _client().variant_audit("https://agent.example/scan")

    assert report["report_id"] == REPORT_ID
    assert report["totals"]["grade"] == "A"
    assert len(sent) == 2
    assert str(sent[0].url) == RESOURCE_URL
    assert "PAYMENT-SIGNATURE" in sent[1].headers


def test_variant_audit_sends_only_the_options_the_caller_set(transport) -> None:
    sent, _state = transport

    _client().variant_audit(
        "https://agent.example/scan",
        threat_classes=["DRAIN_ADDRESS"],
        max_variants_per_class=4,
        since=REPORT_ID,
        depth="deep",
    )

    assert json.loads(sent[0].content) == {
        "target_url": "https://agent.example/scan",
        "threat_classes": ["DRAIN_ADDRESS"],
        "max_variants_per_class": 4,
        "since": REPORT_ID,
        "depth": "deep",
    }


def test_unset_options_are_omitted_so_the_server_applies_its_defaults(transport) -> None:
    sent, _state = transport

    _client().variant_audit("https://agent.example/scan")

    assert json.loads(sent[0].content) == {"target_url": "https://agent.example/scan"}


def test_variant_audit_refuses_to_run_without_a_payment_handler() -> None:
    with pytest.raises(WardenError, match="requires an x402 payment_handler"):
        WardenClient(paid=True).variant_audit("https://agent.example/scan")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"depth": "unlimited"},
        {"max_variants_per_class": 0},
        {"max_variants_per_class": True},
        {"since": "not-a-report-id"},
        {"threat_classes": ["", "DRAIN_ADDRESS"]},
        {"threat_classes": "DRAIN_ADDRESS"},
    ],
)
def test_a_malformed_option_is_refused_before_anything_is_spent(
    transport,
    kwargs: dict[str, object],
) -> None:
    sent, _state = transport

    with pytest.raises(WardenError):
        _client().variant_audit("https://agent.example/scan", **kwargs)

    assert sent == []


@pytest.mark.parametrize("target_url", ["", None, 7])
def test_a_missing_target_url_is_refused(transport, target_url: object) -> None:
    sent, _state = transport

    with pytest.raises(WardenError, match="target_url"):
        _client().variant_audit(target_url)

    assert sent == []


@pytest.mark.parametrize(
    ("field", "changes"),
    [
        ("consent_verified", {"consent_verified": False}),
        ("report_id", {"report_id": "nope"}),
        ("limitations", {"limitations": []}),
        ("totals", {"totals": {"threat_classes": 1}}),
        ("per_class", {"per_class": [_class_entry(grade="S")]}),
        ("target_host", {"target_host": 7}),
    ],
)
def test_an_invalid_report_is_refused_rather_than_returned(
    transport,
    field: str,
    changes: dict[str, object],
) -> None:
    _sent, state = transport
    state["report"] = _report(**changes)

    with pytest.raises(WardenError, match=field):
        _client().variant_audit("https://agent.example/scan")


def test_an_ungraded_class_with_no_rate_is_accepted(transport) -> None:
    _sent, state = transport
    state["report"] = _report(
        per_class=[
            _class_entry(
                detected=0,
                conclusive=0,
                inconclusive=4,
                detection_rate=None,
                grade="INCONCLUSIVE",
            )
        ]
    )

    report = _client().variant_audit("https://agent.example/scan")

    assert report["per_class"][0]["detection_rate"] is None
    assert report["per_class"][0]["grade"] == "INCONCLUSIVE"


def test_variant_audit_never_fails_open(transport) -> None:
    """A failed audit raises; it must not read as a clean bill of health."""
    _sent, state = transport
    state["replay_status"] = 500

    with pytest.raises(WardenError):
        WardenClient(
            paid=True,
            payment_handler=_payment_header,
            fail_open=True,
        ).variant_audit("https://agent.example/scan")


@pytest.mark.parametrize(
    ("field", "report"),
    [
        (
            "schema_version",
            {
                "target_host": "h", "corpus_fingerprint": "c", "generator": "g",
                "issuer": "i", "issuer_sig": "s", "report_id": "a" * 64,
                "consent_verified": True, "limitations": ["x"], "per_class": [],
                "totals": {"grade": "A", "threat_classes": 0, "variants_sent": 0},
            },
        ),
        ("totals", _report(totals={**_class_entry(detected=-1), "threat_classes": 1, "variants_sent": 4})),
        ("totals", _report(totals={**_class_entry(total=99), "threat_classes": 1, "variants_sent": 4})),
        ("per_class", _report(per_class=[{k: v for k, v in _class_entry().items() if k != "detected"}])),
        ("limitations", _report(limitations=[1])),
        ("issued_at", _report(issued_at=-1)),
    ],
)
def test_a_report_missing_or_inconsistent_counts_is_refused(
    transport, field: str, report: dict[str, object]
) -> None:
    """A caller pays, then does arithmetic on this. Absent counts are not evidence."""
    _sent, state = transport
    state["report"] = report

    with pytest.raises(WardenError, match=field):
        _client().variant_audit("https://agent.example/scan")


async def test_the_async_client_offers_the_same_variant_audit_surface() -> None:
    """aio.py documents itself as the same surface as WardenClient."""
    from warden_guard import AsyncWardenClient

    client = AsyncWardenClient(paid=True, payment_handler=lambda ch: "x")
    with pytest.raises(WardenError, match="depth must be"):
        await client.variant_audit("https://agent.example/scan", depth="unlimited")
    with pytest.raises(WardenError, match="payment_handler"):
        await AsyncWardenClient(paid=True).variant_audit("https://agent.example/scan")
