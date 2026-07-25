"""The production payment rail is one explicit X Layer USDT contract."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from x402.http import (
    OKXAuthConfig,
    OKXFacilitatorConfig,
)
from x402.http.okx_facilitator_client import OKXFacilitatorResponseError
from x402.schemas import AssetAmount

from warden.payment import (
    DEFAULT_FACILITATOR_URL,
    PAYMENT_AMOUNT,
    PAYMENT_ASSET,
    PAYMENT_EIP712_NAME,
    PAYMENT_EIP712_VERSION,
    PAYMENT_NETWORK,
    PAYMENT_SCHEME,
    NoRedirectOKXFacilitatorClient,
    PaymentRail,
    build_payment_option,
    load_payment_rail,
    paywall_required,
)


ROOT = Path(__file__).resolve().parents[1]
PAY_TO = "0x0000000000000000000000000000000000000001"


def test_payment_rail_is_fixed_to_xlayer_usdt_exact() -> None:
    rail = load_payment_rail({"PAY_TO_ADDRESS": PAY_TO})

    assert rail == PaymentRail(
        protocol="x402-v2",
        facilitator="okx",
        facilitator_url="https://web3.okx.com",
        scheme="exact",
        network="eip155:196",
        asset="0x779ded0c9e1022225f8e0630b35a9b54be713736",
        amount="100000",
        eip712_name="USD₮0",
        eip712_version="1",
        symbol="USDT",
        decimals=6,
        display_price="0.1 USDT",
        pay_to=PAY_TO,
    )
    assert (PAYMENT_SCHEME, PAYMENT_NETWORK, PAYMENT_ASSET, PAYMENT_AMOUNT) == (
        "exact",
        "eip155:196",
        "0x779ded0c9e1022225f8e0630b35a9b54be713736",
        "100000",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("WARDEN_PAYMENT_SCHEME", "upto"),
        ("WARDEN_PAYMENT_NETWORK", "eip155:8453"),
        (
            "WARDEN_PAYMENT_ASSET",
            "0x0000000000000000000000000000000000000002",
        ),
        ("WARDEN_PAYMENT_AMOUNT", "1"),
        ("WARDEN_PAYMENT_EIP712_NAME", "USDT"),
        ("WARDEN_PAYMENT_EIP712_VERSION", "2"),
        ("WARDEN_PAYMENT_SYMBOL", "USDC"),
        ("WARDEN_PAYMENT_DECIMALS", "18"),
        ("WARDEN_PAYMENT_FACILITATOR", "coinbase"),
    ],
)
def test_payment_rail_rejects_unsupported_configuration(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        load_payment_rail({"PAY_TO_ADDRESS": PAY_TO, field: value})


def test_payment_rail_rejects_unknown_payment_configuration() -> None:
    with pytest.raises(ValueError, match="WARDEN_PAYMENT_NOT_A_REAL_SETTING"):
        load_payment_rail(
            {
                "PAY_TO_ADDRESS": PAY_TO,
                "WARDEN_PAYMENT_NOT_A_REAL_SETTING": "unsafe",
            }
        )


@pytest.mark.parametrize(
    "pay_to",
    [
        "",
        "0x0",
        "0x0000000000000000000000000000000000000000",
        "0X0000000000000000000000000000000000000001",
        "0x000000000000000000000000000000000000000G",
    ],
)
def test_payment_rail_rejects_invalid_or_zero_recipient(pay_to: str) -> None:
    with pytest.raises(ValueError, match="PAY_TO_ADDRESS"):
        load_payment_rail({"PAY_TO_ADDRESS": pay_to})


def test_payment_option_uses_explicit_atomic_amount_and_asset() -> None:
    rail = load_payment_rail({"PAY_TO_ADDRESS": PAY_TO})

    option = build_payment_option(rail)

    assert option.scheme == "exact"
    assert option.network == "eip155:196"
    assert option.pay_to == PAY_TO
    assert option.max_timeout_seconds == 300
    assert isinstance(option.price, AssetAmount)
    assert option.price.model_dump() == {
        "amount": "100000",
        "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
        "extra": {
            "name": "USD₮0",
            "version": "1",
        },
    }
    assert (PAYMENT_EIP712_NAME, PAYMENT_EIP712_VERSION) == ("USD₮0", "1")


@pytest.mark.parametrize(
    "facilitator_url",
    [
        "http://web3.okx.com",
        "https://example.invalid",
        "https://web3.okx.com/",
        "https://web3.okx.com/custom",
        "https://user@web3.okx.com",
        "https://web3.okx.com?redirect=1",
        "https://web3.okx.com#fragment",
        "https://web3.okx.com:443",
        " https://web3.okx.com",
    ],
)
def test_payment_rail_rejects_every_noncanonical_facilitator_origin(
    facilitator_url: str,
) -> None:
    with pytest.raises(ValueError, match="OKX_BASE_URL"):
        load_payment_rail(
            {
                "PAY_TO_ADDRESS": PAY_TO,
                "OKX_BASE_URL": facilitator_url,
            }
        )


def test_payment_rail_accepts_only_the_installed_okx_origin() -> None:
    rail = load_payment_rail(
        {
            "PAY_TO_ADDRESS": PAY_TO,
            "OKX_BASE_URL": "https://web3.okx.com",
        }
    )

    assert DEFAULT_FACILITATOR_URL == "https://web3.okx.com"
    assert rail.facilitator_url == DEFAULT_FACILITATOR_URL


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (None, False),
        ("", False),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("TRUE", True),
    ],
)
def test_paywall_required_accepts_only_explicit_boolean_values(
    configured: str | None,
    expected: bool,
) -> None:
    environment = {}
    if configured is not None:
        environment["WARDEN_REQUIRE_PAYWALL"] = configured

    assert paywall_required(environment) is expected


@pytest.mark.parametrize("configured", ["treu", "required", "2", " true ", "disabled"])
def test_paywall_required_rejects_invalid_boolean_configuration(configured: str) -> None:
    with pytest.raises(ValueError, match="WARDEN_REQUIRE_PAYWALL"):
        paywall_required({"WARDEN_REQUIRE_PAYWALL": configured})


def test_invalid_paywall_boolean_rejects_api_startup() -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OKX_") and key not in {"PAY_TO_ADDRESS", "WARDEN_REQUIRE_PAYWALL"}
    }
    environment["WARDEN_REQUIRE_PAYWALL"] = "treu"

    completed = subprocess.run(
        [sys.executable, "-c", "import warden.api"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "WARDEN_REQUIRE_PAYWALL" in completed.stderr


def test_production_service_requires_the_paywall_and_docs_pin_the_origin() -> None:
    service = (ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")
    payment_docs = (ROOT / "PAYMENT.md").read_text(encoding="utf-8")
    normalized_docs = " ".join(payment_docs.split())
    normalized_docs_lower = normalized_docs.lower()

    assert "Environment=WARDEN_REQUIRE_PAYWALL=1" in service
    assert "WARDEN_REQUIRE_PAYWALL=1" in payment_docs
    assert "https://web3.okx.com" in payment_docs
    assert "alternate facilitator origins are rejected" in normalized_docs
    assert "not yet deployed" in normalized_docs_lower
    assert "deploy and read-only reprobe" in normalized_docs_lower
    assert "The live payment gate is verified" not in payment_docs
    for path in (
        ROOT / "docs" / "build-history" / "CODEX-BUILD-PHASE5.md",
        ROOT / "docs" / "build-history" / "CODEX-KICKOFF-PHASE5.md",
        ROOT / "submission" / "PHASE5-VERIFICATION.md",
    ):
        archived = " ".join(path.read_text(encoding="utf-8").split())
        assert "SUPERSEDED" in archived
        assert "PAYMENT.md" in archived


def _facilitator(
    *,
    http_client: httpx.AsyncClient | None = None,
) -> NoRedirectOKXFacilitatorClient:
    return NoRedirectOKXFacilitatorClient(
        OKXFacilitatorConfig(
            auth=OKXAuthConfig(
                api_key="unit-test-api-key",
                secret_key="unit-test-secret-key",
                passphrase="unit-test-passphrase",
            ),
            base_url=DEFAULT_FACILITATOR_URL,
            http_client=http_client,
        )
    )


async def test_facilitator_never_follows_a_cross_origin_async_redirect() -> None:
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.host != "web3.okx.com":
            raise AssertionError("facilitator credentials reached a redirect target")
        return httpx.Response(
            302,
            headers={"location": "https://attacker.invalid/capture"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        facilitator = _facilitator(http_client=client)
        with pytest.raises(OKXFacilitatorResponseError, match="HTTP 302"):
            await facilitator._do_request_async("GET", "/supported")

    assert requested_hosts == ["web3.okx.com"]


def test_facilitator_never_follows_a_cross_origin_sync_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_hosts: list[str] = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.host != "web3.okx.com":
            raise AssertionError("facilitator credentials reached a redirect target")
        return httpx.Response(
            302,
            headers={"location": "https://attacker.invalid/capture"},
        )

    def client_factory(**kwargs: object) -> httpx.Client:
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("warden.payment.httpx.Client", client_factory)

    with pytest.raises(OKXFacilitatorResponseError, match="HTTP 302"):
        _facilitator().get_supported()

    assert requested_hosts == ["web3.okx.com"]
