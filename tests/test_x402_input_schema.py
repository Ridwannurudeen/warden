"""x402 request-schema and frozen-task recovery regressions."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from warden import api as api_module


ROOT = Path(__file__).resolve().parents[1]


def test_paid_route_configs_publish_bazaar_input_schemas():
    script = """
import base64
import json

from fastapi.testclient import TestClient
from x402.http import OKXFacilitatorClient
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.utils import decode_payment_required_header
from x402.schemas import SupportedKind, SupportedResponse

OKXFacilitatorClient.get_supported = lambda self: SupportedResponse(
    kinds=[SupportedKind(x402_version=2, scheme="exact", network="eip155:196")]
)

from warden import api

assert api._scan_route.extensions == api._SCAN_EXTENSIONS
assert api._audit_route.extensions == api._AUDIT_EXTENSIONS
assert api._harden_route.extensions == api._HARDEN_EXTENSIONS
assert api._variant_audit_route.extensions == api._VARIANT_AUDIT_EXTENSIONS
assert api._scan_route.extensions["bazaar"]["info"]["input"]["inputSchema"]["required"] == ["payload"]
assert api._audit_route.extensions["bazaar"]["info"]["input"]["inputSchema"]["required"] == ["target_url"]
assert api._harden_route.extensions["bazaar"]["info"]["input"]["inputSchema"]["required"] == ["audit_id"]
assert api._variant_audit_route.extensions["bazaar"]["info"]["input"]["inputSchema"]["required"] == ["target_url"]
expected_price = {
    "amount": "500000",
    "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
    "extra": {"name": "USD₮0", "version": "1"},
}
assert [option.price.model_dump() for option in api._scan_route.accepts] == [expected_price]
assert [option.price.model_dump() for option in api._audit_route.accepts] == [expected_price]
assert [option.price.model_dump() for option in api._harden_route.accepts] == [expected_price]
assert [option.price.model_dump() for option in api._variant_audit_route.accepts] == [expected_price]
assert api._payment_rail.protocol == "x402-v2"
assert api._payment_rail.facilitator == "okx"
assert api._payment_rail.network == "eip155:196"
assert api._payment_rail.display_price == "0.5 USDT"
assert api._facilitator_http_client.follow_redirects is False
assert api._facilitator_http_client.trust_env is False
assert set(api._paid_routes) == {
    "POST /scan",
    "GET /scan",
    "POST /audit",
    "GET /audit",
    "POST /harden",
    "GET /harden",
    "POST /variant-audit",
    "GET /variant-audit",
}
assert api.app.user_middleware[0].kwargs["dispatch"] is api.payment_required_schema_middleware
assert next(
    index
    for index, middleware in enumerate(api.app.user_middleware)
    if middleware.cls is PaymentMiddlewareASGI
) > 0

required_by_path = {
    "/scan": "payload",
    "/audit": "target_url",
    "/harden": "audit_id",
    "/variant-audit": "target_url",
}
with TestClient(api.app) as client:
    for path, required_field in required_by_path.items():
        response = client.post(path, json={})
        assert response.status_code == 402
        header = response.headers["PAYMENT-REQUIRED"]
        challenge = json.loads(base64.b64decode(header))
        assert challenge["extensions"]["bazaar"]["info"]["input"]["inputSchema"]["required"] == [required_field]
        assert challenge["outputSchema"]["input"]["inputSchema"]["required"] == [required_field]
        assert challenge["accepts"][0]["outputSchema"]["input"]["inputSchema"]["required"] == [required_field]
        assert challenge["accepts"][0]["amount"] == "500000"
        assert challenge["accepts"][0]["asset"] == "0x779ded0c9e1022225f8e0630b35a9b54be713736"
        assert challenge["accepts"][0]["network"] == "eip155:196"
        assert challenge["accepts"][0]["scheme"] == "exact"
        assert challenge["accepts"][0]["payTo"] == "0x0000000000000000000000000000000000000001"
        assert challenge["accepts"][0]["extra"] == {"name": "USD₮0", "version": "1"}
        assert decode_payment_required_header(header).accepts
assert api._facilitator_http_client.is_closed is True
"""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OKX_") and key != "PAY_TO_ADDRESS"
    }
    env.update(
        {
            "OKX_API_KEY": "schema-test-api-key",
            "OKX_SECRET_KEY": "schema-test-secret-key",
            "OKX_PASSPHRASE": "schema-test-passphrase",
            "PAY_TO_ADDRESS": "0x0000000000000000000000000000000000000001",
            "WARDEN_BADGE_SECRET": "schema-test-badge-secret",
        }
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize(
    ("path", "request_body"),
    [
        ("/scan", '{"payload":"<your untrusted text>"}'),
        ("/audit", '{"target_url":"<your authorized endpoint URL>"}'),
        ("/harden", '{"audit_id":"<your completed audit id>"}'),
        ("/variant-audit", '{"target_url":"<your consenting endpoint URL>"}'),
    ],
)
def test_bodyless_get_has_complete_route_specific_recovery(path: str, request_body: str):
    with TestClient(api_module.app) as client:
        response = client.get(path)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Your task froze because OKX's auto-replay sent no body." in detail
    assert "No charge was made." in detail
    assert "onchainos agent task-402-pay <JOB_ID> --provider-agent-id 3808" in detail
    assert f"--endpoint https://warden.gudman.xyz{path}" in detail
    assert "--token-symbol USDT --token-amount 0.5" in detail
    assert "--accepts '<accepts from the 402>'" in detail
    assert f"--body '{request_body}'" in detail
    assert "onchainos agent complete <JOB_ID>" in detail
    assert "https://warden.gudman.xyz/hire" in detail
