"""Actual Warden paid routes verify and settle through the configured x402 middleware."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.badges import b64u_encode


ROOT = Path(__file__).resolve().parents[1]


def test_real_paid_routes_are_wired_to_local_verification_and_settlement(tmp_path) -> None:
    script = r"""
import socket

from fastapi.testclient import TestClient
from x402.http import HTTPProcessResult, ProcessSettleResult
from x402.http.middleware import fastapi as x402_fastapi


real_socket_connect = socket.socket.connect
real_socket_connect_ex = socket.socket.connect_ex


def reject_external_connect(sock, address):
    if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
        return real_socket_connect(sock, address)
    raise AssertionError(f"external network access is forbidden: {address!r}")


def reject_external_connect_ex(sock, address):
    if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
        return real_socket_connect_ex(sock, address)
    raise AssertionError(f"external network access is forbidden: {address!r}")


def deny_create_connection(*args, **kwargs):
    raise AssertionError("external network connection is forbidden")


socket.create_connection = deny_create_connection
socket.socket.connect = reject_external_connect
socket.socket.connect_ex = reject_external_connect_ex


class CapturingHTTPResourceServer:
    instances = []

    def __init__(self, server, routes):
        self.routes = routes
        self.initialize_calls = 0
        self.verified = []
        self.settled = []
        self.instances.append(self)

    def register_paywall_provider(self, provider):
        raise AssertionError("no paywall provider is expected")

    def requires_payment(self, context):
        return f"{context.method} {context.path}" in self.routes

    def initialize(self):
        self.initialize_calls += 1

    async def process_http_request(self, context, paywall_config=None):
        assert context.payment_header == "local-payment-signature"
        route_key = f"{context.method} {context.path}"
        option = self.routes[route_key].accepts[0]
        self.verified.append(route_key)
        return HTTPProcessResult(
            type="payment-verified",
            payment_payload={"route": route_key},
            payment_requirements={
                "route": route_key,
                "price": option.price.model_dump(),
            },
        )

    async def process_settlement(
        self,
        payment_payload,
        payment_requirements,
        *,
        context,
    ):
        route_key = f"{context.method} {context.path}"
        assert payment_payload == {"route": route_key}
        assert payment_requirements == {
            "route": route_key,
            "price": {
                "amount": "500000",
                "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
                "extra": {"name": "USD₮0", "version": "1"},
            },
        }
        self.settled.append(route_key)
        return ProcessSettleResult(
            success=True,
            headers={"PAYMENT-RESPONSE": f"settled:{route_key}"},
            transaction=f"local:{len(self.settled)}",
        )


x402_fastapi.x402HTTPResourceServer = CapturingHTTPResourceServer

from warden import api


audit_calls = []


class StubAuditor:
    async def audit(self, target_url, sample_prompts):
        audit_calls.append((target_url, sample_prompts))
        return api.AuditResponse(
            score=100,
            grade="A",
            results=[],
            badge="local-test",
            recommendations=[],
        )


api.auditor = StubAuditor()

# /harden reads retained findings rather than probing a target, so the paid-route
# wiring check supplies a conclusive record instead of stubbing an auditor.
async def _stub_variant_audit(target_url, **kwargs):
    return {
        "schema_version": 1,
        "target_host": "agent.example",
        "corpus_fingerprint": "sha256:" + "a" * 64,
        "generator": "warden-adversarial-variants/3",
        "caps": {
            "max_variants_per_class": 25,
            "max_total_variants": 150,
            "probe_timeout_seconds": 5.0,
            "total_timeout_seconds": 180.0,
            "max_response_bytes": 100000,
        },
        "per_class": [],
        "totals": {
            "threat_classes": 0,
            "variants_sent": 0,
            "detected": 0,
            "missed": 0,
            "inconclusive": 0,
            "conclusive": 0,
            "detection_rate": None,
        },
        "consent_verified": True,
        "limitations": ["local wiring stub"],
        "report_id": "b" * 64,
        "issuer": "warden",
        "issued_at": 1785000000,
        "issuer_sig": "sig:stub",
    }


api.run_variant_audit = _stub_variant_audit

api.get_findings = lambda audit_id: {
    "schema_version": 1,
    "audit_id": audit_id,
    "target_host": "agent.example",
    "battery_id": "warden-core-http",
    "battery_version": "2026-07",
    "observed_on": "2026-07-24",
    "findings": [{"attack_class": "SECRET_EXFIL", "total": 2, "blocked": 1, "missed": 1}],
}

expected_routes = [
    "GET /scan",
    "POST /scan",
    "GET /audit",
    "POST /audit",
    "GET /harden",
    "POST /harden",
    "GET /variant-audit",
    "POST /variant-audit",
]

with TestClient(api.app) as client:
    server = CapturingHTTPResourceServer.instances[0]
    assert set(server.routes) == set(expected_routes)
    for route_key in expected_routes:
        options = server.routes[route_key].accepts
        assert len(options) == 1
        assert options[0].scheme == "exact"
        assert options[0].network == "eip155:196"
        assert options[0].pay_to == "0x0000000000000000000000000000000000000001"
        assert options[0].price.model_dump() == {
            "amount": "500000",
            "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
            "extra": {"name": "USD₮0", "version": "1"},
        }

    requests = [
        ("GET", "/scan", {"params": {"payload": "normal settlement note"}}),
        ("POST", "/scan", {"json": {"payload": "normal settlement note"}}),
        ("GET", "/audit", {"params": {"target_url": "https://agent.example/scan"}}),
        ("POST", "/audit", {"json": {"target_url": "https://agent.example/scan"}}),
        ("GET", "/harden", {"params": {"audit_id": "0123456789abcdef"}}),
        ("POST", "/harden", {"json": {"audit_id": "0123456789abcdef"}}),
        ("GET", "/variant-audit", {"params": {"target_url": "https://agent.example/scan"}}),
        ("POST", "/variant-audit", {"json": {"target_url": "https://agent.example/scan"}}),
    ]
    for method, path, request_kwargs in requests:
        response = client.request(
            method,
            path,
            headers={"payment-signature": "local-payment-signature"},
            **request_kwargs,
        )
        route_key = f"{method} {path}"
        assert response.status_code == 200, response.text
        assert response.headers["payment-response"] == f"settled:{route_key}"

assert server.initialize_calls == 1
assert server.verified == expected_routes
assert server.settled == expected_routes
assert audit_calls == [
    ("https://agent.example/scan", []),
    ("https://agent.example/scan", []),
]
assert api._facilitator_http_client.is_closed is True
"""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OKX_") and key != "PAY_TO_ADDRESS"
    }
    env.update(
        {
            "OKX_API_KEY": "local-route-test-api-key",
            "OKX_SECRET_KEY": "local-route-test-secret-key",
            "OKX_PASSPHRASE": "local-route-test-passphrase",
            "OKX_BASE_URL": "https://web3.okx.com",
            "PAY_TO_ADDRESS": "0x0000000000000000000000000000000000000001",
            "WARDEN_BADGE_SECRET": "local-route-test-badge-secret",
            "WARDEN_ISSUER_KEY": b64u_encode(
                Ed25519PrivateKey.generate().private_bytes_raw(),
                "ed25519-seed",
            ),
            "WARDEN_PROTECTION_DB": str(tmp_path / "protection.db"),
            "WARDEN_RATE_LIMIT_PER_MIN": "0",
            "WARDEN_REQUIRE_PAYWALL": "1",
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
