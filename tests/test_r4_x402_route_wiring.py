"""Actual Warden paid routes verify and settle through the configured x402 middleware."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_real_paid_routes_are_wired_to_local_verification_and_settlement() -> None:
    script = r'''
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
            payment_requirements={"route": route_key, "price": option.price},
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
        assert payment_requirements == {"route": route_key, "price": "$0.5"}
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
expected_routes = ["GET /scan", "POST /scan", "GET /audit", "POST /audit"]

with TestClient(api.app) as client:
    server = CapturingHTTPResourceServer.instances[0]
    assert set(server.routes) == set(expected_routes)
    for route_key in expected_routes:
        options = server.routes[route_key].accepts
        assert len(options) == 1
        assert options[0].price == "$0.5"

    requests = [
        ("GET", "/scan", {"params": {"payload": "normal settlement note"}}),
        ("POST", "/scan", {"json": {"payload": "normal settlement note"}}),
        ("GET", "/audit", {"params": {"target_url": "https://agent.example/scan"}}),
        ("POST", "/audit", {"json": {"target_url": "https://agent.example/scan"}}),
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
'''
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
            "OKX_BASE_URL": "https://network.invalid",
            "PAY_TO_ADDRESS": "0x0000000000000000000000000000000000000001",
            "WARDEN_BADGE_SECRET": "local-route-test-badge-secret",
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
