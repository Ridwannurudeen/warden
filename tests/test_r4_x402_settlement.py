"""The locally installed x402 middleware settles a verified paid request."""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from fastapi import FastAPI
from fastapi.testclient import TestClient
from x402.http import HTTPProcessResult, ProcessSettleResult
from x402.http.middleware import fastapi as x402_fastapi


class _VerifiedHTTPServer:
    instances: ClassVar[list[_VerifiedHTTPServer]] = []

    def __init__(self, server: object, routes: object) -> None:
        self.settlement_calls: list[tuple[object, object]] = []
        self.instances.append(self)

    def requires_payment(self, context: object) -> bool:
        return True

    async def process_http_request(
        self, context: object, paywall_config: object
    ) -> HTTPProcessResult:
        return HTTPProcessResult(
            type="payment-verified",
            payment_payload={"payment": "verified"},
            payment_requirements={"price": "$0.5"},
        )

    async def process_settlement(
        self,
        payment_payload: object,
        payment_requirements: object,
        *,
        context: object,
    ) -> ProcessSettleResult:
        self.settlement_calls.append((payment_payload, payment_requirements))
        return ProcessSettleResult(
            success=True,
            headers={"PAYMENT-RESPONSE": "settled"},
            transaction="0xtest",
        )


def test_verified_x402_request_is_settled_after_successful_handler(
    monkeypatch,
) -> None:
    _VerifiedHTTPServer.instances.clear()
    monkeypatch.setattr(x402_fastapi, "x402HTTPResourceServer", _VerifiedHTTPServer)
    paid_middleware = x402_fastapi.payment_middleware(
        {}, object(), sync_facilitator_on_start=False
    )
    app = FastAPI()

    @app.middleware("http")
    async def require_payment(request, call_next: Callable):  # noqa: ANN001, ANN202
        return await paid_middleware(request, call_next)

    @app.post("/paid")
    async def paid_route() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(app).post("/paid", headers={"payment-signature": "test"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert response.headers["payment-response"] == "settled"
    assert _VerifiedHTTPServer.instances[0].settlement_calls == [
        ({"payment": "verified"}, {"price": "$0.5"})
    ]
