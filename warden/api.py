"""FastAPI application for Warden."""

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from warden.badge_store import get_badge
from warden.badges import verify_badge
from warden import __version__
from warden.auditor import AgentAuditor
from warden.engine import WardenEngine
from warden.ratelimit import check_rate_limit, retry_after_seconds
from warden.models import AuditRequest, AuditResponse, HealthResponse, ScanRequest, ScanResponse

MAX_REQUEST_BODY_BYTES = 1_000_000


def _rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("WARDEN_RATE_LIMIT_PER_MIN", "60") or "60")
    except ValueError:
        return 60


engine = WardenEngine()
auditor = AgentAuditor()

app = FastAPI(title="Warden", version=__version__)

_cors_setting = os.getenv(
    "WARDEN_CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,https://warden.gudman.xyz",
)
_cors_origins = [origin.strip() for origin in _cors_setting.split(",") if origin.strip()]
_allow_credentials = not (_cors_origins == ["*"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# x402 paywall — only active when OKX facilitator credentials are present in the
# environment. Absent (local dev, test runs) → endpoints stay free and the app is
# unchanged, so the test suite needs no payment mocking.
if os.getenv("OKX_API_KEY"):
    from x402.http import (
        OKXAuthConfig,
        OKXFacilitatorClient,
        OKXFacilitatorConfig,
        PaymentOption,
    )
    from x402.http.middleware.fastapi import PaymentMiddlewareASGI
    from x402.http.types import RouteConfig
    from x402.mechanisms.evm.exact.server import ExactEvmScheme
    from x402.server import x402ResourceServer

    _pay_to = os.getenv("PAY_TO_ADDRESS", "")
    if not _pay_to:
        raise RuntimeError("PAY_TO_ADDRESS is required when OKX_API_KEY is set")

    _facilitator = OKXFacilitatorClient(
        OKXFacilitatorConfig(
            auth=OKXAuthConfig(
                api_key=os.getenv("OKX_API_KEY", ""),
                secret_key=os.getenv("OKX_SECRET_KEY", ""),
                passphrase=os.getenv("OKX_PASSPHRASE", ""),
            ),
            base_url=os.getenv("OKX_BASE_URL", "https://web3.okx.com"),
            sync_settle=True,
        )
    )
    _server = x402ResourceServer(_facilitator)
    _NETWORK = "eip155:196"  # X Layer mainnet
    _server.register(_NETWORK, ExactEvmScheme())

    _scan_route = RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                price="$0.01",
                network=_NETWORK,
                pay_to=_pay_to,
                max_timeout_seconds=300,
            )
        ],
        description="Warden payload security scan",
        mime_type="application/json",
    )
    _audit_route = RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                price="$15",
                network=_NETWORK,
                pay_to=_pay_to,
                max_timeout_seconds=300,
            )
        ],
        description="Warden agent endpoint security audit",
        mime_type="application/json",
    )
    # Challenge unpaid GET as well as POST: OKX's x402-check probes with GET and
    # expects a 402 payment challenge; a POST-only paywall returns 405 and reads
    # as an invalid x402 service. GET is not left unpaywalled — the paid handlers
    # remain POST-only, so a paid GET simply 405s after settlement (no real
    # caller does this; buyers POST). OPTIONS is deliberately left free for CORS.
    _paid_routes = {
        "POST /scan": _scan_route,
        "GET /scan": _scan_route,
        "POST /audit": _audit_route,
        "GET /audit": _audit_route,
    }
    app.add_middleware(PaymentMiddlewareASGI, routes=_paid_routes, server=_server)


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            return JSONResponse(
                status_code=400, content={"detail": "Invalid Content-Length header"}
            )
    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path.rstrip("/")
    limit_per_minute = _rate_limit_per_minute()
    if path in {"/scan", "/audit"} and limit_per_minute > 0:
        if check_rate_limit(request, limit_per_minute):
            response = JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
            response.headers["Retry-After"] = str(retry_after_seconds())
            return response

    return await call_next(request)


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    verdict = await engine.scan(
        req.payload,
        depth=req.depth,
        context=req.context.model_dump(),
    )
    return ScanResponse.from_verdict(verdict)


@app.post("/audit", response_model=AuditResponse)
async def audit(req: AuditRequest) -> AuditResponse:
    try:
        return await auditor.audit(req.target_url, req.sample_prompts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/badge/{audit_id}")
async def get_badge_endpoint(audit_id: str):
    badge = get_badge(audit_id)
    if badge is None:
        raise HTTPException(status_code=404, detail="Badge not found")
    return {"badge": badge, "verified": verify_badge(badge)}


@app.get("/")
async def root() -> dict[str, object]:
    return {
        "service": "Warden",
        "description": "Deterministic payload firewall and pre-listing security auditor for the agent economy.",
        "version": __version__,
        "endpoints": {
            "scan": "POST /scan",
            "audit": "POST /audit",
            "health": "GET /health",
            "badge": "GET /badge/{audit_id}",
        },
    }


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        corpus_size=_corpus_size(),
        analyzers=[analyzer.name for analyzer in engine.registry.get_all()],
    )


def _corpus_size() -> int:
    root = Path(__file__).resolve().parents[1]
    total = 0
    for corpus_file in (root / "corpus" / "attacks.jsonl", root / "corpus" / "benign.jsonl"):
        if corpus_file.exists():
            with corpus_file.open(encoding="utf-8") as handle:
                total += sum(1 for line in handle if line.strip())
    return total
