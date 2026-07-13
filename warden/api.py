"""FastAPI application for Warden."""

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from warden.badge_store import get_badge, list_badges
from warden.badges import verify_badge
from warden import __version__
from warden.auditor import AgentAuditor
from warden.core.verdict import ReasonCode
from warden.engine import WardenEngine
from warden.gauntlet_store import get_stats, record_attempt
from warden.ratelimit import check_rate_limit, retry_after_seconds
from warden.models import (
    AuditRequest,
    AuditResponse,
    BadgeRecord,
    BadgeRegistryEntry,
    BadgeRegistryResponse,
    DemoExample,
    DemoScanRequest,
    GauntletRequest,
    GauntletResponse,
    GauntletStats,
    HealthResponse,
    ScanRequest,
    ScanResponse,
)

MAX_REQUEST_BODY_BYTES = 1_000_000


def _rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("WARDEN_RATE_LIMIT_PER_MIN", "60") or "60")
    except ValueError:
        return 60


def _demo_rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "20") or "20")
    except ValueError:
        return 20


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
                price="$0.5",
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
    if path.startswith("/api/demo/"):
        limit_per_minute = _demo_rate_limit_per_minute()
        rate_limited = check_rate_limit(request, limit_per_minute, scope="demo")
    elif path in {"/scan", "/audit"}:
        limit_per_minute = _rate_limit_per_minute()
        rate_limited = check_rate_limit(request, limit_per_minute)
    else:
        rate_limited = False

    if rate_limited:
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


@app.post("/api/demo/scan", response_model=ScanResponse)
async def demo_scan(req: DemoScanRequest) -> ScanResponse:
    verdict = await engine.scan(
        req.payload,
        depth="fast",
        context=req.context.model_dump(),
    )
    return ScanResponse.from_verdict(verdict)


@app.post("/api/demo/gauntlet", response_model=GauntletResponse)
async def gauntlet(req: GauntletRequest) -> GauntletResponse:
    verdict = await engine.scan(
        req.payload,
        depth="fast",
        context=req.context.model_dump(),
    )
    scan_response = ScanResponse.from_verdict(verdict)
    claim_status, claim_id = record_attempt(req, scan_response)
    return GauntletResponse(
        **scan_response.model_dump(),
        claim_status=claim_status,
        claim_id=claim_id,
    )


@app.get("/api/demo/gauntlet/stats", response_model=GauntletStats)
async def gauntlet_stats() -> GauntletStats:
    return GauntletStats.model_validate(get_stats(_corpus_size()))


@app.get("/api/demo/examples", response_model=list[DemoExample])
async def demo_examples() -> list[DemoExample]:
    root = Path(__file__).resolve().parents[1]
    curated = {
        "prompt-001": ("Prompt override", ReasonCode.PROMPT_INJECTION),
        "role-001": ("Role impersonation", ReasonCode.ROLE_OVERRIDE),
        "web3-001": ("Web3 transfer instruction", ReasonCode.WEB3_INJECTION),
        "unicode-001": ("Hidden Unicode", ReasonCode.HIDDEN_UNICODE),
        "encoding-001": ("Encoded instruction", ReasonCode.ENCODING_TRICK),
        "stat-001": ("Statistical anomaly", ReasonCode.STATISTICAL_ANOMALY),
        "drain-001": ("Drain address", ReasonCode.DRAIN_ADDRESS),
        "tool-001": ("Tool-call hijack", ReasonCode.TOOL_HIJACK),
        "secret-001": ("Secret exfiltration", ReasonCode.SECRET_EXFIL),
        "link-001": ("Malicious link", ReasonCode.MALICIOUS_LINK),
        "benign-002": ("Clean documentation link", None),
        "benign-003": ("Clean settlement note", None),
    }
    entries: dict[str, dict[str, object]] = {}
    for filename in ("attacks.jsonl", "benign.jsonl"):
        with (root / "corpus" / filename).open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    entry = json.loads(line)
                    if entry.get("id") in curated:
                        entries[str(entry["id"])] = entry

    return [
        DemoExample(
            id=entry_id,
            label=label,
            reason_code=reason_code,
            payload=str(entries[entry_id]["payload"]),
        )
        for entry_id, (label, reason_code) in curated.items()
    ]


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


@app.get("/api/badges", response_model=BadgeRegistryResponse)
async def list_badges_endpoint() -> BadgeRegistryResponse:
    badges = [
        BadgeRegistryEntry(
            badge=BadgeRecord.model_validate(badge),
            verified=verify_badge(badge),
        )
        for badge in list_badges()
    ]
    return BadgeRegistryResponse(badges=badges, total=len(badges))


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
