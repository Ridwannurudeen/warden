"""FastAPI application for Warden."""

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from warden.badge_store import get_badge, list_badges
from warden.badges import verify_badge
from warden import __version__, protection, protection_store
from warden.auditor import AgentAuditor
from warden.core.verdict import ReasonCode
from warden.engine import WardenEngine
from warden.gauntlet_store import get_stats, record_attempt
from warden.ratelimit import check_rate_limit, retry_after_seconds
from warden.models import (
    ApaRegisterRequest,
    ApaRevokeRequest,
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


def _apa_rate_limit_per_minute() -> int:
    try:
        return int(os.getenv("WARDEN_APA_RATE_LIMIT_PER_MIN", "10") or "10")
    except ValueError:
        return 10


engine = WardenEngine()
auditor = AgentAuditor()

app = FastAPI(title="Warden", version=__version__)

_cors_setting = os.getenv(
    "WARDEN_CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,https://warden.gudman.xyz",
)
_cors_origins = [origin.strip() for origin in _cors_setting.split(",") if origin.strip()]
_allow_credentials = "*" not in _cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# In production the deploy sets WARDEN_REQUIRE_PAYWALL=1 so a missing/typo'd
# OKX_API_KEY fails loudly at startup instead of silently serving paid endpoints
# for free. Local dev / test runs leave it unset → endpoints stay free, no mocks.
if os.getenv("WARDEN_REQUIRE_PAYWALL", "").lower() in {"1", "true", "yes", "on"} and not os.getenv(
    "OKX_API_KEY"
):
    raise RuntimeError(
        "WARDEN_REQUIRE_PAYWALL is set but OKX_API_KEY is missing — "
        "refusing to serve paid endpoints for free."
    )

# x402 paywall — only active when OKX facilitator credentials are present in the
# environment. Absent (local dev, test runs) → endpoints stay free and the app is
# unchanged, so the test suite needs no payment mocking.
if os.getenv("OKX_API_KEY"):
    _missing = [
        name
        for name in ("OKX_SECRET_KEY", "OKX_PASSPHRASE", "PAY_TO_ADDRESS", "WARDEN_BADGE_SECRET")
        if not os.getenv(name)
    ]
    if _missing:
        raise RuntimeError(
            "OKX_API_KEY is set but required configuration is missing: "
            + ", ".join(_missing)
            + " (paid endpoints would 502 or badges would be forgeable)."
        )
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
                price="$0.5",
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
    # as an invalid x402 service. OKX's paid auto-replay also uses GET, so /scan
    # and /audit serve GET too — a paid GET that 405s freezes the buyer's task.
    # OPTIONS is deliberately left free for CORS.
    _paid_routes = {
        "POST /scan": _scan_route,
        "GET /scan": _scan_route,
        "POST /audit": _audit_route,
        "GET /audit": _audit_route,
    }
    # Note: the OKX x402 middleware must reach the facilitator's /supported to
    # build even an unpaid 402 challenge, so a facilitator outage takes the paid
    # routes down regardless of how this is wired (confirmed against the package
    # source — not fixable app-side). Monitor facilitator availability instead.
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
    # A request that already carries an x402 payment authorization has paid its
    # own way — never rate-limit it. OKX's paid auto-replay and its x402-check
    # probe share OKX egress IPs, so counting them risks 429-ing a real paid
    # settlement (money signed, no deliverable) or making the listing read as an
    # invalid x402 service. Unpaid challenges are still limited below.
    carries_payment = bool(
        request.headers.get("payment-signature") or request.headers.get("x-payment")
    )
    if carries_payment and path in {"/scan", "/audit"}:
        return await call_next(request)

    if path.startswith("/api/demo/"):
        limit_per_minute = _demo_rate_limit_per_minute()
        rate_limited = check_rate_limit(request, limit_per_minute, scope="demo")
    elif path in {"/apa/register", "/apa/revoke"}:
        limit_per_minute = _apa_rate_limit_per_minute()
        rate_limited = check_rate_limit(request, limit_per_minute, scope="apa")
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


# OKX's create-task auto-replay re-requests the paid resource with GET but does
# not forward a business body, so a service that needs input (scan/audit) has
# nothing to act on. The supported path for such services is task-402-pay --body
# (which warden.gudman.xyz/hire generates). This hint turns the 400 into a
# self-service recovery for anyone inspecting a task frozen in `accepted`.
_RECOVERY_HINT = (
    " If your task froze in `accepted` after paying, OKX's auto-replay sent no "
    "body — re-send with `task-402-pay --body '{...}'` or use "
    "https://warden.gudman.xyz/hire. No charge was made for this request."
)


async def _get_request_fields(request: Request) -> dict[str, object]:
    """Read a paid GET's fields from the query string, or a JSON body if one was sent.

    OKX's x402 auto-replay re-requests the paid resource with GET, so a POST-only
    handler answers 405 and the buyer's task freezes in `accepted`.
    """
    fields: dict[str, object] = dict(request.query_params)
    if fields:
        return fields

    raw = await request.body()
    if not raw:
        return fields

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")
    return parsed


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    verdict = await engine.scan(
        req.payload,
        depth=req.depth,
        context=req.context.model_dump(),
    )
    return ScanResponse.from_verdict(verdict)


@app.get("/scan", response_model=ScanResponse)
async def scan_get(request: Request) -> ScanResponse:
    fields = await _get_request_fields(request)
    try:
        req = ScanRequest.model_validate(fields)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail="Provide the payload to scan as a 'payload' query parameter or JSON body field."
            + _RECOVERY_HINT,
        ) from exc
    return await scan(req)


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


@app.get("/audit", response_model=AuditResponse)
async def audit_get(request: Request) -> AuditResponse:
    fields = await _get_request_fields(request)
    try:
        req = AuditRequest.model_validate(fields)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail="Provide the endpoint to audit as a 'target_url' query parameter or JSON body field."
            + _RECOVERY_HINT,
        ) from exc
    return await audit(req)


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


@app.get("/.well-known/apa-issuer.json")
async def apa_issuer_document() -> dict[str, object]:
    return protection.issuer_document()


@app.post("/apa/register")
async def apa_register(req: ApaRegisterRequest) -> dict[str, object]:
    """TOFU registration per APA-SPEC §4: probe, bind host→pub, issue, log."""
    try:
        endpoint_host, pub, scans = await protection.probe_guard(req.endpoint)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    binding = protection_store.get_binding(endpoint_host)
    if binding is None:
        protection_store.bind_host(endpoint_host, pub)
        status = "active"
    elif binding["pub"] == pub:
        status = "active"
    else:
        # A different key for a bound host: possible rotation or compromise —
        # never silently rebind (APA-SPEC §4.3).
        protection_store.flag_key_changed(endpoint_host)
        status = "key-changed"

    record = protection.issue_attestation(endpoint_host, pub, scans, status=status)
    protection_store.store_attestation(record)
    protection_store.append_log("issued", record)
    return {"attestation": record, "verified": protection.verify_attestation_record(record)}


@app.get("/apa/attestation/{attestation_id}")
async def apa_attestation(attestation_id: str) -> dict[str, object]:
    record = protection_store.get_attestation(attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return {
        "attestation": record,
        "status": protection.effective_status(record),
        "verified": protection.verify_attestation_record(record),
    }


@app.get("/apa/attestation/{attestation_id}/badge.svg")
async def apa_badge_svg(attestation_id: str) -> Response:
    record = protection_store.get_attestation(attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    status = protection.effective_status(record)
    scans = record.get("scans_24h")
    svg = protection.render_badge_svg(status, scans if isinstance(scans, int) else None)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/apa/log")
async def apa_log() -> dict[str, object]:
    entries = protection_store.read_log()
    return {"entries": entries, "total": len(entries)}


@app.post("/apa/revoke")
async def apa_revoke(req: ApaRevokeRequest) -> dict[str, object]:
    record = protection_store.get_attestation(req.attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    endpoint_host = str(record["endpoint_host"])
    binding = protection_store.get_binding(endpoint_host)
    if binding is None:
        raise HTTPException(status_code=400, detail="No key binding for this endpoint host")
    try:
        protection.verify_revocation(req.model_dump(), str(binding["pub"]), endpoint_host)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    updated = protection_store.set_attestation_status(req.attestation_id, "revoked")
    if updated is not None:
        protection_store.append_log("revoked", updated)
    return {"attestation_id": req.attestation_id, "status": "revoked"}


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
