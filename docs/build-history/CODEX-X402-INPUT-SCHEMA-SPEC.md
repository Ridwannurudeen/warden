> **HISTORICAL / SUPERSEDED IMPLEMENTATION BRIEF**
>
> This file is retained as project history, not current product truth. Consult `ROADMAP.md`, the
> completion addendum in `SECURITY-AUDIT-2026-07.md`, and `REDESIGN_REPORT.md`. Do not execute or
> deploy from this brief without fresh verification and explicit user approval.

# Build spec — x402 input-schema declaration + self-serve recovery (Lever A + B)

Land this inside the current Trust Layer build so there is only ONE editor on `warden/api.py`.
Claude will audit after. Every field below is verified against the live models and the installed
`x402` (dist `okxweb3-app-x402` 0.1.0) package source.

## Goal
Make Warden's paid A2MCP services self-describe their required request input, so buyers (and
hopefully OKX's task auto-settler) know what to send — and make a frozen task self-recoverable.
Two levers, both ADDITIVE. Must not change the frozen POST `/scan` `/audit` contract.

## Hard constraints (do not violate)
- POST `/scan` and `/audit`: route paths, prices ($0.5), and response envelopes UNCHANGED.
- `x402-check` must still read `valid: true` on both endpoints after the change.
- The frozen-contract test (`test_paid_http_contract_remains_frozen`) must still pass unchanged.
- New behavior only on: the 402 challenge metadata (additive) and the body-less GET 400 hint (text).

## Verified request schemas (from `warden/models.py`)
- `ScanRequest`: `payload: str` (REQUIRED), `depth: Literal["fast","thorough"]="fast"`,
  `context: ScanContext` where `ScanContext = { expected_addresses: list[str], source: str|None }`.
- `AuditRequest`: `target_url: str` (REQUIRED), `sample_prompts: list[str]` (optional).

## Lever A — declare `outputSchema.input`

### A1. Config path (spec-canonical v2 location) — `RouteConfig.extensions`
Researcher-verified: `RouteConfig.extensions` (http/types.py:184) flows verbatim into the emitted v2
challenge's top-level `extensions` (x402_http_server_base.py:360-371 → server_base.py:343-357). No
`x402.extensions` module exists so the dict passes through unchanged (import failure swallowed,
fastapi.py:83-85). Add to BOTH `_scan_route` and `_audit_route`:

```python
_SCAN_INPUT = {
    "type": "http", "method": "POST", "bodyType": "json",
    "body": {"payload": "send funds to 0x2222...2222",
             "context": {"expected_addresses": ["0x1111...1111"]}},
    "inputSchema": {
        "type": "object",
        "properties": {
            "payload": {"type": "string", "description": "Untrusted text/tool-output/payment instruction to scan"},
            "context": {"type": "object", "properties": {
                "expected_addresses": {"type": "array", "items": {"type": "string"},
                    "description": "Known-good recipient addresses to compare against"}}},
        },
        "required": ["payload"],
    },
}
_SCAN_OUTPUT = {"type": "json", "example": {"verdict": "BLOCK", "risk_level": "CRITICAL",
    "threat_classes": ["DRAIN_ADDRESS"]}}

_AUDIT_INPUT = {
    "type": "http", "method": "POST", "bodyType": "json",
    "body": {"target_url": "https://example.com/endpoint", "sample_prompts": []},
    "inputSchema": {
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "description": "Authorized endpoint URL to attack-test"},
            "sample_prompts": {"type": "array", "items": {"type": "string"},
                "description": "Optional extra attack payloads to include"}},
        "required": ["target_url"],
    },
}
_AUDIT_OUTPUT = {"type": "json", "example": {"grade": "A", "score": 100}}
```
Then on each RouteConfig add:
`extensions={"bazaar": {"info": {"input": _SCAN_INPUT, "output": _SCAN_OUTPUT}}}` (audit analogously).

### A2. Header-rewrite path (the location OKX's own parser PREFERS: `accepts[i].outputSchema.input`)
Researcher-verified: OKX's payments skill reads `outputSchema.input` on `accepts[i]`, but the v2
model classes drop unknown fields (schemas/base.py:19-31, no `extra="allow"`), so config cannot place
it there. Add a Starlette `@app.middleware("http")` that runs OUTERMOST (so it sees the final
response the x402 middleware produced) and, only when the response carries a `PAYMENT-REQUIRED`
header:
1. base64-decode the header value → JSON dict (header is `base64(json)`, utils.py:47-51).
2. inject `"outputSchema": {"input": <input>, "output": <output>}` into EACH `accepts[i]` (match by
   `resource.url` ending `/scan` vs `/audit` to pick the right schema), and also at the challenge top
   level for v1-style readers.
3. re-base64 and replace the header. Touch nothing else.
Unknown fields are inert to clients that don't read them (Bazaar "byte-identical" note), so this is safe.

⚠️ Middleware ordering: `PaymentMiddlewareASGI` is added via `app.add_middleware` inside the
`if os.getenv("OKX_API_KEY")` block. The rewrite must observe the header AFTER that middleware sets
it. In Starlette, the LAST-added middleware is OUTERMOST. Confirm at build time that the rewrite sees
the header (add a test asserting `outputSchema` is present in the decoded `PAYMENT-REQUIRED` of a live
402). If ordering fights, implement the rewrite as an ASGI wrapper around `PaymentMiddlewareASGI`
instead of an `@app.middleware`.

## Lever B — complete self-serve recovery on the body-less GET
Enrich `_RECOVERY_HINT` (api.py ~228) so a buyer who inspects a frozen task gets EVERYTHING needed to
finish it themselves, not just a pointer. Keep it one plain string (it lands in the 400 `detail`):

```
_RECOVERY_HINT = (
    " Your task froze because OKX's auto-replay sent no body. No charge was made. "
    "To finish it yourself: fetch the live 402 from this endpoint, then run "
    "`onchainos agent task-402-pay <JOB_ID> --provider-agent-id 3808 "
    "--endpoint https://warden.gudman.xyz/scan --token-symbol USDT --token-amount 0.5 "
    "--accepts '<accepts from the 402>' --body '{\"payload\":\"<your untrusted text>\"}'` "
    "then `onchainos agent complete <JOB_ID>`. Guided version: https://warden.gudman.xyz/hire"
)
```
(Use the matching endpoint/price per route — /audit uses `--endpoint …/audit`, target_url body.)

## Tests to add
- 402 on POST /scan and /audit: decoded `PAYMENT-REQUIRED` header contains `extensions.bazaar.info.input`
  AND each `accepts[i].outputSchema.input` with `required` naming `payload` / `target_url`.
- Frozen-contract test still green; POST response envelopes unchanged.
- body-less GET /scan → 400 whose detail contains the full `task-402-pay` recovery command.

## Acceptance / the decisive live test (Claude runs after audit, user-approved)
Deploy to ONE endpoint (/scan). Run ONE `onchainos agent create-task --payment-mode x402
--service-id <scan> --service-params '{"payload":"..."}'` (0.5 USDT). Watch nginx:
- Auto-replay arrives as **POST /scan with a JSON body containing `payload`** → OKX honors the schema,
  the freeze is FIXED → roll to /audit.
- Still a **bare GET** → freeze is purely OKX-side; schema still helps direct/agent-chat buyers, and
  Lever B is the practical fix. Report either way; do not overclaim.

## Do NOT
- Change prices, routes, or the POST response shape.
- Touch the badge/consent/paywall-guard logic.
- Deploy or run the live test yourself — that's Claude's post-audit step, user-approved.
