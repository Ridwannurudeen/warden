# Warden Security Audit — July 2026

> **Historical record and current status:** The original audit through **Final disposition** records the
> reviewed state at `b97ea75` on 2026-07-16 and is preserved as evidence of what was found and tested then.
> It is not the current completion status. The dated **2026-07-18 completion addendum** at the end of this
> document supersedes the original deferred-status and closeout tables without rewriting their history.

## Executive summary

This audit reviewed Warden's local source, tests, generated-site pipeline, Python and TypeScript SDKs, MCP surface, endpoint auditor, x402 wiring, APA trust layer, and persistence boundaries. The remediation range is `962525d..b97ea75` on `fix/scanner-exfil-drain-coverage`; the final runtime commit reviewed here is `b97ea75`.

The work fixed **33 production findings**: **2 Critical, 16 High, 12 Medium, and 3 Low**. Each fix has a regression test. Three additional Low-severity evidence or CI defects were corrected. The frozen `/scan` and `/audit` field sets remain unchanged, and the deterministic held-out benchmark remains 64.29% attack recall with 0.00% false positives.

This is not a claim that Warden is exploit-proof. Three reproduced High-severity limitations remain in the legacy signed-audit badge model: badges do not bind the exact endpoint, the public fixed attack battery can be recognized by a target, and caller-supplied custom prompts can dilute the signed grade. Correcting those issues honestly requires a versioned evidence format with an exact target, battery identity, prompt provenance, and benign/liveness controls. Adding those fields would violate the frozen audit response contract in this remediation. Until that migration is designed and tested, signed audit badges must be treated as historical attack-probe receipts, not certification that an endpoint is generally safe.

No network, VPS, wallet, on-chain, paid semantic-provider, deployment, publication, or submission action was performed. All verification was local and offline.

## Scope and methodology

- Read and traced each listed trust boundary before changing it.
- Used static review plus focused dynamic PoCs. A defect was promoted to a finding only after a test or concrete local reproduction demonstrated it.
- Fixed root causes in small commits and added a regression for every production fix.
- Re-ran the complete local Python, JavaScript, TypeScript, contract, benchmark, packaging, lint, and dependency-consistency matrix at `b97ea75`.
- Preserved the exact top-level request and response field sets asserted by `tests/test_gauntlet.py::test_paid_http_contract_remains_frozen`.
- Excluded the unrelated presentation-only commit `556037a` from security finding counts.
- F-19 and F-20 were committed together in `cbdaf84`; this is the one exception to the requested one-fix-per-commit history. The existing local history was not rewritten.

## Threat model

| Surface | Inputs, trust boundary, and attacker control | STRIDE risks | Verified controls | Residual boundary |
|---|---|---|---|---|
| HTTP boundary | Raw HTTP framing, headers, JSON, origin, peer/proxy IP, and payment headers cross ASGI middleware into Pydantic models, rate limiting, x402, and handlers. | Spoofed client/payment state; body tampering; repudiation; stack/secret disclosure; body/depth/rate DoS; authorization bypass. | Streamed byte cap, duplicate/invalid `Content-Length` rejection, JSON depth cap, bounded models, controlled CORS, paid-route wiring tests, malformed-challenge handling, and peer-IP parsing. | Rate state is per process and scans stale buckets linearly. Header presence selects the larger pre-verification payment bucket. Live settlement and deployed CORS were not tested. |
| Detection engine and analyzers | Arbitrary payload and caller-supplied context cross regex, corpus, analyzer, sanitizer, and verdict boundaries. | Context spoofing; evasion/tampering; sensitive-match disclosure; regex/analyzer DoS; unsafe elevation to ALLOW. | Bounded/deduplicated matches, whole-payload neutralization for unsafe classes, sanitized-output rescan, explicit analyzer failure, secret redaction, and the repaired Web3 regex. | No universal per-regex deadline or per-analyzer deadline. Layered encodings, homoglyphs, and broader Unicode normalization remain detection limits. |
| Semantic layer | Runtime-configured endpoint/model/key and an untrusted payload cross an outbound HTTPS provider and untrusted JSON response. | Provider spoofing; response tampering; API-key disclosure; decompression/JSON DoS; semantic elevation. | Absolute HTTPS configuration, paid/thorough-only gating, hard timeout, `Accept-Encoding: identity`, raw-byte cap, strict UTF-8/JSON shape, bounded reason, exception-type-only logging, and deterministic fail-open behavior. | Optional and disabled without all runtime gates. Live provider behavior and the published semantic run were not reproduced offline. |
| APA trust layer | Endpoint URL, DNS, proof document, endpoint signature, issuer signature, nonces, revocations, keys, SQLite state, and transparency records cross public-network and signing boundaries. | Endpoint/key spoofing; record tampering; replay/repudiation; key disclosure; DNS/response DoS; forged trust elevation. | Public-address and redirect restrictions, pinned authority/SNI, nonce and time windows, canonical Ed25519 verification, complete attestation validation, bounded probe deadline/concurrency/body, atomic state transitions, key-history validation, and `0600` fallback key creation. | The local anchor cannot detect a coherent database-plus-anchor replacement; the public external anchor is unpublished. Retired-key grace and legacy HMAC badge rotation remain operator trust boundaries. |
| Marketplace and generated site | External CLI JSON, pagination, agent metadata, URLs, fees, snapshots, and evidence records cross schema validation into static HTML and files. | Listing spoofing; stored XSS/tampering; data disclosure; pagination/build DoS; command/path elevation. | Restricted subprocess environment, argv execution without a shell, bounded/consistent pagination, finite bounded numeric parsing, credential-free HTTPS media, output escaping, numeric file names, and malformed-URL rejection. | Live upstream provenance and network fetches were not exercised. Legacy badge association is only host-scoped. |
| Endpoint auditor | A user URL, optional prompts, DNS answers, consent response, and target responses cross SSRF validation and pinned outbound HTTP into scoring and badge issuance. | Target spoofing; response tampering; audit repudiation; reflected data disclosure; SSRF/resource DoS; false-grade elevation. | Global-IP validation including mapped/NAT64 forms, no redirects, DNS deadline, exact authority/SNI, bounded raw identity responses, strict consent marker, tri-state outcomes, reflection stripping, generic auth failures as inconclusive, and no badge for partial audits. | The legacy battery/badge model remains gameable and host-scoped. Consent is soft by default, and there is no whole-audit deadline. |
| Stores and data | Public submissions, badges, APA records, nonces, concurrent workers, and malformed/truncated local records cross JSONL and SQLite boundaries. | Identity spoofing; lost-update/tampering; repudiation; retained payload disclosure; unbounded growth/lock DoS; state elevation. | Parameterized SQLite, transactions, OS lock for Gauntlet read-modify-write, bounded pending/public data, idempotent identities/revocation, stale-write compare, and malformed-line tolerance. | Badge JSONL has only an in-process lock, no atomic append/fsync, skips corrupt lines rather than repairing them, and has unbounded full-file reads. The committed `deploy/warden.service` starts uvicorn without `--workers`; the live unit was not inspected. |
| MCP server | Local MCP arguments cross FastMCP-generated schemas and Pydantic validation into scanner and auditor operations. | Caller spoofing; argument tampering; result disclosure; oversized-input DoS; typo-based depth elevation/downgrade. | Strict typed depth, bounded payload/context/URL/prompt schemas, full-input rejection instead of truncation, explicit output schemas, and downstream SSRF checks. | Installed FastMCP 3.4.2 defaults to stdio, but `mcp.run()` does not explicitly pin the transport. A future network transport would need authentication and rate limiting. |
| Dependencies and build | PyPI/npm packages, lock data, build backends, and CI actions cross package-manager and workflow trust boundaries. | Package/action spoofing; lock tampering; build disclosure; install DoS; compromised-dependency elevation. | Exact pins for most root runtime packages, exact TypeScript dev dependencies with npm lock integrity, read-only CI permissions, local `pip check`, offline npm audit, tests, build, and package dry-run. | Python has no hash lock; `cryptography`, build tooling, and SDK ranges are lower-bounded; CI actions use floating major tags; CI has no vulnerability scanner. |
| Secrets and configuration | Environment variables, issuer/badge keys, payload secrets, errors, logs, and generated data cross process and filesystem boundaries. | Secret spoofing/tampering; repudiation; log/response disclosure; missing-config DoS; key-based elevation. | Production paywall and badge secret fail closed, key/data paths are ignored, detector output redacts secrets, exception text is suppressed, and key permission regressions exist. | No live key permissions or rotation ceremony was inspected. There is no CI secret-scanning gate, and the badge secret is shared with the index builder. |

## Fixed production findings

All statuses in this table are **FIXED** at `b97ea75`.

| ID | Severity | Location | Reproduced exploit or failure | Proving test | Root-cause fix | Commit |
|---|---|---|---|---|---|---|
| F-01 | High | `warden/mcp_server.py:29` | An attack after the MCP payload cap was silently dropped, so the verdict covered only a safe prefix. | `tests/test_security_mcp_truncation.py::test_mcp_rejects_oversized_payload_instead_of_dropping_the_tail` | Validate the complete request and reject oversize input instead of slicing it. | `d4d46a7` |
| F-02 | High | `warden/api.py:52`, `warden/api.py:100` | A chunked body without `Content-Length` bypassed the header-only cap and could be buffered without bound. | `tests/test_security_http_body_limit.py::test_chunked_body_is_rejected_before_json_validation` | Count every ASGI body chunk and reject invalid, conflicting, or oversized framing. | `89e6f3e` |
| F-03 | Critical | `warden/scanner/scanner.py:40`, `:209`, `:432` | A max-size control-marker payload amplified detections and replacement work; fragment redaction could leave actionable instructions. | `tests/test_security_sanitization_bounds.py::test_max_payload_control_markers_have_bounded_output_and_detections`; `::test_scanner_sanitization_removes_the_entire_unsafe_payload` | Cap/deduplicate matches, remove control markers without expansion, and neutralize the whole unsafe payload. | `3783656` |
| F-04 | Medium | `warden/core/registry.py:35` | Analyzer exception text containing sensitive upstream data was exposed in results and logs. | `tests/test_security_analyzer_errors.py::test_analyzer_exception_does_not_expose_sensitive_message` | Return a constant error and log only analyzer and exception types. | `6d5d007` |
| F-05 | High | `warden/protection.py:257` | Attacker-controlled DNS ran outside the APA timeout and semaphore, allowing unresolved tasks to accumulate. | `tests/test_security_apa_probe_bounds.py::test_probe_deadline_and_concurrency_include_dns_resolution` | Put DNS and the proof fetch under one bounded semaphore and deadline. | `fbf6ad7` |
| F-06 | Medium | `warden/protection_store.py:630`, `scripts/reprobe_protections.py:87` | A stale in-flight reprobe could overwrite a newer signed trust state. | `tests/test_security_reprobe_race.py::test_inflight_reprobe_does_not_overwrite_newer_active_refresh` | Compare the original canonical record inside the write transaction and skip stale updates. | `5f5adb1` |
| F-07 | Medium | `warden/protection.py:449`, `:472`, `warden/badges.py:51` | A valid signature over a malformed or noncanonical attestation could pass incomplete protocol validation. | `tests/test_security_attestation_validation.py::test_server_rejects_issuer_signed_nonconforming_attestation`; `::test_server_rejects_noncanonical_attestation_signature` | Validate the full attestation shape, semantics, ranges, and canonical encodings. | `8c57693` |
| F-08 | Medium | `warden/gauntlet_store.py:34`, `:113`, `:188` | Separate workers could race a review against a submission and lose a record. | `tests/test_security_gauntlet_process_race.py::test_review_and_submission_are_cross_process_serialized` | Serialize JSONL read-modify-write operations with an OS lock file. | `6ee8b91` |
| F-09 | Medium | `warden/badges.py:81`, `warden/badge_store.py:34` | Different same-day audit results could share an ID, and repeated writes duplicated identical badges. | `tests/test_security_badge_identity.py::test_distinct_same_day_same_score_badges_have_distinct_ids`; `::test_record_badge_is_idempotent` | Hash the complete unsigned result and make identical writes idempotent. | `05503ce` |
| F-10 | Medium | `warden/badge_store.py:17`, `warden/gauntlet_store.py:61` | One truncated or non-object JSONL entry made later valid state unreadable. | `tests/test_security_jsonl_recovery.py::test_badge_jsonl_readers_skip_truncated_and_non_object_records`; `::test_gauntlet_jsonl_readers_skip_truncated_and_non_object_records` | Use tolerant readers that skip malformed records and continue. | `d043b75` |
| F-11 | Low | `warden/protection_store.py:576` | Repeated authenticated revocation requests appended duplicate signed revocation history. | `tests/test_security_revocation_idempotence.py::test_repeated_revocation_is_idempotent_and_appends_once` | Return the existing equivalent revoked state without another append. | `9f5fbcf` |
| F-12 | High | `warden/mcp_server.py:29` | A misspelled depth silently became `fast`, and MCP schemas hid runtime limits. | `tests/test_security_mcp_schema.py::test_scan_tool_schema_exposes_bounded_typed_contract`; `::test_scan_tool_rejects_invalid_depth_instead_of_silently_using_fast` | Use strict typed depth and bounded annotated request/output schemas. | `c71a4ca` |
| F-13 | Medium | `sdk/python/warden_guard/client.py:173`, `:189` | The local SDK bypassed server request validation and accepted oversized scanner input. | `sdk/python/tests/test_security_local_input_parity.py::test_local_engine_rejects_oversized_payload_before_scanning` | Validate local scans with the shared `ScanRequest` model. | `11738ef` |
| F-14 | High | `sdk/python/warden_guard/middleware.py:26`, `:64` | Compressed, invalid UTF-8, disconnected, or oversized request bodies could differ from the bytes scanned or exhaust memory. | `sdk/python/tests/test_security_middleware_body.py::{test_non_identity_content_encoding_is_rejected_before_scan_or_downstream,test_invalid_utf8_is_rejected_before_scan_or_downstream,test_oversized_stream_is_rejected_before_scan_or_downstream,test_premature_disconnect_aborts_before_scan_or_downstream,test_invalid_asgi_message_is_rejected_before_scan_or_downstream,test_allow_scans_and_forwards_the_same_utf8_bytes}` | Require identity encoding and strict UTF-8, bound streaming, validate ASGI messages, and forward exactly the scanned bytes. | `f642512` |
| F-15 | High | `sdk/python/warden_guard/client.py:161`, `sdk/python/warden_guard/aio.py:47` | The free hosted client accepted `thorough` even though the demo endpoint always executes `fast`. | `sdk/python/tests/test_security_hosted_depth.py::test_free_sync_client_rejects_thorough_depth_before_network`; `::test_free_async_client_rejects_thorough_depth_before_network` | Reject unsupported free-hosted depth before network access. | `5394759` |
| F-16 | High | `sdk/python/warden_guard/proxy.py:61`, `sdk/python/warden_guard/cli.py:127` | The enforcement proxy could use the truncating free demo path and authorize a malicious tail after a safe prefix. | `sdk/python/tests/test_security_proxy_client.py::{test_reverse_proxy_requires_an_explicit_enforcement_client,test_reverse_proxy_rejects_fail_closed_free_demo_client,test_reverse_proxy_accepts_explicit_protected_client}` | Require an explicit fail-closed local or protected client and route explicit URLs to `/scan`. | `e3eab19` |
| F-17 | High | `sdk/python/warden_guard/llamaindex_guard.py:49` | LLM-visible node metadata was not scanned, allowing injected metadata into synthesis. | `sdk/python/tests/test_security_llamaindex_metadata.py::test_llamaindex_guard_scans_and_neutralizes_llm_visible_metadata` | Scan `MetadataMode.LLM` and exclude the original metadata after sanitization. | `dbf74ed` |
| F-18 | High | `sdk/python/warden_guard/cli.py:25`, `:39` | The APA CLI verifier followed a public redirect to an internal or loopback resource. | `sdk/python/tests/test_security_cli_redirect.py::test_cli_endpoint_verifier_rejects_a_redirected_final_url` | Disable redirects and require an exact final proof URL. | `24abba6` |
| F-19 | Low | `sdk/python/warden_guard/decorator.py:29` | A guarded defaulted parameter was absent from bound arguments and crashed the wrapper. | `sdk/python/tests/test_security_decorator_defaults.py::test_sync_decorator_guards_a_defaulted_argument`; `::test_async_decorator_guards_a_defaulted_argument` | Apply function defaults before scanning and substitution. | `cbdaf84` |
| F-20 | Low | `warden/mcp_server.py:47` | MCP audit schemas omitted target/prompt caps, while runtime behavior truncated prompts. | `tests/test_security_mcp_schema.py::test_audit_tool_schema_exposes_runtime_input_limits` | Publish the runtime bounds in annotated MCP argument schemas. | `cbdaf84` |
| F-21 | High | `warden/api.py:46`, `:52` | A byte-bounded but deeply nested JSON document could trigger parser recursion failure and a 500. | `tests/test_security_json_depth.py::test_paid_scan_rejects_excessive_json_depth_without_recursion_failure` | Reject structural nesting over 64 while ignoring delimiters inside strings. | `9039776` |
| F-22 | High | `warden/auditor.py:407-435` | Substring consent accepted text such as `not-warden-audit-allowed`. | `tests/test_consent.py::test_audit_rejects_negated_consent_marker` | Require an exact case-folded text marker or exact typed JSON consent/status value. | `b761c9e` |
| F-23 | High | `warden/auditor.py:360-397` | Consent used buffered automatic decompression, allowing an oversized response or small compressed bomb before validation. | `tests/test_consent.py::test_audit_rejects_oversized_consent_body`; `::test_audit_rejects_compressed_consent_body` | Stream raw identity bytes with a 4,096-byte cap. | `b761c9e` |
| F-24 | High | `warden/auditor.py:211-290` | Target-controlled compression, invalid UTF-8, JSON depth, huge integers, or response size could exhaust or crash scoring. | `tests/test_auditor_scoring.py::{test_oversized_response_is_inconclusive,test_compressed_response_is_inconclusive,test_deeply_nested_json_response_is_inconclusive,test_oversized_json_integer_is_inconclusive,test_invalid_utf8_response_is_inconclusive}`; `tests/test_consent.py::test_audit_rejects_invalid_utf8_consent_marker` | Bound raw bytes, reject compression/invalid UTF-8, and classify parser-limit failures as inconclusive. | `75b664f` |
| F-25 | High | `warden/apa_url.py:15`, `:69` | IPv4-compatible IPv6, private/link-local NAT64 embeddings, and multicast forms bypassed incomplete SSRF checks. | `tests/test_ssrf.py::test_audit_blocks_non_global_ips`; `::test_audit_allows_nat64_mapped_global_ip` | Reject multicast/compatible space and recursively validate embedded IPv4. | `80f7def` |
| F-26 | Medium | `warden/auditor.py:68` | Target DNS validation had no deadline and could stall an audit task. | `tests/test_ssrf.py::test_audit_url_validation_has_a_deadline` | Enclose URL validation and DNS in the audit timeout. | `80f7def` |
| F-27 | High | `warden/auditor.py:225`, `:347` | A non-default port was dropped from `Host`, so the auditor could test a different virtual host than requested. | `tests/test_ssrf.py::test_audit_preserves_target_authority_for_requests` | Preserve exact HTTP authority while using hostname-only TLS SNI. | `a1abc5c` |
| F-28 | Medium | `warden/marketplace/fetch.py:136`, `:234` | Inconsistent unique pagination could run indefinitely and grow memory. | `tests/test_marketplace.py::{test_fetch_rejects_inconsistent_pagination_metadata,test_fetch_stops_at_the_page_limit,test_fetch_rejects_invalid_page_size_before_running_command}` | Bound page size/list/pages, validate metadata, and refuse partial promotion. | `d9f6724` |
| F-29 | Medium | `warden/marketplace/fetch.py:24`, `:45`, `:81` | NaN/Infinity and extreme fee exponents could emit invalid JSON or trigger massive decimal expansion. | `tests/test_marketplace.py::test_marketplace_agent_rejects_nonfinite_rates`; `::test_marketplace_service_rejects_unsafe_fee_amounts` | Require finite bounded numeric values and bounded `Decimal` formatting. | `60e59f4` |
| F-30 | Medium | `warden/marketplace/render.py:43`, `:130`, `:154` | Malformed IPv6/port URLs raised during rendering or evidence association and stopped the build. | `tests/test_marketplace.py::{test_renderer_ignores_malformed_avatar_urls,test_badge_association_ignores_malformed_service_url,test_apa_association_requires_valid_signature_reviewed_link_and_matching_service_host}` | Catch URL-property errors, validate ports, and reject malformed authorities. | `75747fa` |
| F-31 | Critical | `warden/scanner/patterns.py:45` | `sign` plus near-max whitespace and no suffix caused catastrophic regex backtracking. | `tests/test_scanner.py::TestLayer1Regex::test_web3_sign_pattern_completes_for_max_length_whitespace` | Make the ambiguous whitespace repetition atomic. | `36d1fae` |
| F-32 | Medium | `warden/scanner/semantic.py:81`, `:93`, `:106` | Locally, 1,622 gzip bytes expanded to 1,638,400 bytes before `aiter_bytes()` enforced the nominal 16,384-byte cap. | `tests/test_d1_semantic_guard.py::test_compressed_semantic_response_is_rejected_before_decompression` | Request identity encoding, reject other encodings before iteration, and count bounded raw bytes. | `354fbb6` |
| F-33 | High | `warden/auditor.py:116-166`, `:234-274` | Generic 401/403 responses counted as blocked, and a partially inconclusive run could receive a signed badge. | `tests/test_auditor_scoring.py::test_auth_failure_without_threat_evidence_is_inconclusive`; `tests/test_c1_inconclusive_audits.py::test_partial_audit_returns_results_without_a_signed_badge` | Require threat evidence for auth failures and a fully conclusive battery before signing. | `b97ea75` |

## Corrected evidence and CI defects

| ID | Severity | Location | Correction | Proving test | Commit | Status |
|---|---|---|---|---|---|---|
| V-01 | Low | `README.md:265`, `benchmark/README.md:58`, `site/status.js:142` | Align published semantic benchmark wording with the committed result and require mode/methodology consistency. | `tests/js/ph3-evaluation.test.js`: `public evaluation data matches the committed held-out benchmark`; `evaluation normalization rejects inflated or ambiguous evidence`; `status surface publishes the held-out methodology without an external request` | `d704609` | CORRECTED |
| V-02 | Low | `.github/workflows/ci.yml:8`, `:23` | Install and independently test both optional Python adapters; restrict token permissions to `contents: read`. | `tests/test_security_ci_optional_adapters.py::test_ci_installs_and_runs_optional_python_adapters`; `::test_optional_adapter_tests_skip_independently` | `ec42dbb` | CORRECTED |
| V-03 | Low | `tests/test_consent.py:191` | Stop globally replacing the production response reader in a consent test. | `tests/test_consent.py::test_echoed_payload_does_not_count_as_blocked` | `2f8db01` | CORRECTED |

## Deferred findings and residual risk

The first six findings (D-01 through D-06) were reproduced against `b97ea75` and have since been fixed on `fix/scanner-exfil-drain-coverage`; their rows are updated to FIXED with the closing commit and proving test. The remainder are not represented as fixed.

| ID | Severity | Location | Reproduction and impact | Why deferred / required next step | Status |
|---|---|---|---|---|---|
| D-01 | High | `warden/badges.py`, `warden/marketplace/render.py` | Audits of two different paths on the same host produced the same signed identity, and a host badge associated with a service on a different path or port. Scheme, port, path, query, and battery version are absent from the signed record. | FIXED in `76060bd`. `issue_badge` now emits a versioned v2 record whose signed payload (and audit id) binds a canonical exact target (scheme/host/port/path/query) plus battery identity/version; `associate_badges` requires an exact canonical endpoint match for v2 records. The `/audit` response field set is unchanged (binding lives in the signed dict, not new response fields). Proof: `tests/test_security_audit_evidence.py::test_two_paths_on_same_host_get_distinct_signed_identities`, `tests/test_marketplace.py::test_v2_badge_association_requires_exact_path_and_port`. | FIXED |
| D-02 | High | `warden/auditor.py` | A target that recognizes and rejects all 20 public attack probes received a signed A/100 without any benign or liveness control. | FIXED in `76060bd`. The auditor now runs benign control probes and withholds the signed badge when a target blocks every conclusive benign control (blind-rejection fails liveness). Proof: `tests/test_security_audit_evidence.py::test_target_that_blocks_everything_earns_no_signed_grade`. | FIXED |
| D-03 | High | `warden/auditor.py` | A target blocking 16/20 fixed probes scored B/80, but 20 trivially blocked caller-supplied prompts raised the same target to signed A/90 (36/40). | FIXED in `76060bd`. The signed score/grade is computed from the fixed battery only; caller prompts are unsigned diagnostics recorded as provenance (battery hash + caller-prompt count) and cannot move the signed grade. Proof: `tests/test_security_audit_evidence.py::test_caller_prompt_dilution_cannot_raise_the_signed_grade`. | FIXED |
| D-04 | Medium | `warden/auditor.py`, `deploy/DEPLOY.md:44` | Consent is soft by default; a paid caller can cause 20–40 active POST probes to a public target that did not opt in. SSRF controls, payment, and rate limits reduce but do not remove the abuse boundary. | FIXED in `435bbf8`. `_require_consent()` now defaults to hard consent (`WARDEN_REQUIRE_CONSENT` must be an explicit off value to restore soft mode); DEPLOY.md updated. Proof: `tests/test_consent.py::test_audit_refuses_non_consenting_target_by_default`. | FIXED |
| D-05 | Medium | `warden/api.py`, `warden/ratelimit.py` | Mere presence of a forged payment header selects the 600/minute bucket instead of the normal 60/minute bucket before x402 verification. This does not bypass settlement, but increases facilitator-verification work an unauthenticated source can trigger. | FIXED in `712481c`. The elevated payment bucket is granted only to clients with a live verified-settlement grant (recorded from the x402 `PAYMENT-RESPONSE` receipt on a 2xx); an unverified/forged payment header falls through to the ordinary limit. Proof: `tests/test_s1_paid_rate_limit.py::test_unverified_payment_header_uses_ordinary_bucket`, `tests/test_ratelimit.py::test_forged_payment_header_gets_ordinary_bucket` and `::test_verified_payer_gets_elevated_bucket`. | FIXED |
| D-06 | Medium | `warden/badge_store.py` | Badge JSONL uses only an in-process lock, has no atomic commit/fsync, skips truncated records, and performs full-file reads. Crash loss, multi-process races, and growth cost remain possible. | FIXED in `d4f03c5`. `record_badge` now writes under a cross-process file lock (msvcrt/flock, matching `gauntlet_store`) and appends with `flush()` + `os.fsync()`. Proof: `tests/test_badges.py::test_badge_store_append_is_atomic_and_durable` and `::test_badge_store_concurrent_writes_do_not_interleave`. Residual: full-file reads and unbounded growth remain (registry-scale indexing is future work). | FIXED |
| D-07 | Medium | `site/data/apa-log-anchor.json`, `warden/protection_store.py:331-337` | The independent APA anchor is unpublished. A coherent replacement of the database and local anchor is outside the local verifier's trust model. | Publish and monitor an independently hosted signed checkpoint; retain explicit wording that the 24-hour count is not independently audited. | DEFERRED |
| D-08 | Medium | `pyproject.toml`, `sdk/python/pyproject.toml`, `.github/workflows/ci.yml` | Python resolution is not reproducible with hashes, several ranges are lower-bounded, and CI has no vulnerability audit. Local consistency passed, but Python advisory status was not established offline. | Add a reviewed hash lock and CI dependency/security scanning with a defined update policy. | DEFERRED |
| D-09 | Medium | `warden/api.py:330-352`, `PAYMENT.md:20-25`, `tests/fixtures/payment_required.json` | Runtime source and tests configure 0.5 USDT for `/scan` and `/audit`, while `PAYMENT.md` and the stored challenge fixture describe a 0.01 `/scan` observation. Live pricing was not checked. | Reconcile documentation and fixtures only after read-only live verification; do not infer the deployed price from stale static evidence. | DEFERRED |
| D-10 | Medium | `benchmark/results.json`, `warden/scanner/semantic.py:157-168` | Deterministic coverage is 18/28 attacks (64.29%) with ten named misses. Semantic coverage is optional and fail-open, and its recorded 20/28 result was not rerun offline. | Improve coverage only with held-out evaluation and zero false-positive regression; preserve the deliberate semantic failure boundary. | ACCEPTED LIMIT |
| D-11 | Low | `warden/mcp_server.py:77-78` | The current installed FastMCP defaults to stdio, but transport is implicit. | Pin stdio or add authentication/rate limiting before any network exposure. | DEFERRED |
| D-12 | Low | `warden/api.py:261-274` | Source defaults are controlled and wildcard origins disable credentials, but there is no dedicated CORS regression and live headers were not checked. | Add config-level CORS tests and verify deployed headers during an approved live audit. | DEFERRED |
| D-13 | Low | `README.md:249` | The repository tree text says 92 attack cases while the committed corpus contains 94. | Correct the documentation in a separate evidence-only change. | DEFERRED |
| D-14 | Medium | `warden/auditor.py:91-114`, `:211-230` | Each probe has a timeout, but the 20–40 probes run sequentially with no enclosing whole-audit deadline. A slow public target can therefore retain one audit task for roughly 100–200 seconds before overhead. | Add a whole-audit deadline and explicit partial-result behavior without weakening the no-partial-badge rule. | DEFERRED |

Proof references for the deferred findings:

This exact offline command durably reproduces D-01 through D-03 from the repository root:

```powershell
@'
import asyncio
import os
from urllib.parse import urlparse

import warden.auditor as auditor_module
from warden.auditor import AgentAuditor, AuditOutcome

os.environ["WARDEN_BADGE_SECRET"] = "audit-limitation-test-secret"
auditor_module.record_badge = lambda record: None

async def validate(target_url):
    parsed = urlparse(target_url)
    return f"https://93.184.216.34{parsed.path or '/'}", "example.org", parsed

async def consent(*args):
    return True

async def run(attacks, target_url, sample_prompts=None):
    auditor = AgentAuditor()
    auditor._validate_public_http_url = validate
    auditor._verify_target_consent = consent
    auditor._load_representative_attacks = lambda: attacks

    async def outcome(*args, **kwargs):
        payload = args[3]
        return (
            AuditOutcome.NOT_BLOCKED
            if payload.startswith("fixed-miss")
            else AuditOutcome.BLOCKED
        )

    auditor._target_outcome = outcome
    return await auditor.audit(target_url, sample_prompts)

async def main():
    all_blocked = [
        {"id": f"fixed-{i}", "category": "PROMPT_INJECTION", "payload": f"fixed-block-{i}"}
        for i in range(20)
    ]
    path_a = await run(all_blocked, "https://example.org/demo-safe")
    path_b = await run(all_blocked, "https://example.org/real-service")
    print(
        "D01",
        f"audit_id_equal={path_a.badge_record.audit_id == path_b.badge_record.audit_id}",
        f"signed_fields={sorted(path_a.badge_record.model_dump())}",
    )
    print(
        "D02",
        f"grade={path_a.grade}",
        f"score={path_a.score}",
        f"blocked={path_a.badge_record.blocked}/{path_a.badge_record.total}",
        f"signed={path_a.badge_record is not None}",
    )

    mixed = [
        {"id": f"fixed-{i}", "category": "PROMPT_INJECTION", "payload": f"fixed-block-{i}"}
        for i in range(16)
    ] + [
        {"id": f"fixed-{i}", "category": "PROMPT_INJECTION", "payload": f"fixed-miss-{i}"}
        for i in range(16, 20)
    ]
    baseline = await run(mixed, "https://example.org/scan")
    diluted = await run(
        mixed,
        "https://example.org/scan",
        [f"custom-block-{i}" for i in range(20)],
    )
    print(
        "D03",
        f"baseline={baseline.grade}/{baseline.score:.0f}",
        f"diluted={diluted.grade}/{diluted.score:.0f}",
        f"blocked={diluted.badge_record.blocked}/{diluted.badge_record.total}",
    )

asyncio.run(main())
'@ | python -
```

Observed output at `b97ea75`:

```text
D01 audit_id_equal=True signed_fields=['audit_id', 'blocked', 'consent_verified', 'grade', 'issued_at', 'score', 'signature', 'target_host', 'total']
D02 grade=A score=100.0 blocked=20/20 signed=True
D03 baseline=B/80 diluted=A/90 blocked=36/40
```

The `b97ea75` reproduction above no longer holds on the fix branch: benign controls now fail liveness for a blind-rejecting target (so `path_a.badge_record` is `None`), and the target/battery binding gives the two paths distinct audit ids. The closing regression tests in `tests/test_security_audit_evidence.py` assert the fixed behavior directly.

Migration note for existing v1 badges: legacy records carry no `badge_version`/`target`/`battery` fields. They remain individually verifiable (`verify_badge` is unchanged for them) and are treated as historical host-scoped receipts — `associate_badges` still matches them by host only. New audits emit v2 bound records; v1 records must not be presented as exact-endpoint certifications.

- D-04's former soft-default behavior is preserved only under an explicit `WARDEN_REQUIRE_CONSENT=false`; the hard-consent default is proven by `tests/test_consent.py::test_audit_refuses_non_consenting_target_by_default`.
- D-05's former elevated-bucket-on-forged-header behavior is closed; a forged header now shares the ordinary bucket.
- D-06 retains the corrupt-line-skipping behavior proven by `tests/test_security_jsonl_recovery.py`; the durability gap is closed with a cross-process lock plus fsync.
- D-07 is asserted honestly by the external-anchor state and `tests/test_ph4_external_anchor.py`; the committed public anchor remains unpublished.
- D-08 and D-09 are direct configuration/document comparisons. D-10 was reproduced by the held-out benchmark command. D-11 was checked against installed FastMCP 3.4.2 behavior. D-12 and D-13 are source/test-inventory comparisons.
- D-14 follows directly from the sequential loop and per-request five-second timeout; no outer timeout encloses the loop.

Additional trust boundaries:

- Badge IDs are a 64-bit truncated hash. Collision is theoretical at current volume but should be widened in a versioned format.
- Retired APA keys accept records signed within their bounded historical validity window. A compromised retired key can forge backdated records inside that grace boundary.
- Rotating the legacy HMAC badge secret invalidates old records; retaining a compromised key preserves forgeability because legacy records carry no key identifier or issuer history.
- The free hosted Python and TypeScript clients intentionally fail open on transport/HTTP failure. Documentation directs enforcement users to local Python with `fail_open=False`; callers must not treat the free hosted client as a fail-closed control.
- The rate limiter is in-memory and per process. Multi-worker or distributed deployment needs a shared limiter and bounded cleanup strategy.
- `expected_addresses` has no independent item-count bound, although the enclosing request body is byte-bounded.
- JSONL malformed-line handling preserves later records but does not repair, quarantine, or prove integrity of the damaged history.

## Verification results

All commands below were run locally at `b97ea75` on 2026-07-16.

| Gate | Command | Result |
|---|---|---|
| Root Python suite | `python -m pytest -q` | **655 passed, 1 skipped, 1 warning** in 41.93s |
| Python SDK suite | `python -m pytest -q` from `sdk/python` | **95 passed** in 21.75s |
| Browser JavaScript suite | `node --test tests/js/*.test.js` | **122 passed, 0 failed** |
| TypeScript SDK suite | `npm test -- --run` from `sdk/ts` | **31 passed** across 3 files |
| Ruff | `python -m ruff check .` | **All checks passed** |
| Frozen paid contract | `python -m pytest -q tests/test_gauntlet.py::test_paid_http_contract_remains_frozen` | **1 passed** |
| Held-out benchmark | `python scripts/benchmark_recall.py` | **18/28 attacks = 64.29%; 0/16 false positives = 0.00%** |
| APA portable verifier | `python spec/verify_apa.py --selftest` | **SELFTEST PASSED**; genuine accepted, tamper and wrong key rejected |
| Distribution/x402 wiring | `python -m pytest -q tests/test_r4_distribution.py tests/test_r4_x402_route_wiring.py` | **2 passed** |
| TypeScript build | `npm run build` from `sdk/ts` | **Passed** |
| TypeScript package preview | `npm pack --dry-run` from `sdk/ts` | **Passed**; 18 files, 14.6 kB package, no tarball created |
| npm advisory check | `npm audit --offline` from `sdk/ts` | **0 vulnerabilities reported** from locally available advisory data |
| Python dependency consistency | `python -m pip check` | **No broken requirements found** |

The root suite emitted one existing Starlette/httpx TestClient deprecation warning. It did not fail a test.

`bandit` was not installed. `pip-audit 2.10.0` was installed, but its available vulnerability services require network access and no offline advisory database was present, so a Python vulnerability scan was not claimed. A tracked-file secret-pattern review found only intentional security test vectors and documentation paths; no tracked live credential was identified.

The deterministic misses were:

- `held-prompt-002`
- `held-prompt-003`
- `held-role-002`
- `held-web3-002`
- `held-encoding-002`
- `held-corpus-002`
- `held-drain-002`
- `held-tool-003`
- `held-secret-002`
- `held-link-002`

## What was not tested

- No live x402 challenge, facilitator reachability, settlement, replay, deployed price, or paid route was called.
- No paid semantic request was made. The committed semantic-enabled 71.43% recall / 0% false-positive result is recorded evidence, not an independently reproduced result from this audit.
- No live marketplace, OKX, DNS, TLS, target endpoint, public APA anchor, VPS, nginx, systemd, filesystem permission, or key-rotation ceremony was inspected.
- No wallet, signing service, chain, transaction, deployment, publication, or submission operation was performed.
- No multi-host, network-filesystem, crash-consistency, long-duration soak, or distributed-rate-limit test was run.
- No external dependency advisory data was fetched because the audit prohibited network access.
- Browser behavior was covered by repository JavaScript tests; no live browser smoke test against a deployed site was performed.

## Surface closeout checklist

| Surface | Status | Fixed findings | Principal proof |
|---|---|---:|---|
| HTTP boundary | DONE for local implementation; live payment/CORS PARTIAL | 3 | Body framing, JSON depth, frozen contract, rate/x402 suites |
| Detection engine and analyzers | DONE for reproduced defects; coverage PARTIAL | 4 | Sanitization bounds, analyzer errors, Web3 timeout, held-out benchmark |
| Semantic layer | DONE for local adapter; live provider UNTESTED | 1 | Semantic guard suite and compressed-response regression |
| APA trust layer | DONE for local signing/state; external witness PARTIAL | 7 | Probe bounds, attestation validation, reprobe race, revocation, APA self-test |
| Marketplace and generated site | DONE for offline/static paths | 3 | Pagination, numeric, malformed URL, escaping, site suites |
| Endpoint auditor | DONE for fixed transport/scoring defects; badge model DEFERRED | 7 | Consent, SSRF, scoring, response-bound, partial-audit regressions |
| Stores and data | DONE for reproduced races/recovery; badge durability PARTIAL | 4 | Process-race, identity, JSONL recovery, stale-write tests |
| MCP server | DONE for default stdio; network transport UNTESTED | 3 | Input-cap, strict-schema, truncation regressions |
| SDKs | DONE for local implementation and packaging | 7 | Python SDK 95, TypeScript 31, build and pack dry-run |
| Dependencies and supply chain | PARTIAL | 1 evidence correction | npm offline audit, `pip check`, CI assertions; Python CVEs untested |
| Secrets and configuration | PARTIAL | 1 cross-surface fix | Redaction/error tests and tracked-file review; live keys/config untested |

## Final disposition

The audited runtime at `b97ea75` passes the complete offline verification matrix and closes every reproduced Critical implementation defect. The fixed HTTP, scanner, SDK, APA, marketplace, MCP, semantic-response, and partial-audit defects have regression coverage.

Warden is **not ready to present the legacy signed audit badge as endpoint certification**. The recommended next security change is a deliberately versioned audit-evidence v2 that binds the canonical endpoint, battery version/hash, fixed-versus-custom prompt provenance, benign/liveness controls, and issuer key identity. That work must update the frozen contract through an explicit migration rather than hiding changed evidence semantics behind the legacy fields.

---

## Completion addendum — 2026-07-18

Local verification for this addendum was refreshed on 2026-07-18 from
`feat/post-hackathon-completion`. It covers finite repository work only. It does not upgrade a source-ready
mechanism into a deployment, independent witness, paid transaction, uptime result, package release, customer
relationship, or commercial outcome.

### Addendum status vocabulary

| Classification | Meaning |
|---|---|
| **FINITE SOURCE BUILT / LOCALLY VERIFIED** | The bounded source change exists and its focused local regression gates pass. |
| **ACCEPTED DETECTOR LIMITATION** | The measured detection gap remains published and is not disguised as fixed. |
| **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** | The repository mechanism is complete, but closure requires an approved deployment, production observation, independent system, credentials, funds, or another party. |
| **NOT AUTHORIZED / NOT BUILT** | The action or expansion was not authorized and was not represented as completed. |

### Current disposition of D-01 through D-14

This table supersedes the status column in the historical deferred-findings table above. The original
reproductions remain valid evidence of the `b97ea75` state.

| ID | Current disposition | Current proof and remaining boundary | Classification |
|---|---|---|---|
| D-01 | Closed in source | New version-2 audit evidence binds the canonical scheme, host, port, path, query, and battery identity; exact endpoint association is required. `tests/test_security_audit_evidence.py` and marketplace association regressions cover the boundary. Legacy version-1 records remain historical host-scoped receipts. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-02 | Closed in source | The immutable audit battery includes three benign liveness controls. A target that blindly rejects all inputs receives no signed grade or portable record. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-03 | Closed in source | The signed score uses only the fixed battery. Caller prompts are unsigned diagnostics and cannot inflate or dilute the signed grade. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-04 | Closed in source | Endpoint consent is hard by default; soft mode requires an explicit operator override. Shield also requires explicit owner enrollment and still performs endpoint consent. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-05 | Closed in source | Rate limits and verified-payer elevation use shared SQLite state. A forged payment header receives no elevated grant; only a successful response carrying a settlement receipt records the bounded grant. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-06 | Closed in source | The legacy badge registry is bounded to 5,000 records and atomically rewritten under a cross-process lock with file fsync and POSIX directory fsync. A failed replacement preserves the prior complete registry. Malformed-line repair remains a separate residual boundary below. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-07 | Mechanism complete; independent witness open | Signed checkpoints, atomic publication, bounded append-only checkpoint history, prefix verification, and retained-head pinning are implemented and tested. The committed anchor sentinel remains `unpublished`, and no independently controlled off-domain retention or on-chain witness exists. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| D-08 | Source closure complete; hosted execution open | Root Python dependencies are exact and hash-locked. CI installs with `--require-hashes`, runs `pip-audit`, pins GitHub Actions to immutable commits, checksum-pins TruffleHog, scans full history, audits/builds/packs the TypeScript SDK, and follows `docs/DEPENDENCY_UPDATE_POLICY.md`. The final pushed commit still needs a hosted CI run; local source cannot prove that remote execution. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| D-09 | Source corrected; deployed challenge stale | Source, tests, fixtures, and documentation bind `/scan` and `/audit` to x402 v2 `exact`, X Layer, 500000 atomic units (0.5 USDT), and EIP-712 `{"name":"USD₮0","version":"1"}`. The documented read-only probe on 2026-07-18 still observed live `{"name":"USDT","version":"1"}`. An approved deploy and read-only reprobe are required before claiming live authorization or settlement correctness. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| D-10 | Measured limitation retained | The current deterministic held-out result is 87/94 attacks detected (92.55% recall) with 0/45 benign false positives. The seven exact misses are `held-prompt-002`, `held-prompt-003`, `held-role-002`, `held-corpus-002`, `held-drain-002`, `held-secret-002`, and `held-evade-mix-003`. Optional model tiers remain disabled without provider configuration and have no current independent calibration result. | **ACCEPTED DETECTOR LIMITATION** |
| D-11 | Closed in source | The MCP entrypoint explicitly invokes `mcp.run(transport="stdio")`. No network MCP transport is exposed by this entrypoint. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-12 | Source closure complete; production headers open | Exact configured-origin behavior and wildcard-without-credentials behavior have dedicated CORS regressions. Deployed nginx and application response headers were not reverified after these changes. | **SOURCE READY / EXTERNAL, OPERATOR, OR TIME DEPENDENT** |
| D-13 | Closed in source | Public documentation and regression contracts use the current 94-case attack set. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |
| D-14 | Closed in source | `AgentAuditor.audit()` now encloses the complete audit in a 30-second deadline and converts expiry into an explicit no-partial-grade/no-badge failure. | **FINITE SOURCE BUILT / LOCALLY VERIFIED** |

### Finite security and product mechanisms completed

The post-audit build also completed these bounded source items:

- Python and TypeScript SDKs, local Python enforcement, LangChain and LlamaIndex adapters, MCP stdio, and
  a fail-closed Warden Gateway;
- strict x402 challenge validation and caller-owned payment callbacks that permit exactly one paid replay;
- shared SQLite rate windows, verified-settlement grants, bounded runtime metrics, and anonymous
  multi-process outbound-probe leases;
- the owner-enrolled Warden Shield lifecycle with signed renewals, drift states, bounded metadata-only
  events, and hardened scheduling units;
- explicit opt-in redacted feedback, bounded retention, cross-process-safe human review, exactly-one dataset
  promotion, canonical corpus provenance, and k=5-suppressed aggregate threat intelligence;
- the public ASP Payload Security Standard draft and its machine-readable profile;
- readiness and unsigned-challenge monitoring, dead-man transition alerts, deterministic monthly summaries,
  and a policy that distinguishes a readiness objective from an SLA;
- portable Ed25519 endpoint-audit records bound to the exact subject and immutable battery, including
  issuance-log binding, expiry, lookup, and revocation;
- a candidate-only, fail-closed issuer-key rotation orchestrator and rollback runbook;
- immutable CI action pins, a checksum-pinned full-history secret scan, hash-locked Python dependencies,
  local and hosted advisory gates, and a reviewed dependency-update policy;
- a packaged canonical corpus fingerprint; and
- APA schemas, the portable reference verifier, and the 12-vector conformance pack.

These mechanisms are source capabilities. They do not prove that a production operator enabled them or that
an external party consumed their outputs.

### Current residual architecture and operating risks

1. **No independent log witness.** The publisher and same-origin public files remain inside Warden's
   operator boundary. A coherent replacement remains detectable only relative to a history head retained by
   an independent party or system.
2. **SQLite is a single-host coordination boundary.** The configured databases coordinate multiple workers
   and scheduled processes sharing one host and filesystem. They are not a distributed, multi-host rate,
   lease, metrics, or consensus store.
3. **Legacy badge identity and key history.** Legacy HMAC audit badges use a 16-hex-character (64-bit)
   truncated identifier. Collision is theoretical at current volume but the identifier is not suitable as
   a globally unique security primitive. Legacy records also carry no key identifier or issuer history:
   rotating the HMAC secret invalidates old records, while retaining a compromised secret preserves
   forgeability. Portable Ed25519 endpoint-audit evidence is the preferred format.
4. **Retired APA key grace.** Verifiers select a retired issuer key using the signed `verified_at` cutoff.
   The one-hour attestation lifetime bounds, but cannot eliminate, forged backdating inside the
   post-retirement grace window.
5. **Hosted SDK fail-open modes.** The free hosted Python and TypeScript defaults convert transport or HTTP
   failure into an `ALLOW` telemetry result. They must not be used as a fail-closed action boundary. Local
   Python and Gateway enforcement explicitly use fail-closed behavior.
6. **Production `expected_addresses` item count.** `ScanContext.expected_addresses` has no independent
   list-length cap, although payload length, structural JSON depth, and the one-megabyte HTTP body bound cap
   total request size. The demo context has a separate item cap.
7. **Malformed JSONL history is tolerated, not repaired.** Badge and related readers can skip malformed
   lines so later records remain available. They do not repair, quarantine, or cryptographically prove the
   integrity of the damaged historical line.
8. **Detector and model boundary.** The deterministic benchmark is small and authored, not universal
   efficacy evidence. Optional semantic and embedding thresholds are uncalibrated, external-provider
   behavior was not reproduced here, and provider failure preserves the deterministic result.
9. **Live key and filesystem operation remains untested.** Local tests cover validation, transactions,
   candidate rotation, and runbook contracts. They do not prove production key provenance, file ownership,
   permissions, backup handling, or a completed rotation ceremony.

### External and time-dependent work not completed

No deploy, VPS mutation, push of this completion branch, registry package publication, listing submission,
hackathon submission, social post, funded transaction, paid settlement replay, honeypot funding, payout,
wallet action, or production key rotation was authorized or performed as part of this completion work.

No complete 30-day monitor window was observed; the committed service-monitor source is explicitly
`not_running`. Therefore no achieved uptime, historical availability, or SLA is claimed.

No Coinbase, Solana, Google AP2, A2A escrow, evaluator-stake, marketplace-partnership, CertiK-partnership,
grant, customer-enrollment, subscription, review-volume, or revenue outcome was implemented or claimed.
Those are external product or business decisions, not deferred security fixes.

### Addendum verification

The following commands and results were reproduced locally while preparing this addendum. The test groups
overlap and must not be summed as one suite total:

| Gate | Result |
|---|---|
| Focused audit, consent, rate, payment, x402, observability, probe, Shield, feedback, standard, reliability, endpoint-audit, rotation, supply-chain, conformance, anchor, and distribution suite | **229 passed, 1 warning** |
| Legacy badge durability/recovery and verified-payer rate-limit suite | **16 passed, 1 warning** |
| Python x402 replay, LangChain, LlamaIndex, and Gateway suite | **45 passed** |
| TypeScript client and x402 replay suite | **70 passed** |
| `python scripts/benchmark_recall.py --json` | **87/94 attacks detected; 0/45 benign false positives; seven named misses above** |
| `python spec/verify_apa.py --selftest` | **SELFTEST PASSED** |
| `python spec/run_conformance.py` | **APA CONFORMANCE PASSED - 12 vectors passed** |

The warning in the two root test groups is the existing Starlette/httpx TestClient deprecation warning. UI
integration and final whole-tree, browser, accessibility, responsive, performance, and hosted CI results are
reported separately; this addendum invents none of them.

### Addendum disposition

All fourteen originally deferred items now have an explicit outcome: D-01 through D-06, D-11, D-13, and
D-14 are closed in finite source; D-07, D-08, D-09, and D-12 have complete source mechanisms but remain
operator or external verification work; and D-10 remains an honestly published detector limitation.

That is why the earlier audit listed deferred and untested work: some findings required later bounded source
changes, while others could never be closed by editing a repository alone. The finite source work is now
built and locally verified. The remaining items are not concealed engineering defects; they are explicitly
bounded production, independent-witness, elapsed-time, provider, funding, or business outcomes.
