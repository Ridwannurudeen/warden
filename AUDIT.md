# Warden — Audit Scope (Claude)

Codex builds; **Claude audits every gate before it is considered done.** This is both Claude's checklist and Codex's acceptance spec — if the build passes this, the gate passes. Audits are adversarial: the job is to find the false-positive or the missed staged attack *before* a judge does, because a detection tool that misfires on stage loses the room.

## Method
At each gate Claude will, in order: (1) read the changed files, (2) run the tests and the corpus gate itself (not trust a green claim), (3) run a focused adversarial pass with a `security-reviewer` subagent, (4) drive the actual behavior end-to-end for the demo path. Findings are reported most-severe-first; nothing is marked done while `test_corpus.py` is red.

---

## Gate A — detection engine + corpus (the keystone)
**Correctness**
- [ ] The four analyzers implement the `Analyzer` ABC correctly (name/weight/`async analyze`→`AnalyzerResult`); registry weight-normalization still sums to 1.0 with four analyzers.
- [ ] `verdict.py` decision logic matches §5.3: hard-BLOCK short-circuits fire *before* bands; band boundaries correct at 20 and 70; invalid input → BLOCK (fail-closed).
- [ ] `DrainAddressAnalyzer`: mismatch vs `expected_addresses` → BLOCK; a legit address referenced *without* transfer intent and with no expected set → **not** flagged (false-positive check). EVM compare is case-insensitive.
- [ ] `ExfiltrationAnalyzer`: real BIP-39 seed / private key → BLOCK; ordinary prose mentioning "key" or "wallet" → not flagged.
- [ ] `MaliciousLinkAnalyzer`: punycode/homoglyph/IP-literal/data: flagged; a normal `https://docs.example.com` → not flagged.
- [ ] `ToolHijackAnalyzer`: tool-call-shaped JSON with a financial action → flagged; ordinary JSON data → not flagged.

**Anti-flake (the thing that wins or loses judges)**
- [ ] Claude runs `pytest tests/test_corpus.py` locally — must be 100% green, deterministic across ≥3 runs.
- [ ] Verdict path uses **no** LLM/network call (`ai_analyzer=None`); confirm by reading the call path, not just the config.
- [ ] `benign.jsonl` false-positive count = **0**. Coverage: ≥8 attacks per ReasonCode, all eleven classes present, demo payload included.
- [ ] Corpus entries have valid JSON escaping for unicode/control-char payloads.

**Style/hygiene**
- [ ] Copied files changed only in import paths; no gratuitous rewrites. No dead code, no stubs, no Claude/Anthropic attribution.

## Gate B — API + MCP + payment seam
**Contract**
- [ ] `/scan` returns exactly `ScanResponse`; `/health` shape correct; `/audit` returns `AuditResponse`.
- [ ] MCP tool schemas match §8.1 byte-for-byte (field names, enum values). MCP and HTTP call the **same** engine (no divergent second implementation).
- [ ] Claude drives the demo: POST the payment-redirect payload with `expected_addresses` → **BLOCK + DRAIN_ADDRESS**; the same payload without the firewall is shown being acted on.

**Security (security-reviewer subagent)**
- [ ] `audit_agent.target_url` — **SSRF guard**: reject non-http(s), block internal/loopback/link-local/metadata IPs, cap redirects and response size, timeout. This tool makes outbound requests to a user-supplied URL — highest-risk surface in the build.
- [ ] Payload length bound enforced; scanner never 500s on adversarial input (huge unicode, nested JSON, gigantic base58 runs).
- [ ] No secrets in code/repo; CORS not wildcard-with-credentials; no injection in any shelled-out or logged path.
- [ ] Payment seam does **not** hardcode an unverified SDK import; reverse-proxy fallback documented in `PAYMENT.md`.

**Deploy safety**
- [ ] `deploy/` is strictly additive — new unit, new nginx block, new subdomain, unused port. Confirm it references nothing owned by a co-hosted live project. (Actual deploy is user-run; Claude reviews the files.)

## Gate C — listing (user-owned)
- [ ] Claude drafts the exact NL registration/listing prompts; verifies the endpoint is public+HTTPS+x402-guarded before the user submits for OKX review. Claude does not register or submit anything.

## Gate D — submission assets (user-owned submit)
- [ ] README architecture claims match the actual code (no overstatement — Claude cross-checks, as with prior submissions).
- [ ] ≤90s demo script maps to a flow that actually runs green. X thread facts verified. **User submits the form and posts; Claude never submits without explicit approval.**

---

## Standing rules for the audit
- Run the corpus test; never accept "tests pass" on trust.
- Prefer finding a real false-positive/false-negative over stylistic nits — detection credibility is the named project risk.
- Report findings with `file:line` and a concrete failing input, ranked by severity.
- A gate is not done until its box list is fully checked and `test_corpus.py` is green.
