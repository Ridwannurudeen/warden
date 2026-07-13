# Warden Phase 5 — Codex Build Brief (The Marketplace Security Index)

**Branch:** create `phase5-web-platform` off `master` (currently `beb2b34`, 57 tests green, ruff clean).

**Read `submission/PHASE5-VERIFICATION.md` before writing a line.** Every strategic claim in this
brief was verified live on 2026-07-13 against the OKX `onchainos` CLI v4.1.0, the live
`warden.gudman.xyz` endpoint, and the installed `okxweb3-app-x402` package source. Do not re-derive
or second-guess those findings; do verify any *code* fact you depend on.

---

## Why this phase exists (the one-paragraph thesis)

The website is currently a brochure: `site/app.js:67` calls exactly one endpoint (`GET /health`).
Every actual capability we have — an 11-class deterministic engine, a 92-attack corpus, HMAC-signed
badges, a live attack-battery auditor — is invisible and unusable from the web. Meanwhile we
verified that **all 374 agents on the OKX.AI marketplace are publicly enumerable, with their live
endpoints and descriptions**, and that **only the task flow (not raw x402) can ever earn us a
review** — reviews being an explicit Highest Revenue judging criterion. Phase 5 turns the website
into the security index *of the marketplace it sells into*: a page for every agent, a real
task-flow checkout, and a staked public challenge. That is the thing no competitor can replicate,
because it compounds on data and a deterministic engine that only we have.

## Standing constraints (same as Phases 2–4 — these are hard)

- Listing `#3808` is **live and re-approved** (`approvalDisplayStatus: 4`) with a **frozen x402
  contract**: `POST /scan` = 0.01 USDT, `POST /audit` = 15 USDT, both also answer `GET` with a 402
  challenge. **Do NOT change route paths, price fields, or the response envelope shapes**
  (`ScanRequest` / `ScanResponse` / `AuditResponse` in `warden/models.py`). Everything you add is
  **additive**: new routes, new fields, new files.
- **Do NOT deploy and do NOT touch the VPS.** Ops is user-owned. Do not run `agent update` or any
  on-chain write.
- Run `python -m pytest -q` and `ruff check .` before calling anything done. Baseline on `master`:
  **57 tests, ruff clean.** Do not regress either.
- Every item ends at a **▸Claude-audit gate**. Stop there and hand off.
- **No attribution, no co-author tags, anywhere.** Match existing code style exactly.

---

## Item 1 — Public scan API for the web (the foundation everything else needs)

The web UI cannot call `POST /scan` — it is x402-paywalled by design, and it must stay that way.
So add a separate, free, hardened demo route. This is the single most load-bearing item; build it
first.

**1a. New route `POST /api/demo/scan` in `warden/api.py`** (add near the existing `/scan` handler
at `warden/api.py:149`, following its exact shape).

- Reuses the **same engine instance** already constructed in `api.py` — do not build a second one.
  It calls `engine.scan(payload, depth=..., context=...)` exactly like `scan()` does at
  `warden/api.py:150-157`, and returns a `ScanResponse` via `ScanResponse.from_verdict`
  (`warden/models.py:54`).
- **Hard cap the payload** at a smaller limit than the paid route (paid route truncates via
  `ScanRequest.truncate_payload`, `warden/models.py:31`). Use a new request model
  `DemoScanRequest` with a tighter cap (suggest 4 000 chars) so the free route can't be used as a
  compute faucet.
- **Force `depth="fast"`.** Do not let the web caller select `depth="thorough"` (the TF-IDF layer
  is materially more expensive). Ignore/reject the field.
- It must be **free and outside the paywall.** Verify how: the paywall is registered only for the
  route keys `"POST /scan"`, `"GET /scan"`, `"POST /audit"`, `"GET /audit"` (see the `RouteConfig`
  registrations at `warden/api.py:82-110`). A new path is therefore automatically unpaywalled —
  **confirm this is true by testing with `OKX_API_KEY` set**, don't just assume it.

**1b. Dedicated, stricter rate limiting for the demo route.**
`warden/ratelimit.py` currently applies one global per-IP fixed window
(`WARDEN_RATE_LIMIT_PER_MIN`, default 60), keyed on `X-Real-IP` (Phase-3 fix — **do not regress
that keying**). Add a **separate, lower budget for `/api/demo/*`** (suggest
`WARDEN_DEMO_RATE_LIMIT_PER_MIN`, default 20) so demo abuse cannot exhaust the budget that protects
the paid endpoints. Reuse the existing window/eviction machinery — do not write a second limiter.

**1c. Example-payload endpoint `GET /api/demo/examples`.**
Serve a curated set of example payloads (one per `ReasonCode` where we have a good one) drawn from
`corpus/attacks.jsonl` plus a couple from `corpus/benign.jsonl`. The 11 codes are defined in
`warden/core/verdict.py:14-25`. Return `[{id, label, reason_code, payload}]`. This powers the
one-click chips in the playground and guarantees the demo can never be a blank box.

**Tests:** demo route returns a correct verdict for a known-BLOCK corpus attack and a known-ALLOW
benign string; oversized payload is rejected/truncated; `depth=thorough` is not honoured; demo rate
limit triggers independently of the paid limit; the demo route stays **free while `OKX_API_KEY` is
set** (this is the one that actually proves the paywall isn't leaking).

**▸Claude-audit gate 1.**

---

## Item 2 — The Marketplace Security Index (⭐ the centerpiece — this is what wins)

A generated security page for **every agent on OKX.AI**, built entirely from public data.

**2a. Marketplace ingest — `warden/marketplace/fetch.py` (new module).**

Enumerate all agents via the OKX CLI (verified working, 2026-07-13):

```
onchainos agent search --query "a" --page <N> --page-size 100
```

Verified behaviour — rely on it, but re-confirm before trusting: page size caps at 100, pages 1–8
return data, **page 9 returns 0 → the set is exhausted at 374 unique agents**. Deduplicate by
`agentId`.

Each record gives you (all verified present): `agentId`, `name`, `profileDescription`,
`categoryCode`, `soldCount`, `feedbackRate`, `securityRate`, `onlineStatus`, `profilePicture`,
`communicationAddress`, and `services[]` — each with `endpoint`, `feeAmount`, `feeToken`,
`serviceDescription`, `serviceType`, `serviceId`.

Persist to a versioned snapshot (JSONL, in the style of `warden/badge_store.py`) with a fetch
timestamp. **This is a snapshot, not a live call per page-view** — the site must never shell out to
the CLI on a request.

**2b. Index the snapshot through our own engine — `warden/marketplace/index.py` (new module).**

For each agent, run its **public text** — `profileDescription` and each service's
`serviceDescription` — through the existing engine (`WardenEngine.scan`, `warden/engine.py:27`).
Record per agent: the verdict, any threat classes hit, and a short rationale.

**Be honest about what this measures.** It scans *public listing text*, not the agent's endpoint
behaviour. A clean result means "this agent's public description contains no injection patterns" —
it does **not** mean the agent is secure. The generated pages must say exactly that, in plain
language, unmissably. Overclaiming here would be a self-inflicted credibility wound for a security
product; it is the one mistake we cannot make.

**2c. Static page generation — `warden/marketplace/render.py` + `site/agents/`.**

Generate `site/agents/{agentId}.html` for every agent, plus an index at `site/agents/index.html`.
Each agent page shows:
- Identity (name, avatar via `profilePicture`, category, agent ID, link to its OKX listing)
- Public marketplace stats (`soldCount`, `feedbackRate`, and `securityRate` — **label the last one
  honestly as "buyer review average", because that is what we proved it is; do NOT present it as a
  security score**)
- **Warden's public-text scan result** (verdict + threat classes + the honesty caveat from 2b)
- **Audit status: "Not yet audited"** for everyone (nobody has a badge yet), with a CTA to get one
- If/when they hold a Warden badge, show it, signature-verified, linking to `/badge/{id}`

The index page ranks/filters agents (by category, by sold count, by whether their public text
tripped anything) and states the headline: *N agents indexed, M with injection-pattern matches in
public text, 0 independently audited.*

**Generation is a build step, not a request-time path.** A script (`scripts/build_index.py` or a
Makefile-style entry — match whatever the repo already does) regenerates `site/agents/`. Commit the
generator; **do not commit 374 generated HTML files** unless they are small and clean — decide, and
say which you chose in the handoff.

**2d. The distribution hook.** The whole point: this becomes one X post — *"We scanned every agent
on OKX.AI. Find yours."* — where all 374 operators have a personalised page waiting. Draft the post
copy into `submission/x-thread.md` (append; don't rewrite what's there). Do **not** post it.

**⚠ Framing constraint (non-negotiable):** aggregate stats and per-agent pages are fine; a
public "wall of shame" is not. Never assert an agent *is* insecure or vulnerable. Report only what
we actually measured, with the caveat. If an agent's public text trips a rule, phrase it as
"public listing text contains patterns Warden classifies as X" — a fact, not an accusation.

**Tests:** fetch module parses a captured fixture of real CLI output (commit a small fixture; do not
hit the network in tests); index module produces expected verdicts for a fixture agent; renderer
produces valid HTML for an agent with and without a badge, and for an agent with zero services.

**▸Claude-audit gate 2.**

---

## Item 3 — The task-flow checkout (⭐ the ONLY path that earns reviews)

**Read Q4 in `submission/PHASE5-VERIFICATION.md` first.** Recap of the proven constraint: a raw
x402 call to `/scan` increments `soldCount` but creates **no task**, and `agent feedback-submit`
**requires a `--task-id`** — so a direct-pay buyer **can never leave a review**. Reviews are an
explicit Highest Revenue judging criterion. Therefore the website's checkout must walk a buyer
through the **task flow**.

**3a. `site/hire.html` + `site/hire.js` — "Hire Warden" flow.**

The buyer here is an **agent operator** (they have a User-role agent identity and USDT0 on X Layer
— cold humans have neither; this is the correct and verified target audience). Build a clear,
guided, copy-pasteable walkthrough of the verified sequence:

1. `agent create-task --description "…" --budget … --max-budget … --currency …` → **jobId**
2. `agent set-asp` → provider `3808` + service (`18954` scan / `18955` audit)
3. `agent set-payment-mode`
4. `agent task-402-pay <JOB_ID> --provider-agent-id 3808 --accepts <accepts from our 402> --endpoint https://warden.gudman.xyz/scan --token-symbol … --token-amount …`
5. `agent complete <JOB_ID>`
6. `agent feedback-submit --agent-id 3808 --creator-id <their agent id> --score … --task-id <JOB_ID>`

Make every command a one-click copy button with **their** values pre-filled where the page can know
them. Show the live `accepts` array (fetch it from our own `GET /scan` 402 — that is a free,
unauthenticated request). Show what each step does and what it costs. The last step is the review —
ask for it plainly and honestly, and only after they have actually received a verdict.

**3b. Browser-wallet direct pay (optional, second-class — build only after 3a works).**

We verified a browser *can* pay directly: the 402 challenge carries a complete EIP-712 spec
(domain `name="USDT"`, `version="1"`, `chainId=196`, `verifyingContract=0x779ded…3736`; struct
`TransferWithAuthorization(from,to,value,validAfter,validBefore,nonce)` —
`x402/mechanisms/evm/types.py:229-248`), the header is
`PAYMENT-SIGNATURE: base64(PaymentPayload JSON)` (`x402/http/utils.py:28`,
`x402/schemas/payments.py:72`), and EIP-3009 is **gasless for the payer**. So
`eth_signTypedData_v4` + replay works from MetaMask.

**But it produces NO task and therefore NO review** — so it is strictly worse than 3a for our
goals. Build it only as a "pay a single call right now" convenience, and *route users toward 3a*.
Requires USDT0 on X Layer. If it costs you meaningful time, **skip it and say so.**

**⚠ HONESTY LINE (hard):** we do **not** self-pay to inflate `soldCount`, and agent `#4844`
(our own User-role identity) **must never** review `#3808`. Payer==payTo is visible on-chain.
Do not build any flow that makes self-dealing easy or automatic.

**Tests:** the page renders the correct pre-filled commands for both services; the `accepts` array
is fetched and rendered from a fixture; no secret/private key is ever handled by our code (3b signs
in the user's wallet only).

**▸Claude-audit gate 3.**

---

## Item 4 — The Gauntlet (⭐ the spectacle; corpus flywheel)

A public adversarial arena: **try to get an attack past Warden.**

**4a. `site/gauntlet.html` + `POST /api/demo/gauntlet` (reuses Item 1's engine path + rate limits).**
User submits a payload and declares intent (e.g. "drain funds", "hijack a tool call", "exfiltrate a
secret"). We return the real verdict. If the engine returns **ALLOW** on a payload that genuinely
carries that declared attack intent, that is a **candidate bypass**.

**4b. Bypass claims are queued, not auto-crowned.**
Persist candidate bypasses (JSONL, `badge_store.py` style) for **human review** — an ALLOW verdict
alone is not a bypass (someone can trivially submit benign text and declare "drain"). Confirmed
bypasses become corpus entries with credit to the finder. Show a live counter: attempts, confirmed
bypasses, current corpus size (`GET /health` already reports `corpus_size` — `warden/api.py:191`).

**4c. Staking the pot — DESIGN ONLY, DO NOT IMPLEMENT.**
The intended endgame is a real funded honeypot agent ("drain it and keep the money"). That needs an
LLM budget, a funded wallet, and careful prompt design, and it introduces a **new attack surface we
do not currently defend** (a novel jailbreak defeats the *model*, not the firewall — which is
honest and is exactly the flywheel, but the pot must be sized as marketing spend we can afford to
lose). **Write the design into `ROADMAP.md`; build nothing on-chain.** Flag it to the user as a
funding decision.

**Tests:** gauntlet route honours the demo rate limits; a corpus attack is correctly BLOCKED; a
claim on an ALLOW verdict is persisted as *pending*, never as *confirmed*.

**▸Claude-audit gate 4.**

---

## Item 5 — Site restructure + supporting surfaces

`site/index.html` is currently a **single page with JS tab-panels** (`site/index.html:24-30`,
panels at `:36`, `:126`, `:172`, `:199`). Per the user's standing multi-page standard, promote this
to real pages with a shared nav and a landing page:

- `/` landing (hero, the drain-BLOCK demo, headline index stat, CTAs)
- `/playground` (Item 1)
- `/agents` + `/agents/{id}` (Item 2)
- `/gauntlet` (Item 4)
- `/hire` (Item 3)
- `/badges` — browsable registry of issued badges, each signature-verified live via
  `GET /badge/{id}` (`warden/api.py:167`); `site/badge.html` + `site/badge.js` already do
  single-badge lookup — extend, don't duplicate
- `/docs` — one page per `ReasonCode` (11, `warden/core/verdict.py:14-25`): a real example attack,
  why it matters in agent commerce, Warden's verdict
- `/integrate` — copy-paste snippets: OnchainOS/Claude Code prompt, raw x402 curl, Python, TS, the
  MCP config (`warden/mcp_server.py` exists — check what it actually exposes before documenting it)
- `/status` — uptime, corpus version, test count, listing status, link to the on-chain payment proof

Keep the existing brand (shield mark, current palette in `site/styles.css`). Light **and** dark.
Mobile-clean. **Self-contained — no external resource requests** (this was an explicit Phase-1
audit requirement and the CSP/no-CDN property must hold; verify nothing you add fetches a font,
script, or image from another host).

**▸Claude-audit gate 5.**

---

## Explicitly OUT of scope

- Any change to `/scan`, `/audit`, their prices, paths, or response envelopes (**frozen contract**).
- Layer-4 LLM (`ai_analyzer=None` stub, `warden/engine.py:19`) — still no LLM budget; leave it.
- `WARDEN_REQUIRE_CONSENT` default (stays `false`) and `WARDEN_BADGE_SECRET` (already a real
  64-char secret on the VPS — do not regenerate or touch the signing logic).
- Any VPS deploy, any `agent update` / on-chain write, any posting to X. All user-owned.
- The funded honeypot pot (design only — Item 4c).

## Definition of done

`python -m pytest -q` green (≥57, plus your new tests), `ruff check .` clean, nothing in the frozen
contract altered, no external resource requests from the site, and a handoff note stating: what you
built, what you verified vs. assumed, what you skipped and why, and any finding that contradicts
this brief. **If something in this brief turns out to be wrong when you hit the code, stop and say
so — do not paper over it.**
