# Phase 5 — Pre-scope verification (2026-07-13)

Three questions had to be answered before scoping the website build. All three were run against
live systems (OKX `onchainos` CLI v4.1.0, the live `warden.gudman.xyz` endpoint, and the installed
`okxweb3-app-x402` package source). Nothing below is assumed.

---

## Q1 — Can a human pay the x402 endpoint from a normal browser wallet (no OKX Agentic Wallet)?

**ANSWER: YES.** True arm's-length payment from a visitor's own wallet is buildable.

Evidence chain:

1. `onchainos payment pay-local --help` — signs x402 "locally with a hex private key
   (reads EVM_PRIVATE_KEY)", supports `exact + EIP-3009`. So the TEE Agentic Wallet is **not**
   required to produce a valid payment; any EVM key can.

2. The live 402 challenge (`GET https://warden.gudman.xyz/scan`) returns a `payment-required`
   header whose base64 decodes to a **complete EIP-712 domain + message spec**:

   ```json
   {"x402Version":2,
    "resource":{"url":"https://warden.gudman.xyz/scan","description":"Warden payload security scan"},
    "accepts":[{"scheme":"exact","network":"eip155:196",
                "asset":"0x779ded0c9e1022225f8e0630b35a9b54be713736",
                "amount":"10000","payTo":"0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51",
                "maxTimeoutSeconds":300,
                "extra":{"name":"USDT","version":"1"}}]}
   ```

3. The EIP-712 structs are confirmed in package source
   (`x402/mechanisms/evm/types.py:229-248`):
   - `EIP712Domain(name, version, chainId, verifyingContract)`
     → `name="USDT"`, `version="1"`, `chainId=196`, `verifyingContract=0x779ded…3736`
   - `TransferWithAuthorization(from, to, value, validAfter, validBefore, nonce)`

4. The header is assembled as base64 of the `PaymentPayload` JSON
   (`x402/http/utils.py:28` + `x402/schemas/payments.py:72`):
   `{x402Version: 2, payload: {…sig + authorization…}, accepted: {…}, resource: {…}}`
   sent in the `PAYMENT-SIGNATURE` header, then the original request is replayed.

**What this means:** a browser using `eth_signTypedData_v4` (MetaMask/any injected wallet) can
produce a valid payment with no CLI, no OKX account, and **no gas** (EIP-3009 is a gasless signed
authorization — the OKX facilitator broadcasts it).

**⚠ THE REAL FRICTION (do not gloss over this):** the payer must already hold **USDT0
(`0x779ded…3736`) on X Layer (chain 196)**. Almost no random human/judge has that. So the
"visitor pays from their own wallet" flow is *technically* live but has a near-zero conversion
rate on cold traffic. Any design that depends on it must solve funding, or pair it with a
sponsored path. This is the single biggest constraint on the website-as-checkout idea.

---

## Q2 — Can we enumerate every agent on the marketplace, with useful metadata?

**ANSWER: YES — and the data is richer than expected.**

- `onchainos agent search --query "a" --page N --page-size 100` paginates cleanly, and always
  terminates (an empty page reliably signals exhaustion).
- **⚠ RE-VERIFIED same day, ~2h later: the count and exhaustion page are NOT stable.** First sweep
  (morning): pages 1–8 had data, page 9 = 0, 374 unique IDs. Second sweep (afternoon, same method):
  pages 1–4 had data (100+100+100+73=373), page 5 = 0, and the unique-ID set had **shifted** —
  8 IDs from the morning sweep were gone, 1 new ID appeared (367 overlap). **This is a live
  marketplace with agents listing/delisting continuously — treat any specific count (374, 373,
  "exhausts at page N") as a snapshot valid only at fetch time, never a hardcoded constant.**
  The generator (Item 2 in the build brief) must paginate until it sees an empty page **at build
  time**, not assume a fixed page count.

Each record carries: `agentId`, `name`, `profileDescription`, `categoryCode`, `soldCount`,
`feedbackRate`, `securityRate`, `onlineStatus`, `profilePicture`, `communicationAddress`, and a
full `services[]` array — each service with `endpoint` (the live URL), `feeAmount`, `feeToken`,
`serviceDescription`, `serviceType` (A2MCP/A2A), `serviceId`.

**Notable:** OKX itself exposes a `securityRate` field per agent. Factor (#4502) shows `5.0`;
**Warden (#3808) shows `null`.** Worth understanding what populates it — it is literally a
security score on the platform, and we are the security ASP with a blank one.

**This means** a per-agent security page for every agent the sweep returns (368 in the shipped
snapshot; the live count drifts with listings) is fully buildable from public data,
including their public endpoints and descriptions.

---

## Q3 — Do payments through the endpoint attribute to #3808's public marketplace stats?

**ANSWER: YES — confirmed by direct observation.**

`onchainos agent get-agents --agent-ids 3808` now returns:
- `soldCount: 1` (it was 0 before the Jul-07 payment test)
- `approvalDisplayStatus: 4` → **Listed / eligible** (it had dropped to 2 "under review" after the
  Jul-09 listing update — it has since been re-approved; this was previously unconfirmed)
- `onlineStatus: 1`
- `securityRate: null`

**This means** every real paid `/scan` call made through the website increments the public
`soldCount` that judges see, and the website-as-checkout thesis is mechanically sound.

**⚠ HONESTY CONSTRAINT:** that `soldCount: 1` came from our own **self-pay** (payer wallet ==
payTo wallet). It proves the rail and proves attribution — it is **not** demand. We must not farm
`soldCount` with self-payments to inflate the judged metric; that is gaming, it is detectable
(payer == payTo on-chain), and it would poison the one thing Warden sells, which is trust.
Only genuine third-party payments count.

---

---

## Q4 (unplanned, found while chasing Q1–Q3) — what actually populates `securityRate`, and how do reviews work?

### `securityRate` is NOT a security score. It is the mean star rating from buyer reviews.

Proven arithmetically, not assumed. `onchainos agent feedback-list --agent-id 1445` returns
review distribution `{"3": 1, "4": 7, "5": 48}`:

```
(3×1 + 4×7 + 5×48) / 56  =  271 / 56  =  4.839…
```

and agent 1445's `securityRate` in the search index is **4.84**. Exact match.

Across the dated sweep of 374 agents: 254 are `null`, 80 are exactly `5.0`, and the rest are review-averages
(4.67, 4.71, 4.98 …). `securityRate` is non-null **only** for agents that have received reviews.

**So Warden's `securityRate: null` is not a platform judgement about our security — it just means
we have zero reviews.** The field is misleadingly named. Nothing to "earn" except reviews.

### ⚠⚠ THE CRITICAL FINDING: a raw x402 pay-per-call CANNOT be reviewed.

Observed directly on our own listing:
- `#3808` has `soldCount: 1` (our Jul-07 self-pay x402 call).
- `onchainos agent tasks` → **"Task list (0 total)"**.
- `onchainos agent feedback-list --agent-id 3808` → **`total: 0`, empty list.**

And `onchainos agent feedback-submit` **requires**:
```
--agent-id    (who is being reviewed)
--creator-id  (the REVIEWER's own agent id — reviewer must have an agent identity)
--score       (0.00–5.00)
--task-id     (REQUIRED: the related task id)
```

**A direct x402 call creates no task → there is no `task-id` → no review can ever be submitted
for it.** It increments `soldCount` (revenue/orders) and nothing else.

This matters enormously, because the Highest Revenue Award is judged on
**"revenue, orders, and positive reviews"**. Our current, only, sales path structurally cannot
produce the third one.

### The path that DOES produce reviews: the task flow (x402-compatible)

Verified from the CLI surface — `task-402-pay` takes a `<JOB_ID>`, so x402 A2MCP services *are*
payable inside a task:

1. Buyer (needs a **User-role agent identity**): `agent create-task --description … --budget … --currency …` → returns a **jobId**
2. `agent set-asp` → attach provider Warden `#3808` + service (18954 scan / 18955 audit)
3. `agent set-payment-mode`
4. `agent task-402-pay <JOB_ID> --provider-agent-id 3808 --accepts <accepts array from our 402> --endpoint https://warden.gudman.xyz/scan --token-symbol … --token-amount …`
   → signs x402, does direct/accept, replays the endpoint (real verdict returned)
5. `agent complete <JOB_ID>` → releases payment
6. `agent feedback-submit --agent-id 3808 --creator-id <buyer agent id> --score 5 --task-id <JOB_ID>` → **review lands, `securityRate` populates**

**Implication for the website:** the checkout must drive buyers through the **task flow**, not the
raw x402 call. Only the task flow yields all three judged criteria (revenue + orders + reviews).
The buyer needs an agent identity — which every marketplace operator already has,
and no cold human does. This *confirms* the retarget: the website's paying audience is agent
operators, not passers-by.

---

## Bearing on scope

- **The checkout must be task-flow based, not raw x402** (Q4) — otherwise we can never earn a
  single review, and reviews are an explicit judging criterion.
- `securityRate` is just the review average (Q4) — it populates itself once real reviews land.
  Nothing special to build for it.
- Website-as-checkout is **real**, but cold humans can't pay (no USDT0 on X Layer, no agent
  identity). The audience is **the marketplace agent operators** (Q1 + Q4).
- The all-agents security index is **real and unblocked** — best data asset we have (Q2).
- Marketplace attribution is **real** (Q3): paid calls do increment the public `soldCount`.
- **Honesty line:** never farm `soldCount` or reviews with self-payments/self-reviews. Payer==payTo
  is visible on-chain, and #4844 (our own User agent) must not review #3808.
