# `/hire` catalogue unblock — staged plan

**Date:** 2026-07-25
**Status:** staged. Path A is preferred and needs no code. Path B is the fallback and is fully
specified so it can be executed without re-deriving anything.

## The problem, verified

`site/hire.js:82-99` derives the expected atomic amount from the catalogue's `feeAmount` and requires
the live `accepts` entry to match it **exactly**; no match throws before any command is generated. So
the catalogue and the endpoint must agree or `/hire` cannot build payment commands.

They do not agree:

| Surface | Fee | Services |
| --- | --- | --- |
| `warden/payment.py` and the live 402 | `0.1` (`100000`) | 4 paid routes |
| OKX listing (verified 2026-07-25) | `0.1` | 5 services |
| `site/data/warden-services.json` (repo **and** live) | `0.5` | 2 (`scan`, `audit`) |
| `data/marketplace/agents-v1.jsonl` | `0.5` | 2 |

The catalogue is generated, not hand-maintained: `scripts/build_index.py:213` writes it from the
snapshot via `build_hire_catalog`. So the fix has to reach the snapshot or the builder, never the
generated file — a hand-edit is reverted by the next index build and is therefore forbidden.

## Why a refresh cannot simply be run today

`fetch_snapshot` (`warden/marketplace/fetch.py:257`) is a **marketplace-wide census**. It paginates
`onchainos agent search` over every agent and records `sampled` / `expected` / `dropped` as an honest
sampling record of the *public* marketplace. Agent #3808 is `approvalStatus: 2` / `status: 2` — under
review, not listed — and is therefore **absent from `agent search`** (verified: a search for "Warden"
returns 10 results, none of them 3808). A truthful census run today correctly omits Warden, and
`build_hire_catalog` then raises
`RuntimeError("Agent #3808 is missing from the marketplace snapshot")` (`warden/marketplace/catalog.py:25`).

**Editing Warden's entry into the snapshot by hand is not an option.** The snapshot's own metadata
claims it is a census captured at a timestamp; injecting a row that the census did not observe
falsifies that record. Rejected on evidence-honesty grounds, not convenience.

## Path A — the review clears (preferred, no code change)

Trigger: `onchainos agent get-agents --agent-ids 3808` shows the listing live again, and a search
returns 3808.

1. Refresh the census and regenerate the catalogue:
   `python scripts/build_index.py` (it calls `fetch_snapshot` then writes
   `site/data/warden-services.json`).
2. Confirm the regenerated catalogue reads `0.1` for every service and that `serviceId` values still
   match the live listing.
3. Update the pinned fee assertion in `tests/test_hire_catalog.py` — it currently asserts
   `["0.5", "0.5"]` against the 2026-07-18 snapshot, and that assertion is *correct* until the
   snapshot actually changes. Update it in the same commit that refreshes the snapshot, never before.
4. Run the full gate, then redeploy the site index so `/opt/warden-site/data/warden-services.json`
   carries the new file.
5. Verify `/hire` builds a payment command end to end.

Cost: minutes. Nothing else moves.

## Path B — the review has not cleared by T-24h (fallback, code change)

Trigger: 2026-07-26 ~23:00 UTC with #3808 still unlisted, i.e. roughly 24h before the enforced
deadline of **2026-07-27 22:59 UTC**. At that point a broken `/hire` during judging outweighs the risk
of the change.

**The insight that makes this work:** `agent service-list --agent-id 3808` returns Warden's own
services **while the agent is unlisted** — verified 2026-07-25, all four A2MCP services at `0.1`. Note
that `agent get-agents` does **not**: its `serviceList` comes back empty (`[]`) during review, so it is
not a usable source. Warden's own catalogue should be sourced from Warden's own listing, not from a
public census; the current coupling means `/hire` breaks every time the listing is edited at all.

Field mapping, confirmed against both surfaces:

| Catalogue field | `service-list` source | Verified value |
| --- | --- | --- |
| `serviceId` | row `id` (numeric — `MarketplaceService.service_id` requires a decimal) | `33460`, `33461`, `36873`, `36941` |
| `feeAmount` | row `fee` | `0.1` |
| `feeTokenAddress` | row `contractAddress` | `0x779ded0c9e1022225f8e0630b35a9b54be713736` |
| `endpoint`, `serviceName`, `serviceDescription`, `serviceType` | same-named row fields | match the live listing |

Do **not** map the row's `serviceId` UUID — it fails the decimal validator.

Steps:

1. Add a provider-scoped adapter method beside `OnchainOSCLIAdapter.search_page`
   (`warden/marketplace/fetch.py:238`) that shells `agent service-list --agent-id <id>` and parses the
   `data[0].list` rows into `MarketplaceService`, plus `data[0].agentInfo` into a `MarketplaceAgent`.
   Reuse the existing models; they already ignore extra keys.
2. Give `build_hire_catalog` an alternate entry point that accepts that `MarketplaceAgent` directly,
   leaving the snapshot path intact for the census-driven callers. Keep the existing invariants — one
   service per endpoint, `A2MCP` only, fee token required.
3. Have `scripts/build_index.py` prefer the provider-scoped source for the hire catalogue and keep the
   census for `marketplace-summary.json`, which is genuinely about the wider marketplace.
4. Set `snapshotFetchedAt` from the provider fetch time so the file does not claim census provenance
   it no longer has.
5. Tests: keep `test_hire_catalog_is_derived_from_marketplace_snapshot` for the census path and add one
   for the provider path with a stubbed runner. Do not weaken the existing assertions.
6. Full gate, then redeploy the site index.

## Decision

Prefer Path A. It is mechanical, carries no change risk, and the review clearing is required for the
hackathon submission to be valid anyway — so if Path A never becomes available, `/hire` is not the
binding problem. Path B exists so a stale `/hire` cannot be the thing a judge sees, and its real value
outlives the deadline: sourcing our own catalogue from our own listing removes a recurring breakage
every time the listing is edited.
