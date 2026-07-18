> **SUPERSEDED — ARCHIVE ONLY.** Do not use this kickoff for current work. Its
> linked pricing and signing-domain assumptions are obsolete; use `PAYMENT.md`
> and the current repository contracts instead.

You have full read/write access to this repository. Build Phase 5 end-to-end, autonomously, in one
continuous run. Do not stop to check in after each item — only stop when the entire scope is done,
or if you hit a genuine hard blocker that makes the brief's premise wrong (in which case: say so in
writing, keep building everything else you can, and flag the blocker clearly in your final handoff).

## Read first, in this order

1. `submission/PHASE5-VERIFICATION.md` — every strategic claim below was verified live against real
   systems (the OKX `onchainos` CLI, the live `warden.gudman.xyz` endpoint, the installed x402
   package source) on 2026-07-13. Trust these findings; don't re-derive them.
2. `CODEX-BUILD-PHASE5.md` — the full build brief. Five items, in order. Item 1 is the foundation
   the rest depend on — build it first. Items 2–5 can follow in the brief's order.

## What "full access" means here

You can read, write, create, and delete files anywhere in this repo; run the test suite and linter;
create commits on your working branch; install/use any Python package already reachable in this
environment. That's the access grant.

It does **not** mean the safety constraints in the brief are relaxed. These stay hard, no exceptions:
- Never change `/scan` or `/audit`'s route paths, prices, or response envelope shapes — that
  contract is live and frozen on a real OKX.AI marketplace listing.
- Never deploy to the VPS, never run `agent update` or any on-chain write, never post to X. All of
  that is user-owned and happens after your work is reviewed.
- Never add attribution, co-author tags, or any Claude/Codex/AI-generated marker to code, commits,
  or docs.
- Never self-deal on revenue/review metrics (no self-pay to inflate `soldCount`, no self-review).

Those aren't gates slowing you down — they're the difference between a real submission and a voided
one. Build fast inside them, not around them.

## How to work

- Branch: create `phase5-web-platform` off `master` (`beb2b34`, 74 tests green, ruff clean — verify
  this yourself before starting).
- Build Item 1, run its tests, `ruff check .`, commit. Move straight to Item 2. Repeat through
  Item 5. Don't pause for approval between items — the checkpoints in the brief are for a review
  pass that happens after you're done, not permission gates mid-build.
- If you discover a brief claim is wrong when you hit the actual code (a line number moved, a
  behavior differs from what's documented), fix your understanding, keep building, and note the
  discrepancy in your handoff — don't silently paper over it, and don't stall on it either.
- Keep commits scoped and readable, matching the existing repo's commit style (see `git log`).
- When genuinely done — all five items built, tests green, ruff clean, nothing in the frozen
  contract touched — write a single handoff note covering: what you built, what you verified vs.
  assumed, what you deliberately skipped (Item 3b browser-pay and Item 4c the staked pot are
  explicitly optional/design-only in the brief — say what you did with each), and any finding that
  contradicts the brief. Then stop.

Go.
