# AI Usage Disclosure

This project was built with the assistance of AI coding tools, under continuous human direction and review.

## Where AI was used
- **Research and planning** — surveying the OKX.AI / x402 / A2MCP mechanics, threat classes, and prior art;
  drafting the fix plan and product roadmap.
- **Implementation** — generating and editing code across the detection engine, API, trust layer (APA),
  SDKs, and deployment scripts.
- **Security & limitations auditing** — multiple independent AI review passes over the codebase for
  vulnerabilities, detection-recall gaps, and honesty of claims; every finding was re-verified against the
  source before action.
- **Testing and documentation** — writing regression tests and docs.

## What remained human-controlled
- A human directed the work, made all product and scope decisions, and reviewed/approved every change.
- No AI action was autonomous where it mattered: **all payments, on-chain/marketplace writes, deployments,
  and any public submission or posting were human-approved.** Signing keys and secrets were never generated
  or exposed by AI.

## Integrity of the numbers
- Detection results, the published held-out benchmark (recall / false-positive rate), latency figures, and
  marketplace data (sales, ratings, agent counts) are **measured or read from real sources**, not AI-fabricated.
  Where a capability is limited (e.g. detection recall on novel attacks), the documentation states it honestly
  rather than overclaiming.
