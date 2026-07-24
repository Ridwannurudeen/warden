# Warden Hardening Loop — Google Form Draft

Status: staged only. Do not open an authenticated form session, paste, upload, or submit without
explicit user approval. Replace every bracketed placeholder and verify every URL first.

**Project name:** Warden

**Agent/listing:** Warden #3808 — `[VERIFIED_CURRENT_LISTING_STATUS]`

**One-line description:** Warden audits agent endpoints, builds signed training-derived Hardening
Packs for the missed classes, and proves improvement through a signed re-audit.

**Product URL:** https://warden.gudman.xyz

**Listing URL:** [VERIFIED_LISTING_3808_URL]

**Demo video:** [FINAL_APPROVED_VIDEO_URL]

**#OKXAI post:** [FINAL_APPROVED_POST_URL]

**Repository/spec:** [FINAL_APPROVED_REPOSITORY_URL]

**What problem does it solve?**

Autonomous agents consume untrusted messages, tool output, links, and transaction instructions
before taking consequential actions. A scan can identify one dangerous payload, but builders also
need a repeatable way to diagnose endpoint-level gaps, apply targeted controls, and measure whether
those controls improved the endpoint.

**What did you build?**

Warden implements the complete audit → harden → re-audit loop. A consented endpoint audit runs a
fixed attack battery and produces signed technical evidence. Given that completed audit ID,
`/harden` returns a deterministic Ed25519-signed Hardening Pack covering exactly the classes the
endpoint missed. Packs contain training-corpus examples only, detector families, integration
guidance, provenance, expiry, and a reference to the source audit. Builders apply fail-closed local
SDK enforcement or the Warden gateway, then use the existing audit route again. The initial audit,
pack, and re-audit are separate signed records in the transparency log.

The post-hackathon training suite adds `warden-selftest` for local practice, deterministic
adversarial variant evaluation packs, public audit-evidence lineage, continuous Shield hardening,
and a human-reviewed Gauntlet-to-training promotion path. The infrastructure tier adds hardened
gateway deployment manifests, bounded payload-free metrics, and an offline labeled-data calibration
harness. Hosted gateway service and new payment transports remain operator-gated rather than being
claimed as live.

**How does the demo work?**

The ≤90-second run uses a loopback-only consented endpoint and the real fixed 20-probe audit battery.
The weak endpoint receives signed grade F evidence. Warden builds and verifies its signed Hardening
Pack. The endpoint then enables real fail-closed local enforcement plus its deny-by-default command
policy. The same battery re-runs and produces a strictly improved grade A. Finally, the demo verifies
the two signed audits, signed pack, three ordered transparency events, and signed checkpoint. No
wallet, payment, public endpoint, prerecorded verdict, or mocked grade change is used.

**Technical stack:**

- FastAPI paid `/scan`, `/audit`, and `/harden` services on the pinned x402 exact rail.
- Deterministic Python verdict engine and fixed consented endpoint-audit battery.
- Canonical JSON and Ed25519-signed audit, Hardening Pack, and transparency evidence.
- Python SDK local fail-closed enforcement, `warden-selftest`, and `warden-gateway`.
- TypeScript hosted client plus browser-side independent evidence verification.
- SQLite atomic evidence stores and hash-chained transparency log.
- Local EVM tests for ERC-8004 feedback and the Solidity transparency anchor.

**What is novel?**

Warden connects diagnosis to treatment and then measures the result. The pack is not generic advice:
it is derived from the exact signed audit's missed classes, carries training-source lineage, and is
cryptographically linked to that audit. The product therefore exposes a verifiable F → treatment → A
trajectory while keeping held-out evaluation cases private.

**Business model:**

`/scan`, `/audit`, and `/harden` are each pay-per-call services on the existing pinned 0.5 USDT
rail. The self-test and local SDK provide a free practice path before a graded paid audit. Local
gateway operation is source-ready. Hosted gateway availability, subscription packaging, and any
pricing changes are not live claims and require separate operator approval.

**Evidence and limitations:**

The demo proves improvement against one fixed battery at two recorded times. Signed evidence
supports independent integrity checks; it does not certify an endpoint, guarantee future safety,
prove every request traversed Warden, or replace the endpoint operator's own authorization policy.

**Team:** Ridwan (solo)

## Final submission gate

- [ ] Every placeholder is replaced with a verified final value.
- [ ] Listing #3808's current status is copied from a fresh read, not historical notes.
- [ ] The live production route and x402 terms match the submitted copy.
- [ ] The video and post URLs open in a signed-out browser.
- [ ] Metrics, counts, prices, and route claims match the exact tested release commit.
- [ ] The user approves the completed form answers and explicitly authorizes submission.
- [ ] Submit exactly once; capture the confirmation URL or receipt in the operator ledger.
