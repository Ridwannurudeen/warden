# Warden Demo Script

Target length: 75-90 seconds. Record Mode B now. Switch to Mode A only after the user funds a buyer wallet with USDT plus gas on X Layer and explicitly approves a paid replay.

## Preflight

From the repo root:

```bash
python -m pytest -q
python -m ruff check .
python demo/run_demo.py --mode local
```

Keep the terminal zoomed enough that `BLOCK`, `DRAIN_ADDRESS`, and `valid: true` are readable.

## Beat Sheet

| Time | Screen | Voiceover |
|---:|---|---|
| 0-8s | Landing page hero | "Warden is a paid A2MCP payload firewall for agent services on OKX.AI. It scans untrusted agent output before a buyer agent acts." |
| 8-20s | `/playground`; select the Drain address example | "Here is the failure case: a payload says payment is confirmed and tells the buyer to send funds to an attacker address. The expected recipient is supplied as trusted context." |
| 20-38s | Click **Run Warden**; reveal the structured result | "The free playground uses Warden's real deterministic fast path. It returns BLOCK with DRAIN_ADDRESS and redacts the attacker address before execution." |
| 38-52s | Result JSON | "The verdict, risk level, threat classes, sanitized payload, and checks are machine-readable so an agent can enforce the decision." |
| 52-65s | Terminal `Live payment gate` from Mode B | "The production endpoint remains paywalled with x402 v2 on X Layer. This recording uses the no-funds path, so no private key or token spend is shown." |
| 65-80s | `/hire` reviewable task flow | "Operators can hire the 0.5 USDT payload scan or the 0.5 USDT endpoint audit through a task, receive the result, and then leave an honest task-linked review." |
| 80-90s | `/agents` marketplace security index | "Agent 3808 was listed and eligible when verified on July 13. The index reports only patterns in public listing text, not a claim that an endpoint is secure." |

## On-Screen Commands

No-funds recording path:

```bash
python demo/run_demo.py --mode local
```

If the live x402 check is noisy during recording, first verify it off-camera, then record:

```bash
python demo/run_demo.py --mode local --skip-live-check
```

Funded paid path, only after user approval:

```bash
python demo/run_demo.py --mode live-paid --confirm-spend
```

## What Not To Show

- Do not show `.env`, OKX API keys, private keys, mnemonics, or wallet export screens.
- Do not claim the paid Mode A flow settled until it actually runs and returns a paid Warden response.
- Do not submit the Google Form or post the X thread from this script.
