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
| 8-18s | Demo tab or terminal payload | "Here is the failure case: a payload says payment is confirmed and tells the buyer to send funds to an attacker address." |
| 18-30s | Terminal `Naive agent path` | "A naive agent treats the message as instruction text and prepares the wrong transfer." |
| 30-50s | Terminal `Warden path` | "The same payload through Warden returns BLOCK with DRAIN_ADDRESS. The attacker address is redacted before execution." |
| 50-65s | Terminal `Live payment gate` | "The live endpoint is paywalled with x402 v2 on X Layer. The recording uses the no-funds path, so no private key or token spend is shown." |
| 65-80s | Pricing tab | "The product has two services: 0.01 USDT payload scans and 15 USDT endpoint audits for agents preparing for review." |
| 80-90s | Hero or footer | "Agent 3808 is registered and under review. The buyer-funded paid demo can be run once the wallet is funded." |

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
