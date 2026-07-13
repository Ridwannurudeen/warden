# Warden hackathon demo

Target length: 82 seconds. Record at 1920×1080 or 1440×900 with the browser at 100% zoom.

## Cold-start preparation

1. Open `/showcase` in a private or clean browser tab.
2. Confirm the API status indicator is live and Scene 01 is selected.
3. Leave auto-advance off for the primary recording.
4. Confirm no wallet, terminal, private payload, account notification, or unrelated browser tab is
   visible.
5. Do not open a paid route or execute any generated command during the recording.

## 82-second script

| Time        | Exact action                                                  | Narration                                                                                                                                                                                | Expected state                                                                                    |
| ----------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 00:00–00:08 | Start on `/showcase`, Scene 01.                               | “Autonomous agents act on output from other services. This one quietly replaces a payment recipient.”                                                                                    | The poisoned `0x2222…2222` instruction is labeled as example input.                               |
| 00:08–00:17 | Click **Next scene**.                                         | “The operator already knows the legitimate recipient. Warden compares untrusted output with that trusted context before a wallet builds the transfer.”                                   | Scene 02 shows `0x1111…1111` against `0x2222…2222`.                                               |
| 00:17–00:28 | Click **Next scene**, then **Run the real free scan**.        | “This is the real deterministic fast path—not a replay, not an LLM, and not a paid call.”                                                                                                | Scene 03 shows a loading state, then advances only after a validated `/api/demo/scan` response.   |
| 00:28–00:42 | Pause on Scene 04.                                            | “Warden returns BLOCK, DRAIN_ADDRESS, CRITICAL risk, a sanitized payload, and the exact next action: stop and verify the recipient.”                                                     | The result source reads **Live demo result**; prevented action and detector boundary are visible. |
| 00:42–00:55 | Click **Next scene**.                                         | “Production users can place the same contract before a transfer through OKX tasks, raw x402, Python, TypeScript, or MCP. Signing stays in the operator’s CLI wallet.”                    | Scene 05 shows the three-step operator summary and no raw CLI requirement.                        |
| 00:55–01:10 | Click **Next scene**.                                         | “Warden complements listing-time review with runtime control. Marketplace signals, Gauntlet candidates, and signed audits each prove something different—and their limits stay visible.” | Scene 06 shows corpus, reason-code, and no-guarantee evidence.                                    |
| 01:10–01:22 | Point to **Put Warden before the next action**; do not click. | “One request turns untrusted output into an enforceable ALLOW, SANITIZE, or BLOCK decision before the agent acts.”                                                                       | Final CTA is visible. Stop recording.                                                             |

## Live-endpoint fallback

If the free demo request errors or times out, keep the failure visible for one second and click
**Use labeled example fallback**. Say: “The live endpoint is temporarily unavailable, so this is the
same committed drain-address example, explicitly labeled—not presented as a live result.” Continue
from Scene 04. Never edit the page, network response, or narration to imply the fallback was live.

## Capture checklist

- Resolution is at least 1280×720; 1920×1080 is preferred.
- Browser zoom is 100%; no horizontal clipping appears.
- Microphone uses the presenter’s real voice; no text-to-speech.
- Cursor is visible and moves only to the next required control.
- Notifications, password managers, wallets, terminals, and private tabs are closed.
- The result-source label says **Live demo result** before claiming the endpoint ran.
- Audio clearly distinguishes runtime control from listing-time review.
- No official OKX endorsement, perfect-detection, certification, uptime, customer, or traction claim
  appears in narration.
- Final cut is 90 seconds or shorter and includes `#OKXAI` only when the user later approves posting.
- Review the final capture frame by frame for payloads, addresses, credentials, and unrelated personal
  information before any external upload.
