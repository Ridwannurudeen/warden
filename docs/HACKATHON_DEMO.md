# Warden hackathon demo

Target length: 75 seconds. The final cut must be 90 seconds or shorter. Record at 1920x1080 or
1440x900 with the browser at 100% zoom.

## What is live

`/theater` makes three sequential `POST /api/demo/theater` requests through the real Warden verdict
gate. The additive route then calls a Warden-owned, no-side-effect demo ASP handler only when the
verdict permits delivery: BLOCK does not invoke it, SANITIZE delivers only `sanitized_payload`, and
ALLOW delivers the original payload. Each response includes the handler receipt. The neutralized
counter advances only when the verdict, reason code, and receipt all match the named attack. Request
errors and unexpected or malformed receipts stop autoplay and remain visible. No wallet, payment,
marketplace task, or third-party agent is invoked.

Autoplay starts after 900 ms and runs one pass. It is disabled when the browser reports
`prefers-reduced-motion: reduce`; in that case, use **Run next attack** for each request and describe
the run as manual.

## Cold-start preparation

1. Verify `/health` in a separate clean tab, then close it.
2. Close wallets, terminals, password managers, notifications, private tabs, and unrelated apps.
3. Open a blank tab. Start recording before navigating to `/theater` so the first live request is
   captured.
4. Confirm the viewport shows the stage, counter, compute readout, and top of the live feed without
   horizontal clipping.
5. Do not claim an attack was neutralized until its accepted response appears in the feed and the
   counter advances.

## 75-second script

| Time        | Exact action                                                | Narration                                                                                                                                                                                                 | Evidence to keep visible                                                                                                     |
| ----------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 00:00-00:08 | Navigate to `/theater`; let autoplay start.                 | "Warden is the immune system of the agent economy: a runtime boundary before an autonomous agent acts."                                                                                                   | The Warden-owned demo-agent boundary and live API disclosure are visible.                                                    |
| 00:08-00:24 | Do not click. Let the three requests complete.              | "A prompt injection, recipient swap, and secret-exfiltration instruction are entering the real free Warden gate now."                                                                                     | Each accepted `/api/demo/theater` response appears in the feed; the counter reaches 3/3 only on a valid verdict and receipt. |
| 00:24-00:38 | Point to the feed, verdicts, receipts, and compute readout. | "The gate sanitizes the first attack before the demo handler, blocks the other two without invoking it, and returns a receipt for the downstream state."                                                  | Three feed rows show verdicts, threat classes, demo ASP delivery state, and the latest compute value.                        |
| 00:38-00:50 | Point to the stopped action boundary and status line.       | "A surprising verdict, malformed receipt, or request error stops the pass instead of being counted. The handler has no side effects and no third party is invoked."                                       | The completed state or an honestly stopped error state remains on screen.                                                    |
| 00:50-01:03 | Scroll to **From demo to open proof**.                      | "APA turns live guard state into an open Ed25519-signed attestation with a rolling 24-hour screened-payload count or an explicit unavailable state. It does not claim every request traversed the guard." | The APA scope statement is readable.                                                                                         |
| 01:03-01:15 | Point to **Integrate APA** and stop without clicking.       | "Local enforcement, portable verification, and a public transparency log make this infrastructure other agent services can adopt."                                                                        | The integration and documentation actions are visible.                                                                       |

If the live pass stops, keep the stopped state visible and record again only after diagnosing the
actual error. Never splice a generated verdict into the feed or narrate an unaccepted response as live.

## Capture checklist

- Resolution is at least 1280x720; 1920x1080 is preferred.
- Browser zoom is 100%; no horizontal clipping appears.
- The presenter uses a real voice; no text-to-speech.
- Cursor movement is deliberate and does not hide the live feed.
- Notifications, password managers, wallets, terminals, and private tabs are closed.
- The counter reaches 3/3 only after three accepted live verdict-and-receipt responses.
- Audio distinguishes deterministic verdict compute from hosted network round-trip time.
- Audio states the APA proof boundary and does not upgrade `guard-live` to "secure" or "protected."
- No official OKX endorsement, perfect-detection, certification, uptime, customer, traction, or
  per-request-routing claim appears.
- The final cut is 90 seconds or shorter and includes `#OKXAI` only if the user later approves posting.
- Review every frame for payloads, addresses, credentials, payment signatures, browser extensions,
  and unrelated personal information before any external upload.
