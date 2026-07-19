# Warden product demo

Target length: 75 seconds. The final cut must be 90 seconds or shorter. Record at 1920x1080 or
1440x900 with the browser at 100% zoom.

## What is live

`/theater` starts idle. Loading the page sends no request. The visitor must select **Run test
sequence** before the first `POST /api/demo/theater` request is made. After that explicit action,
the page advances through the three controlled cases unless the visitor pauses or the browser
reports `prefers-reduced-motion: reduce`; reduced-motion users run each remaining case with **Next
case**. There is no autoplay on page load.

Each request passes through the real Warden verdict gate. The additive route calls a Warden-owned,
no-side-effect demo handler only when the verdict permits delivery: BLOCK does not invoke it,
SANITIZE delivers only `sanitized_payload`, and ALLOW delivers the original payload. Each response
includes the handler receipt. The completed counter advances only when the verdict, reason code,
and receipt all match the named case. Request errors and unexpected or malformed receipts stop the
sequence and remain visible. No wallet, payment, marketplace task, or third-party agent is invoked.

The product message is **verifiable pre-action security for AI agents**: Warden sits before a
consequential action, returns ALLOW, SANITIZE, or BLOCK, withholds or transforms unsafe output, and
leaves evidence that can be inspected.

## Cold-start preparation

1. Verify `/health` in a separate clean tab, then close it.
2. Close wallets, terminals, password managers, notifications, private tabs, and unrelated apps.
3. Open a blank tab. Start recording before navigating to `/theater`, then keep the idle state
   visible long enough to show that no request is sent before explicit activation.
4. Confirm the viewport shows the stage, counter, compute readout, and top of the live feed without
   horizontal clipping.
5. Do not claim an attack was neutralized until its accepted response appears in the feed and the
   counter advances.

## 75-second script

| Time        | Exact action                                                   | Narration                                                                                                                                                                                                 | Evidence to keep visible                                                                                                     |
| ----------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 00:00-00:08 | Navigate to `/theater`; do not activate the sequence yet.     | "Warden provides verifiable pre-action security for AI agents. It sits between untrusted output and a consequential action."                                                                              | The idle status says no request has been sent; the controlled demo boundary is visible.                                     |
| 00:08-00:12 | Select **Run test sequence** once.                             | "Nothing runs on page load. I am explicitly starting three controlled requests against Warden's own no-side-effect handler."                                                                              | The button action and first request-in-progress state are visible.                                                           |
| 00:12-00:28 | Let the explicitly activated sequence complete.               | "A prompt injection, recipient swap, and secret-exfiltration instruction are passing through the real Warden gate."                                                                                       | Each accepted `/api/demo/theater` response appears in the record; the counter reaches 3/3 only on a valid verdict and receipt. |
| 00:28-00:42 | Point to the record, verdicts, receipts, and compute readout. | "Warden transforms the first payload before delivery and blocks the other two before execution. The receipt records exactly what the demo handler received."                                             | Three rows show verdicts, reason codes, handler delivery state, source time, and compute value.                              |
| 00:42-00:53 | Point to the action boundary and status line.                 | "An unexpected verdict, malformed receipt, or request error stops the sequence instead of being counted. No wallet, payment, task, or third party is invoked."                                           | The completed state or an honestly stopped error state remains on screen.                                                    |
| 00:53-01:05 | Scroll to **Signed guard record**.                             | "APA binds an endpoint host, signing key, and observed guard claim in an Ed25519-signed record. It does not claim that every request traversed the guard."                                                | The APA scope statement is readable.                                                                                         |
| 01:05-01:15 | Point to **Integrate in 5 minutes** and stop without clicking. | "The caller keeps final authority. Warden gates the action and leaves portable evidence for independent inspection."                                                                                      | The integration and decision-contract actions are visible.                                                                  |

If the live pass stops, keep the stopped state visible and record again only after diagnosing the
actual error. Never splice a generated verdict into the feed or narrate an unaccepted response as live.

## Capture checklist

- Resolution is at least 1280x720; 1920x1080 is preferred.
- Browser zoom is 100%; no horizontal clipping appears.
- The presenter uses a real voice; no text-to-speech.
- Cursor movement is deliberate and does not hide the live feed.
- Notifications, password managers, wallets, terminals, and private tabs are closed.
- The recording visibly shows the idle state before the single explicit **Run test sequence**
  activation.
- The counter reaches 3/3 only after three accepted live verdict-and-receipt responses.
- Audio distinguishes deterministic verdict compute from hosted network round-trip time.
- Audio states the APA proof boundary and does not upgrade `guard-live` to "secure" or "protected."
- No official OKX endorsement, perfect-detection, certification, uptime, customer, traction, or
  per-request-routing claim appears.
- The final cut is 90 seconds or shorter. Recording, uploading, posting, and submission remain
  user-owned and require explicit approval.
- Review every frame for payloads, addresses, credentials, payment signatures, browser extensions,
  and unrelated personal information before any external upload.
