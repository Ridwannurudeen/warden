# Frontend screenshot manifest

The two `warden-landing-*.png` files in this directory were captured on 2026-07-04 and predate the
Trust Layer interface. Preserve them as baseline evidence; do not present them as current screenshots.

**Current captures: 2026-07-28, commit `a81a0dd`, from production `warden.gudman.xyz`, device scale
factor 2.** All eleven routes below were captured against the live build, not a local preview. The
two state-bearing frames were asserted before the shutter rather than after: the Theater frames were
taken only once the page reported a receipt-validated `3 / 3`, and the playground frame only once
`[data-demo-verdict]` actually read `BLOCK` — and it is framed so `BLOCK`, `CRITICAL` and
`DRAIN_ADDRESS` are all visible, because proving a verdict in the DOM is not the same as showing it.

**Theme note.** Production now defaults to **dark**, and the site ships no `prefers-color-scheme`
rules — the theme is an explicit `data-theme` toggle persisted to `localStorage`. A browser context's
colour scheme therefore has no effect here. Each capture below drives the real toggle and asserts
`documentElement.dataset.theme` before shooting; without that assertion a "dark" frame silently
records as the light one under a different filename.

| Route         |   Viewport | Theme         | Proposed output file                     | Required state                                                                 |
| ------------- | ---------: | ------------- | ---------------------------------------- | ------------------------------------------------------------------------------ |
| `/`           | 1440 x 900 | Light explicit | `home-action-boundary-desktop-light.png` | Pre-action message, action-boundary visual, and product CTAs are readable.     |
| `/`           |  390 x 844 | Light explicit | `home-action-boundary-mobile-light.png`  | Closed navigation, action boundary, and primary live-scan action are visible.  |
| `/`           | 1440 x 900 | Dark default  | `home-action-boundary-desktop-dark.png`  | Same evidence as the light frame; contrast is manually checked.                |
| `/theater`    | 1440 x 900 | Light explicit | `theater-idle-desktop-light.png`         | Idle state, explicit activation, and “no request” status are visible.          |
| `/theater`    | 1440 x 900 | Light explicit | `theater-complete-desktop-light.png`     | An explicitly started run has three receipt-validated rows and counter 3/3.   |
| `/theater`    |  390 x 844 | Light explicit | `theater-complete-mobile-light.png`      | Verdicts, handler delivery, status, and controls fit without clipping.         |
| `/trust`      | 1440 x 900 | Light explicit | `trust-architecture-desktop-light.png`   | Enforcement, signed evidence, transparency, and dated context are visible.     |
| `/verify`     | 1440 x 900 | Light explicit | `verify-initial-desktop-light.png`       | Initial verifier instructions are visible; no invented attestation is entered. |
| `/apa/log`    | 1440 x 900 | Light explicit | `apa-log-desktop-light.png`              | Real transparency entries or the honest empty state are visible.               |
| `/playground` | 1440 x 900 | Light explicit | `playground-block-desktop-light.png`     | A real drain-address response shows BLOCK and DRAIN_ADDRESS.                   |
| `/agents`     | 1440 x 900 | Light explicit | `marketplace-evidence-desktop-light.png` | Marketplace Evidence Index filters, provenance, date, and first rows appear.  |

Before accepting each capture:

- Confirm the route, viewport, theme, commit, and capture date in the review notes.
- Confirm all local assets load and the console has no errors.
- Confirm live states came from the displayed endpoint during that session.
- Confirm no payload, address, token, credential, payment signature, wallet, extension, notification, or
  unrelated desktop content is visible.
- Confirm APA copy and badges report their real status and do not imply per-request routing or permanent safety.
- Do not mark the release checklist complete until desktop and mobile captures have been reviewed by a human.
