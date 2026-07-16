# Frontend screenshot manifest

The two `warden-landing-*.png` files in this directory were captured on 2026-07-04 and predate the
Trust Layer interface. Preserve them as baseline evidence; do not present them as current screenshots.

No current screenshots have been accepted for this working tree. Capture them only from the exact build
being reviewed, at device scale factor 2 or higher, and record the commit alongside the files.

| Route         |   Viewport | Theme         | Output file                           | Required state                                                                 |
| ------------- | ---------: | ------------- | ------------------------------------- | ------------------------------------------------------------------------------ |
| `/`           | 1440 x 900 | Light default | `home-safety-map-desktop-light.png`   | Immune-system hero and Safety Map boundary are readable.                       |
| `/`           |  390 x 844 | Light default | `home-mobile-light.png`               | Closed navigation and primary Theater action are visible.                      |
| `/`           | 1440 x 900 | Dark explicit | `home-safety-map-desktop-dark.png`    | Same evidence as the light frame; contrast is manually checked.                |
| `/theater`    | 1440 x 900 | Light default | `theater-complete-desktop-light.png`  | A real one-pass run has three receipt-validated feed rows and counter 3/3.     |
| `/theater`    |  390 x 844 | Light default | `theater-complete-mobile-light.png`   | Verdicts, downstream delivery, status, and controls fit without clipping.      |
| `/trust`      | 1440 x 900 | Light default | `trust-pillars-desktop-light.png`     | Local enforcement, APA, and Safety Map pillars are visible.                    |
| `/verify`     | 1440 x 900 | Light default | `verify-initial-desktop-light.png`    | Initial verifier instructions are visible; no invented attestation is entered. |
| `/apa/log`    | 1440 x 900 | Light default | `apa-log-desktop-light.png`           | Real transparency entries or the honest empty state are visible.               |
| `/playground` | 1440 x 900 | Light default | `playground-block-desktop-light.png`  | A real drain-address response shows BLOCK and DRAIN_ADDRESS.                   |
| `/agents`     | 1440 x 900 | Light default | `marketplace-index-desktop-light.png` | Filters, evidence boundary, date, and first rows are visible.                  |

Before accepting each capture:

- Confirm the route, viewport, theme, commit, and capture date in the review notes.
- Confirm all local assets load and the console has no errors.
- Confirm live states came from the displayed endpoint during that session.
- Confirm no payload, address, token, credential, payment signature, wallet, extension, notification, or
  unrelated desktop content is visible.
- Confirm APA copy and badges report their real status and do not imply per-request routing or permanent safety.
- Do not mark the release checklist complete until desktop and mobile captures have been reviewed by a human.
