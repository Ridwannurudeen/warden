# Frontend screenshot manifest

The two `warden-landing-*.png` files in this directory were captured on 2026-07-04 and predate the
hackathon frontend overhaul. Keep them as baseline evidence; do not use them as current release
screenshots.

The final capture environment was unavailable on 2026-07-13 because the in-app browser reported no
attached browser session. Capture the current production build after deployment approval, using a
device scale factor of at least 2 and the following stable paths:

| Route         |   Viewport | Output file                     | Required state                                           |
| ------------- | ---------: | ------------------------------- | -------------------------------------------------------- |
| `/`           | 1440 × 900 | `home-desktop-dark.png`         | First viewport and action-gate example visible           |
| `/`           |  390 × 844 | `home-mobile-dark.png`          | Closed navigation; hero CTA visible                      |
| `/playground` | 1440 × 900 | `playground-block-desktop.png`  | Real drain-address result showing BLOCK                  |
| `/playground` |  390 × 844 | `playground-mobile-input.png`   | Default example and trusted recipient visible            |
| `/showcase`   | 1440 × 900 | `showcase-verdict-desktop.png`  | Scene 04 after an explicit live scan or labeled fallback |
| `/showcase`   |  390 × 844 | `showcase-mobile-gate.png`      | Scene 03 before the explicit scan action                 |
| `/hire`       | 1440 × 900 | `hire-readiness-desktop.png`    | Readiness and current service summary visible            |
| `/agents`     | 1440 × 900 | `marketplace-index-desktop.png` | Filters, methodology boundary, and first rows visible    |

Before accepting each capture, verify that no payload, address, token, credential, payment signature,
browser extension, or unrelated desktop content is visible. Also capture one light-theme homepage frame
to confirm theme contrast, but keep the dark frame as the README hero when it is current.
