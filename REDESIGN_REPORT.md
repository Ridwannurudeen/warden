# Warden redesign report

Date: 2026-07-18

Branch: `feat/post-hackathon-completion`

Scope: local production source and generated site; no deployment, publication, payment, or VPS change

## Outcome

Warden now presents one mature product: a security boundary placed immediately before an AI agent performs
a consequential action.

The final message is:

> Verifiable pre-action security for AI agents.

The website no longer leads with the “immune system” metaphor, an oversized BLOCK panel, or a wall of
equal-weight experiments. The homepage establishes the action boundary, the three verdicts, the caller's
authority, and the evidence that remains after an action is withheld or transformed.

The implementation preserves Warden's actual contracts. It does not convert `ALLOW` into a safety
guarantee, endpoint audit records into certification, public listing text into a maliciousness judgment, or
source-ready mechanisms into live production claims.

## Scope and routes audited

The generated site contains 910 HTML pages: 28 canonical public routes (including the documentation index,
11 reason-code references, and the marketplace index) plus 882 generated marketplace detail records.

Canonical routes:

- Product: `/`, `/playground`, `/theater`, `/showcase`, `/gauntlet`, `/hire`
- Developers: `/integrate`, `/docs`, and 11 `/docs/{reason-code}` pages
- Evidence: `/verify`, `/apa/log`, `/badges`, `/badge`, `/trust`, `/status`
- Marketplace: `/agents` and generated `/agents/{id}` records
- Legal: `/privacy`, `/terms`

`/log` remains a static compatibility page. `/apa/log` is the canonical application route: JSON by default
and HTML only when the client explicitly accepts `text/html`.

The final local build and route contracts were audited from source and generated output. A new interactive
browser walkthrough of the final commit was not completed because this session exposed no browser backend.
No live deployment is claimed.

## Main problems found

1. The site used generic, inflated positioning that obscured the concrete action-boundary product.
2. The homepage's large BLOCK treatment made one example look like the entire product.
3. Navigation gave experiments, commercial flows, evidence, and core product surfaces similar weight.
4. Copy repeated concepts and caveats in a way that felt generated rather than editorially controlled.
5. Marketplace signals, endpoint audits, APA attestations, service health, and illustrative examples were
   visually close enough to be misread as the same kind of proof.
6. Dynamic areas could begin with ambiguous placeholders or stale values.
7. Manual and generated routes did not consistently share navigation semantics, provenance labels, spacing,
   responsive behavior, and evidence styling.
8. Documentation and old handoff files retained obsolete names, metrics, autoplay directions, and product
   metaphors after the product had changed.

## Final information architecture

| Group | Primary destinations | User outcome |
| --- | --- | --- |
| Product | Overview, Playground, Attack Theater, Use Warden | Understand the boundary, run it, and choose a service |
| Developers | Integrate, Documentation | Place Warden immediately before execution and handle all three verdicts |
| Evidence | Verify, Transparency Log, Endpoint Audit Records, Marketplace Evidence Index, Status | Inspect signatures, chain state, dated records, and service evidence |
| Research | Gauntlet, Product Tour | Reproduce the product story or submit an authorized adversarial candidate |

The desktop header keeps a persistent **Integrate** action and **Run a live scan** CTA. The mobile shell uses
an accessible menu with the same destinations. Section proxies receive visual section styling without
incorrectly claiming `aria-current="page"`; only exact canonical destinations receive that attribute.

Three journeys are explicit:

- Security evaluator: understand the boundary → run an incident → inspect proof → use Warden
- Developer: understand the decision contract → choose an integration → test the execution branch
- Auditor or researcher: inspect methodology → verify a record → inspect chain and dated evidence

## Design concept

The final register is “editorial cryptography meets an operational incident room”: quiet, high-consequence,
and inspectable.

The visual system uses:

- a warm gold action-boundary signal rather than generic cybersecurity cyan;
- obsidian and parchment surfaces;
- compact technical labels and tabular numerals;
- restrained borders, two-to-three radius levels, and limited elevation;
- semantic verdict colors that remain distinct from the brand accent; and
- product records, hashes, timestamps, and real source data instead of decorative dashboard mockups.

### Core tokens

| Token | Light | Dark |
| --- | --- | --- |
| Surface | `#fffdf8` | `#14110b` |
| Raised surface | `#ffffff` | `#1b1710` |
| Soft surface | `#f2ecdf` | `#211c13` |
| Text | `#141109` | `#f6f0e1` |
| Border | `#e0d7c5` | `#2c2619` |
| Strong border | `#c9bda2` | `#463f2c` |
| Brand accent | `#b88a2a` | `#d7aa49` |
| ALLOW | `#287a57` | `#59b98a` |
| SANITIZE | `#9a6412` | `#e5852a` |
| BLOCK | `#b64045` | `#ef6f5b` |

Radii are 4, 7, and 10 pixels. The primary content width is 1,180 pixels.

### Shared patterns

The site renderer and shared CSS/JavaScript now provide consistent:

- global shell, direct navigation, mobile navigation, status, theme, breadcrumbs, and footer;
- buttons, form fields, tabs, copy controls, code blocks, notices, and async panels;
- verdict and reason states;
- `LIVE`, `DATED`, `ILLUSTRATIVE`, `DEGRADED`, and `UNKNOWN` source stamps;
- evidence boundaries, signed-record layouts, signature and chain states;
- action-boundary diagrams, compact incident receipts, and raw-evidence disclosure;
- marketplace filters, desktop rows, mobile cards, empty results, and detail records; and
- loading, timeout, rate-limit, malformed-response, unavailable, retry, and reset states.

## Route outcomes

### Homepage

The homepage uses a short product sequence:

1. concise pre-action security message and two primary journeys;
2. compact illustrative action receipt;
3. one explicitly activated live incident;
4. placement and decision-contract explanation;
5. verification, integration, and service paths.

The BLOCK example is now one compact outcome inside a wider boundary story. No production request runs on
page load.

### Playground and Theater

The Playground is a two-panel scan workspace with curated attack classes, trusted-recipient context,
verdict-first output, exact sanitization differences, raw JSON, and bounded error states.

Attack Theater starts idle and sends no request until **Run test sequence** is selected. After activation,
the three controlled cases continue only while their verdict, reason, and downstream receipt agree. Errors
stop visibly. Reduced-motion users advance cases manually.

### Product Tour, Gauntlet, and Use Warden

Product Tour is a guided explanation rather than a duplicated homepage. Gauntlet separates private
candidate submission, human review, confirmed bypasses, public finder consent, signed WARDEN BREAKER
certificates, and the transparency log.

The `/hire` URL is preserved, but the interface is **Use Warden**. Its staged flow keeps service selection,
request input, cost, signing responsibility, payment, execution, completion, and review boundaries visible.
Generated commands quote untrusted input and remain locked until their prerequisites are established.

### Documentation and integrations

Documentation has a persistent desktop index, mobile access, on-page navigation, deep links, copyable code,
and the complete machine-readable reason vocabulary.

Integrations lead with source installation and actual supported paths: Python, TypeScript, direct HTTP,
raw x402, OnchainOS, FastMCP stdio, LangChain, and LlamaIndex. Paid SDK handling validates the pinned
challenge and permits exactly one caller-authorized replay. No package registry availability is invented.

### Evidence, status, and marketplace

Verifier, transparency log, Endpoint Audit Records, Trust, and Status distinguish signature validity,
freshness, revocation, chain continuity, issuer provenance, point-in-time audit evidence, current
reachability, and dated product evidence.

The Marketplace Evidence Index never labels an agent safe, unsafe, or malicious from public text. It
separates pattern matches, no implemented match, no public text, linked audit evidence, unavailable records,
and partial discovery.

Privacy and Terms are explicitly dated service summaries in the shared visual system, not a claim of
independent legal review.

## Copy and positioning changes

- “The immune system of the agent economy” → “Verifiable pre-action security for AI agents”
- “Safety Map” and “Safety Index” → “Marketplace Evidence Index”
- “Hire” → “Use Warden” in the interface while preserving the route
- “Showcase” → “Product Tour” in navigation while preserving the route
- “No trust required” → local signature verification with explicit key-provenance and freshness limits
- “Provable safety” style claims → verifiable enforcement, inspectable evidence, and bounded proof
- Theater autoplay language → explicit activation and honest stopped states

Archived implementation briefs and submission drafts now carry visible superseded notices so their old copy
and metrics cannot be mistaken for current product truth.

## Dynamic data and provenance

Every important dynamic claim has a state, source boundary, and timestamp or explicit unavailable result.
The site does not turn an unavailable fetch into zero or success.

Committed evidence at completion:

| Source | Current committed state |
| --- | --- |
| Marketplace snapshot | `DEGRADED`: 882 sampled, 885 expected, 3 dropped, 5 public-text signals, 0 linked audits; captured `2026-07-18T18:35:07Z` |
| Held-out benchmark | `DATED`: 87/94 attacks detected, 0/45 benign false positives; measured `2026-07-17T17:36:22Z` |
| Service monitor | `UNKNOWN`: `not_running`; no historical uptime claim |
| Independent APA anchor | `UNKNOWN`: `unpublished`; no independent-witness claim |

An exact `0/0/0` marketplace response is treated as a complete dated empty result. Inconsistent or
incomplete counts remain degraded.

## Accessibility

Implemented and source-tested:

- skip link and landmark structure;
- exact-page navigation semantics;
- visible focus and keyboard-operable mobile navigation, tabs, copy controls, and product flows;
- focus cycling/restoration contracts for the mobile menu;
- text labels in addition to semantic color;
- source-tested text and control contrast in both themes;
- 44-pixel primary navigation and touch-control floors;
- reduced-motion CSS and manual Theater progression;
- live-region messaging for changing status;
- labels, descriptions, table headers, diagram alternatives, and raw-record disclosure;
- long-token wrapping and responsive marketplace cards for narrow layouts; and
- pre-CSS theme initialization to prevent a theme flash.

No formal WCAG 2.2 AA conformance claim is made. Axe, a real screen-reader walkthrough, interactive
keyboard/zoom review, and formal 200% zoom testing were not completed because no browser backend was
available in this session.

## Performance and technical quality

The site remains dependency-free HTML, CSS, and JavaScript with self-hosted assets and a self-only resource
policy. There is no frontend framework, runtime package bundle, tracker, autoplay video, WebGL scene, or
third-party font request.

Static facts for the final generated site:

- 910 HTML pages;
- one 72,246-byte shared stylesheet;
- 16 top-level JavaScript files totaling 365,535 bytes uncompressed;
- 154,167 bytes of referenced homepage JavaScript uncompressed; and
- content-hashed local CSS/JavaScript URLs.

Static generation is idempotent: `build_index.py` followed by `build_site.py`, repeated in the same tree,
produced an identical site diff hash.

Lighthouse and Core Web Vitals were not measured. No Performance, Accessibility, Best Practices, SEO, LCP,
CLS, or INP score is claimed.

## Security-sensitive decisions

- Scanner, payment, signing, wallet, evidence, and API contracts were not weakened for presentation.
- No page executes a payment, task, review, live incident, or adversarial request merely because it loads.
- User-controlled values are rendered through text-safe paths; marketplace hydration does not use HTML
  parsing sinks.
- Generated shell commands keep untrusted values inside one quoted argument.
- The site loads same-origin resources under the existing CSP and does not add analytics.
- Local verification does not send a pasted record back to Warden.
- Endpoint audits require authorization and remain point-in-time evidence, not certification.
- Gauntlet candidates remain private until human confirmation and explicit public-credit consent.

## Verification results

| Gate | Result |
| --- | --- |
| Complete root Python suite | 1,297 passed, 1 skipped, 1 existing Starlette/httpx deprecation warning |
| Complete frontend state suite | 189 passed |
| Ruff | Passed |
| Python SDK | 147 passed |
| TypeScript SDK | 81 passed; build, audit, and dry-run package passed |
| Detector, scanner, verdict, and Shield focused suite | 262 passed |
| UI, site, and marketplace focused suite | 109 passed |
| Package, standard, audit-data, and supply-chain focused suite | 72 passed |
| Python dependency integrity | `pip check` clean; `pip-audit` found no known vulnerabilities |
| Root distributions | Wheel and source distribution built; Twine checks passed |
| Held-out benchmark | 87/94 recall (92.55%); 0/45 false positives |
| APA reference and conformance | Self-test passed; all 12 vectors passed |
| Static generation | Completed twice with identical output |
| Social preview | Regenerated from the gold SVG and verified at 1,200 × 630 |

The checksum-pinned TruffleHog workflow contract passes. A final full-history binary scan is recorded
separately from this report after the final documentation commit.

## Screenshots and browser QA

Historical before-redesign baselines:

- `docs/screenshots/warden-landing-desktop.png`
- `docs/screenshots/warden-landing-mobile.png`

They predate the current interface and are not presented as current screenshots.

No current after-redesign screenshot was accepted. Browser discovery returned no available browser, so the
final interactive viewport matrix at 1440, 1280, 1024, 768, 390, and 360 pixels, console/network inspection,
theme walkthrough, keyboard walkthrough, and current screenshot capture remain unexecuted.

## Remaining limitations

### Measured product limits

- Seven held-out attacks remain undetected: `held-prompt-002`, `held-prompt-003`, `held-role-002`,
  `held-corpus-002`, `held-drain-002`, `held-secret-002`, and `held-evade-mix-003`.
- Optional semantic and embedding tiers remain uncalibrated without provider configuration.
- Marketplace discovery is partial by 3 records and has no linked endpoint audit.
- The monitor is not running and the independent anchor is unpublished.

### External, operator, or time-dependent work

- approved deployment and production smoke/rollback verification;
- production x402 domain correction and read-only reprobe;
- deployed CORS, nginx, systemd, filesystem, and key verification;
- hosted CI on the final pushed commit;
- an independently controlled anchor witness;
- a complete 30-day monitor window;
- registry publication of either SDK;
- real Shield enrollment, alert delivery, and recurring observation; and
- a production issuer-key rotation ceremony.

### Unexecuted local QA

- interactive browser, viewport, console, keyboard, zoom, and theme walkthrough;
- axe and real screen-reader testing;
- current after-redesign screenshots; and
- Lighthouse and Core Web Vitals measurement.

No deployment, push, package publication, form submission, social post, funded transaction, wallet action,
or VPS mutation was performed.
