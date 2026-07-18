# Warden production UI/UX maturity report

- Date: 2026-07-18
- Repository: `C:\Users\gudma\OneDrive\Desktop\GITHUB-FILES\warden`
- Branch: `fix/scanner-exfil-drain-coverage`
- Verified HEAD: `3e96a8b3075066f67afd3ad1ebecd9c18641515a`

## Executive outcome

Warden's public website has been rebuilt from a collection of visually competing experiments into one restrained product system.

The central story is now:

`untrusted agent output -> Warden boundary -> ALLOW / SANITIZE / BLOCK -> caller policy -> consequential action`

The homepage leads with:

> A security boundary for agent actions.

The former oversized BLOCK presentation is gone. Verdicts now appear as compact operational states: BLOCK and ALLOW render at 50 by 30 CSS pixels in the verified homepage layout, while SANITIZE expands only enough to fit its label. Verdict color is reserved for meaning rather than used as a decorative brand effect.

The writing was reduced, bounded, and aligned to the implemented product. Marketing, live tools, documentation, evidence, research, commerce, marketplace data, and legal pages now use one information architecture, shell, tone, and evidence model.

This work remains local and uncommitted. It was not deployed, pushed, published, submitted, or used to access the VPS.

## Scope audited

The audit covered the static-site architecture, shared renderer, styling and JavaScript, FastAPI preview behavior, generated documentation, marketplace generation, live demo contracts, evidence surfaces, SDK integration claims, CSP/security headers, dynamic-data fallbacks, tests, build scripts, SEO output, and responsive behavior.

Public route families audited:

- `/`
- `/playground`
- `/theater`
- `/showcase`
- `/gauntlet`
- `/hire`
- `/docs`
- `/docs/{reason-code}`
- `/integrate`
- `/badges`
- `/badges/{audit-id}`
- `/verify`
- `/apa/log`
- `/trust`
- `/status`
- `/agents`
- `/agents/{agent-id}`
- `/privacy`
- `/terms`

The generated tree contains 758 HTML pages:

- 15 top-level product pages
- 12 documentation pages
- 1 marketplace index
- 730 marketplace detail pages

The final static audit found:

- 758 unique titles
- 758 unique canonical URLs
- Exactly one description, `main#main`, and H1 per page
- 1,701 element IDs with no duplicates
- 25,433 internal links checked, including 2,454 fragment links, with no missing target
- 2,298 local CSS/JavaScript references across 17 assets, all carrying current SHA-256 fingerprints
- `theme.js` before `styles.css` on every page
- 28 stable canonical routes in the sitemap
- Exact expected `robots.txt` output

## Problems found in the previous experience

- The homepage gave too many experiments equal visual weight and did not establish a single product hierarchy.
- The large BLOCK panel made one verdict look like the product instead of one state within a decision system.
- Repeated slogans, proof claims, cards, decorative effects, and long caveats made the copy feel generated rather than edited.
- The palette mixed brand emphasis and danger states, so red, amber, glow, and accent treatments competed for attention.
- Navigation exposed internal product naming such as Hire, Showcase, Safety Index, and audit badges without enough context.
- Marketing, live tools, evidence pages, marketplace records, documentation, and legal pages looked like separate products.
- Dynamic data could leave ambiguous loading, checking, zero, or unavailable states.
- ALLOW, signature validity, endpoint audit results, and public marketplace text could be read more broadly than their evidence justified.
- Mobile navigation, dense evidence metadata, tables, and marketplace rows needed stronger reflow and touch behavior.
- The previous theme path could apply persisted state after CSS and risk a visible theme transition.
- Documentation tables lacked captions, mobile status became color-only, and several control/error colors missed the intended contrast thresholds.

## Final information architecture

### Header

- Product
- Playground
- Developers
- Docs
- Evidence
- Research

Persistent actions:

- Run a live scan
- Integrate
- Service status
- Theme control

### Footer

Product:

- Overview
- Live Playground
- Incident Replay
- Use Warden

Developers:

- 5-minute quickstart
- Integration guide
- Documentation

Evidence:

- Verify an attestation
- Transparency log
- Endpoint audit records
- Marketplace Evidence Index
- Service status

Research:

- Gauntlet
- Methodology
- Product Tour

Policy:

- Trust and security
- Privacy
- Terms

This creates three direct visitor paths:

- Evaluator: understand the boundary -> run a controlled incident -> inspect proof
- Developer: understand the contract -> integrate -> handle the three decisions
- Auditor or researcher: inspect methodology -> verify a record -> inspect chain and dated evidence

## Design direction

The final direction is a quiet security control plane: editorial structure with operational precision.

It deliberately removes:

- Gradients
- Glow systems
- Particles and decorative motion
- Scroll-reveal effects
- Fake terminals
- Autoplay demonstrations
- Generic security imagery
- Repetitive card walls
- Constant verdict-color decoration

The sticky header retains one restrained background blur. No other glass-effect system remains.

### Core tokens

Light theme:

- Background: `#f4f6f7`
- Surface: `#ffffff`
- Primary text: `#17212b`
- Brand accent: `#356f86`
- Control border: `#7a8b95`

Dark theme:

- Background: `#0b1015`
- Surface: `#111820`
- Primary text: `#edf2f6`
- Brand accent: `#68adc1`
- Control border: `#677887`

Semantic verdicts:

- ALLOW: restrained green
- SANITIZE: restrained amber
- BLOCK: restrained red

The verdict always includes text and shape, not color alone.

Typography:

- Local Plus Jakarta Sans for interface and editorial text
- Cascadia/system monospace stack for code, hashes, timestamps, and reason codes
- Tabular numerals for evidence and metrics

Geometry:

- Radius levels: 4, 7, and 10 pixels
- 1-pixel control borders
- 44-pixel practical minimum for primary interactive targets
- 12-column desktop composition with focused reading widths

### Shared component patterns

- Canonical page shell
- Direct desktop navigation
- Full-viewport mobile navigation with focus containment and restoration
- SourceStamp
- Verdict and risk labels
- Evidence boundaries
- Action-boundary diagrams
- Signed receipt and verification readouts
- Chain status and tamper demonstration
- Breadcrumbs
- Documentation navigation and table of contents
- Responsive table shells and mobile result cards
- Copy controls with live feedback
- Empty, error, degraded, retry, and reset states

## Copy and positioning

The homepage no longer leads with an unsupported superlative or a long technical paragraph.

Primary positioning:

> Warden inspects untrusted agent output before it reaches payments, tools, links, or secrets. It returns a policy verdict and an inspectable record.

Canonical CTAs:

- Product: Run a live scan
- Developer: Integrate in 5 minutes
- Evidence: Verify an attestation
- Commercial: Use Warden

Removed or avoided:

- Provable safety
- No trust required
- Unsupported first-in-the-world claims
- Universal safety language for ALLOW
- Certification language for endpoint audit records
- Malicious, safe, or secure labels inferred from marketplace text
- Invented logos, testimonials, awards, uptime, usage, or customer proof

Implemented boundaries:

- ALLOW means no implemented detector fired; it is not a safety guarantee.
- A valid signature proves record integrity under the applicable key; it is not endpoint safety.
- Endpoint audit records are point-in-time evidence, not certification.
- Public-text pattern matches do not establish malicious intent.
- The caller retains final authority.
- A demo verdict does not prove that every external execution path is gated.

## Route implementation

### Homepage

- Rebuilt around the action boundary rather than a feature-card wall.
- Replaced the oversized BLOCK display with a compact example request and decision trace.
- Reduced the page to six focused narrative sections.
- Preserved an explicitly activated live incident console.
- Preserved local signature, chain, and one-byte tamper verification.
- Presents supported integration paths and currently sourced services without invented package commands or metrics.
- Uses real product content and bounded source states.

### Playground

- Responsive scan workspace with curated attacks and custom payload input.
- Removable, validated expected-recipient context.
- Decision, risk, reason code, detected span, transformed output, latency, source state, and raw JSON remain distinct.
- Explicit empty, invalid, oversized, rate-limit, timeout, unavailable, malformed-response, retry, and reset states.
- ALLOW copy remains bounded.
- Browser QA confirmed a real local BLOCK / DRAIN_ADDRESS result with no page overflow.

### Incident Replay

- Three controlled cases: prompt injection, recipient drain, and secret exfiltration.
- No request occurs before explicit activation.
- Verdict and downstream demo-handler receipt must agree before a case counts as neutralized.
- Unexpected or unavailable results pause honestly.
- Replay and reset are deterministic.
- The local browser run completed all three cases and displayed validated handler receipts.

### Product Tour

- Reduced to a compact three-step recipient-change tour.
- Uses one explicit live scan action.
- Makes the no-wallet and no-downstream-system boundary visible.
- The final scene separates scanner response from caller-side enforcement.
- Keyboard navigation and predictable reset behavior are covered.

### Gauntlet

- Submission is placed before public findings.
- Authorization, storage, privacy, and public-finder consent are separate.
- Candidate, duplicate, detected, confirmed, and unavailable states do not expose private payloads.
- Confirmed results link only to validated same-origin certificate and verification material.
- No cash bounty is implied.
- No submission was made during QA.

### Use Warden

- Keeps the `/hire` route while presenting a clearer commercial label.
- Four-step review path with persistent order summary.
- Service, endpoint or payload, cost, network, asset, recipient, signing responsibility, and command stages remain separate.
- Generated shell commands quote untrusted values and unlock only after their evidence gate.
- Payment and wallet signing remain outside the browser.

### Integrations and documentation

- Five-minute source-install path for the repository clients.
- Exact placement immediately before consequential execution.
- Python, TypeScript, direct HTTP/x402, MCP, OnchainOS, LangChain, and LlamaIndex claims remain tied to implemented repository surfaces.
- Fail-open, fail-closed, timeout, retry, logging, privacy, secret, and wallet boundaries are explicit.
- Documentation includes 11 generated reason-code pages.
- Every one of the 14 documentation tables now has a visible caption.

### Evidence

- Endpoint audit records explicitly state point-in-time evidence, not certification.
- The verifier separates parsing, issuer resolution, signature, freshness, subject, revocation, and proof boundary.
- The transparency page explains the chain before raw hashes and exposes local recomputation and tampering.
- The trust page separates local enforcement, signed APA evidence, public transparency, and dated context.
- Status separates current reachability from objectives, benchmark evidence, marketplace freshness, and historical uptime.
- No historical uptime chart is invented.

### Marketplace Evidence Index

- Uses neutral evidence language rather than a safety ranking.
- Initial HTML contains 50 useful rows; explicit hydration loads all 730 records and expands in bounded windows.
- Search and filters operate over the complete snapshot after hydration.
- Index rows omit raw scanner verdict badges.
- Each of 730 detail pages contains one linked-evidence ledger.
- All 1,755 source services have matching rendered disclosures.
- Script-detectable Han and Hangul content is tagged for assistive pronunciation; no `lang="und"` remains.

### Legal

- Privacy and Terms share the product shell.
- Both use readable widths, dated metadata, deep links, table of contents, cross-links, and print rules.

## Dynamic data and provenance

SourceStamp supports:

- `LIVE`
- `DATED`
- `ILLUSTRATIVE`
- `DEGRADED`
- `UNKNOWN`

Every remote block uses a stable loading footprint, timeout, retry or reset where applicable, a check timestamp, and an explicit unavailable state. The UI does not turn a failed request into zero or success.

Current marketplace evidence:

- Captured: `2026-07-16T02:47:26Z`
- Sampled: 730
- Expected discovery total: 752
- Missing or degraded: 22
- Public-text signals: 3
- Linked signed endpoint audits: 0

The marketplace is therefore displayed as degraded and dated, not current or complete.

Current held-out evaluation:

- Measured: `2026-07-17T17:36:22Z`
- Attack cases: 94
- Detected: 87
- Recall: 92.55%
- Benign cases: 45
- False positives: 0
- Semantic layer: disabled for this measurement

The site reads these values from versioned data. They are not duplicated as mutable marketing constants.

## Accessibility

Implemented and verified:

- Skip link and landmark structure
- One H1 per generated page
- Visible focus treatment
- Keyboard-operable navigation, tabs, tour, replay controls, and recipient chips
- Escape-to-close and focus restoration for mobile navigation
- Programmatic labels, descriptions, errors, and status announcements
- Text and shape in addition to semantic color
- 44-pixel mobile brand, status, theme, and primary controls
- Reduced-motion styles and no autoplay
- Static equivalents for causal narratives
- Responsive tables and mobile marketplace cards
- Visible documentation captions
- No page-level horizontal overflow in the sampled layouts
- Theme controls announce their action
- Mobile status shows `UP`, `OFF`, or `?` in addition to its dot

Contrast regressions corrected:

- Secondary control borders now exceed 3:1 against adjacent surfaces in both themes.
- Error and removed-diff text now exceed 4.5:1 against their applicable backgrounds.
- Verdict label foregrounds were corrected for their semantic backgrounds.

Generated language audit:

- 758 `lang="en"` page roots
- 1,740 script-detectable `lang="zh"` passages
- 4 `lang="ko"` passages
- 0 `lang="und"` passages

Current marketplace data does not provide authoritative locale metadata. Script-only classification cannot reliably distinguish every ambiguous Han-only or Latin-language passage, so the renderer does not invent more specific tags where the source cannot support them.

Manual browser checks covered keyboard focus in the mobile menu, Escape restoration, live status labeling, both themes, explicit demo activation, focus after marketplace expansion, and representative error/degraded states.

No claim of formal WCAG 2.2 conformance is made because an automated axe pass, a real screen-reader walkthrough, and a formal 200% zoom audit were not completed.

## Performance and technical quality

- Static-first multi-page architecture retained.
- No trackers, external fonts, video, WebGL, chart framework, or animation library added.
- No gradient or particle system remains.
- No demo request is triggered by page load or viewport entry.
- Theme initialization is a 466-byte external script placed before CSS, preventing a persisted-theme flash without weakening CSP.
- Marketing and documentation remain usable without a successful remote data request.
- Local assets are fingerprinted from their actual SHA-256 content.
- Browser QA found no external page assets on the sampled routes.

Final unminified asset sizes:

- `site/styles.css`: 61,332 bytes
- `site/app.js`: 31,337 bytes
- `site/theme.js`: 466 bytes
- `site/agents.js`: 28,026 bytes
- Top-level route JavaScript combined: 335,030 bytes; pages load only their relevant modules
- Social preview PNG: 54,111 bytes

Current key fingerprints:

- `theme.js`: `2c7c8d24`
- `styles.css`: `a3737335`
- `app.js`: `0abdbc0f`
- `agents.js`: `6f9c9326`

Lighthouse was not run. The CLI is not installed in this workspace, and no performance, LCP, CLS, INP, or accessibility score is claimed.

## Security-sensitive decisions

- Scanner, detector, cryptographic, key-history, transparency, payment-settlement, wallet-signing, and frozen HTTP field contracts were not changed to simplify the UI.
- Browser demos reject malformed, contradictory, unavailable, or incomplete evidence.
- A successful incident requires agreement between the verdict and demo-handler receipt.
- User-controlled marketplace and certificate values are written with text nodes rather than HTML parsing.
- Generated shell arguments are validated and quoted.
- CSP remains strict; no inline scripts or event handlers were introduced.
- Marketplace signals remain non-diagnostic.
- Gauntlet payloads remain private unless separately authorized for publication.
- Payment signing stays outside Warden and the browser.
- The frozen paid request/response contract regression remains green.

The separate security record is `SECURITY-AUDIT-2026-07.md`.

The historical D-01 through D-14 register is not 14 currently deferred findings. Current disposition at this HEAD:

- D-01 through D-06: fixed
- D-10: accepted detector limitation
- D-07, D-08, D-09, D-11, D-12, D-13, and D-14: deferred

The seven actionable deferred items are:

1. Publish and monitor an independent APA checkpoint.
2. Add a reviewed Python hash lock and CI vulnerability scanning.
3. Reconcile the live `/scan` price with dated documentation and fixtures after read-only live verification.
4. Pin MCP transport explicitly before any network exposure.
5. Add dedicated CORS configuration regressions and verify deployed headers during an approved live audit.
6. Correct the README's 92-versus-94 corpus inventory.
7. Add a whole-audit deadline without weakening the no-partial-badge rule.

The accepted limit is seven held-out detector misses at 92.55% recall and zero measured false positives. Improving recall must preserve the held-out and false-positive discipline.

These residuals do not invalidate the local website redesign. They prevent describing the entire security programme as fully remediated or exploit-proof.

## Browser QA

Representative viewport checks:

- 1440 by 1000: homepage and trust architecture
- 1280 by 900: homepage
- 1024 by 900: Marketplace Evidence Index
- 768 by 900: Incident Replay
- 390 by 844: service status
- 360 by 800: homepage, Playground, Product Tour, documentation, integrations, and marketplace details

Verified browser behavior:

- No page-level horizontal overflow on sampled routes
- Compact verdict labels
- Persisted light/dark theme across navigation
- Full-viewport mobile menu
- Focus moves into the menu and returns to its trigger
- Mobile service status includes visible text
- Live Playground returned a validated BLOCK / DRAIN_ADDRESS result
- Product Tour advanced only after an explicit scan
- Incident Replay completed only after three validated handler receipts
- Verifier reported the signed bundled sample as archival/stale rather than current
- Transparency and commercial surfaces showed explicit degraded states when local preview dependencies were unavailable
- Marketplace initial SSR count was 50 and full snapshot count was 730
- No raw ALLOW, SANITIZE, or BLOCK label appeared in marketplace index rows
- No JavaScript exception or hydration warning was observed

The browser console recorded two expected local-preview network failures:

- `503` for the unavailable local transparency checkpoint
- `400` for the unpaid local `/scan` terms probe

Both produced explicit degraded UI rather than false success.

Final browser-session screenshot artifacts:

- `warden-home-final-1440.png`
- `warden-home-final-1280.png`
- `warden-theater-final-768.png`
- `warden-status-final-390.png`
- `warden-home-final-360.png`

They are browser-session artifacts, not files checked into the repository.

No valid baseline screenshot set was captured before the inherited redesign work began, so this report does not claim a controlled pixel-level before/after comparison.

## Build and test results

Current working-tree verification passed on base HEAD `3e96a8b3075066f67afd3ad1ebecd9c18641515a`:

- `python scripts/build_index.py`
  - 730 agents indexed
  - 3 public-text matches
  - 0 independently audited
- `python scripts/build_site.py`
  - 11 reason-code pages
  - Documentation index
  - Public APA specification
  - Fingerprinted local assets
  - 28 canonical crawler routes
- `python -m pytest -q`
  - 835 passed
  - 1 skipped because POSIX mode bits are unavailable on Windows
  - 1 existing Starlette/httpx TestClient deprecation warning
- `node --test tests/js/*.test.js`
  - 175 passed
- `python -m pytest -q sdk/python/tests`
  - 95 passed
- `npm test` in `sdk/ts`
  - 31 passed across 3 files
- `npm run build` in `sdk/ts`
  - passed
- `npm pack --dry-run` in `sdk/ts`
  - passed
  - 18 files
  - 14.6 kB package estimate
- `python scripts/benchmark_recall.py`
  - 87 of 94 attacks detected
  - 92.55% recall
  - 0 of 45 benign cases changed
- `python spec/verify_apa.py --selftest`
  - genuine record accepted
  - tampered record rejected
  - wrong issuer key rejected
- `python -m ruff check .`
  - passed
- `python -m pip check`
  - no broken requirements
- `python -m compileall -q warden scripts`
  - passed
- `git diff --check`
  - passed

Independent generated-tree audit:

- 758 pages
- 758 unique titles and canonicals
- No duplicate IDs
- No broken internal links or fragments
- No stale asset fingerprints
- 14 documentation tables and 14 captions
- 730 snapshot records, JSON records, and detail pages in exact parity
- 50 matching initial marketplace rows
- 1 linked-evidence ledger per detail page
- No pending-state classes or raw verdict badges in index rows
- 1,755 source services and rendered disclosures in exact parity

## Remaining limitations

1. Lighthouse, axe, a real screen-reader walkthrough, and formal 200% zoom testing remain unmeasured.
2. No controlled baseline screenshot set exists.
3. The bundled public attestation is validly signed but archival/expired.
4. The public external transparency anchor remains unpublished.
5. Marketplace discovery is partial and dated: 730 of an expected 752, with 22 missing and no linked signed endpoint audits.
6. Endpoint audits remain point-in-time fixed-battery evidence, not certification.
7. No genuine historical uptime series exists.
8. Local preview could not establish live x402 terms or a transparency checkpoint.
9. No production deployment, VPS smoke test, live paid call, wallet signature, or on-chain action was performed.
10. The seven deferred security items and one accepted detector limit remain as described above.

## Important changed files

Shared system:

- `warden/site_render.py`
- `scripts/build_site.py`
- `site/theme.js`
- `site/styles.css`
- `site/app.js`
- `site/assets/warden-mark.svg`
- `site/assets/warden-social-card.svg`
- `site/assets/warden-social-card.png`

Homepage and product:

- `site/index.html`
- `site/incident-console.js`
- `site/playground.html`
- `site/playground.js`
- `site/theater.html`
- `site/theater.js`
- `site/showcase.html`
- `site/showcase.js`
- `site/gauntlet.html`
- `site/gauntlet.js`
- Removed `site/home-examples.js`

Commerce, developer, and legal:

- `site/hire.html`
- `site/integrate.html`
- `warden/site_docs.py`
- `site/privacy.html`
- `site/terms.html`

Evidence and operations:

- `site/badges.html`
- `site/badge.html`
- `site/verify.html`
- `site/verify.js`
- `site/log.html`
- `site/trust.html`
- `site/status.html`
- `warden/marketplace/render.py`
- `site/agents.js`

Regression coverage:

- `tests/test_mature_ui_contract.py`
- `tests/test_marketplace.py`
- `tests/test_redesign_contract.py`
- `tests/test_site.py`
- `tests/test_preview.py`
- `tests/test_sitemap.py`
- Route-specific suites under `tests/js`

## Final disposition

The local website redesign is complete and verified. It now presents Warden as a mature pre-action security product rather than a collection of experiments, while preserving the security and evidence boundaries implemented by the repository.

The result is ready for human review and an explicitly authorized deployment workflow. It has not been committed, pushed, or deployed.
