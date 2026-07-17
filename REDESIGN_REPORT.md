# Warden production UI/UX redesign report

Date: 2026-07-17  
Repository: `C:\Users\gudma\OneDrive\Desktop\GITHUB-FILES\warden`  
Branch: `fix/scanner-exfil-drain-coverage`  
Base HEAD: `5f474153df1cbfe84df474c2a447499ba018d920`

## Outcome

Warden now presents one coherent product story across marketing, live tools, developer documentation, evidence verification, adversarial research, commercial checkout, legal pages, and marketplace data:

> Verifiable pre-action security for AI agents.

The redesign centers the product on the action boundary:

`untrusted output → Warden → ALLOW / SANITIZE / BLOCK → caller policy → consequential action`

It pairs that decision with an inspectable receipt model and explicitly separates current, dated, illustrative, degraded, and unknown information. No detector, cryptographic, payment-settlement, wallet-signing, or frozen API contract was changed for presentation convenience. One checkout command-generation defect found during adversarial review was fixed so unvalidated x402 alternatives cannot reach the generated CLI command.

This work remains local. It was not deployed, pushed, published, or submitted.

## Audit scope

### Repository and product surfaces

The audit covered the static-site architecture, shared renderer, CSS and JavaScript system, FastAPI preview routing, generated documentation, marketplace renderer, public data files, SDK integration claims, security headers/CSP, tests, build scripts, and deployment documentation.

Public routes audited and redesigned:

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

The final generated tree contains 758 HTML pages:

- 15 hand-authored top-level pages
- 12 documentation pages
- 1 marketplace index
- 730 marketplace detail pages

Static inspection found zero pages missing a title, description, canonical URL, `<main>` landmark, or single `<h1>`. It also found zero duplicate titles.

### Live and competitor review

The live Warden routes, headers, public data endpoints, health behavior, evidence endpoints, and current copy were inspected over HTTP. Current product architecture and messaging were also reviewed on:

- `https://www.lakera.ai/`
- `https://www.lakera.ai/product/ai-agent-security`
- `https://www.paloaltonetworks.com/ai-security/prisma-airs`
- `https://www.paloaltonetworks.com/ai-security/agent-security`
- `https://www.paloaltonetworks.com/ai-security/ai-runtime-security`

The competitors informed grouping, lifecycle clarity, product visualization, proof structure, and conversion hierarchy. No competitor wording, layout, branding, imagery, code, or proprietary asset was copied.

Rendered viewport crawling was not possible because the connected browser backend was unavailable. The audit therefore does not claim screenshot-based visual verification.

## Main UX problems found

- The old top navigation treated commercial, experimental, evidence, and developer surfaces as peers, making the primary product journey difficult to identify.
- Route labels such as “Hire,” “Safety Index,” “Audit badges,” “Showcase,” and “Verify APA” required product knowledge before they made sense.
- Marketing copy sometimes collapsed distinct claims: verdict, risk, signature validity, freshness, endpoint state, and universal safety.
- Dynamic panels used ambiguous loading or checking language and could leave visitors unsure whether data was current, stale, absent, or merely not requested.
- The homepage had strong technical proof but lacked one disciplined sequence from unsafe output to gated action to durable evidence.
- Product tools, generated documentation, evidence pages, marketplace pages, and legal pages did not consistently share the same shell or information architecture.
- Endpoint audit records risked reading like certification; marketplace text matches risked reading like agent safety judgments.
- The integration route exposed real paths but did not lead with one exact, fail-closed implementation sequence.
- The Gauntlet needed stronger authorization, privacy, storage, consent, review-state, and “confirmed bypass” boundaries.
- Generated SEO artifacts were absent, while volatile marketplace detail IDs made a naïve static sitemap vulnerable to becoming stale.
- There was no browser E2E, Lighthouse, or screenshot pipeline in the repository.

## Final information architecture

### Product

- Overview
- Live Playground
- Attack Theater
- Use Warden

### Developers

- 5-Minute Quickstart
- Integrations
- Documentation

### Evidence

- Verify an Attestation
- Transparency Log
- Endpoint Audit Records
- Marketplace Evidence Index
- Service Status

### Research

- Gauntlet
- Methodology
- Product Tour

Persistent actions:

- Primary: Run live scan
- Secondary: Integrate
- Utility: Service status, initially and honestly marked unknown

The footer mirrors these four groups and adds Trust & Security, Privacy, Terms, and the verified marketplace identity link.

## Design concept

The implemented direction is “editorial cryptography meets an operational incident room.”

Three recurring objects organize the experience:

1. **Action boundary** — a visible interruption between untrusted output and execution.
2. **Verdict** — ALLOW, SANITIZE, and BLOCK as text, shape, icon, and semantic color states.
3. **Receipt** — an inspectable record that remains after an action is withheld or transformed.

The design uses a restrained neutral foundation, one gold brand signal, semantic verdict colors, editorial spacing, technical monospace details, lightweight SVG/CSS diagrams, tabular numerals, and explicit density differences between narrative, tools, docs, and registries. It preserves dark/light themes and reduced-motion behavior without introducing external fonts, video, WebGL, or third-party UI dependencies.

## Shared system

The redesign consolidates or establishes:

- Canonical generated `page_shell`
- Four-group desktop and mobile navigation
- Five-column footer
- SourceStamp
- EvidenceBoundary
- ActionBoundary diagrams
- Signed receipt and proof readouts
- Verdict and risk states
- Async loading/error/degraded patterns
- Status indicators
- Breadcrumbs
- Documentation sidebar and table of contents
- Filterable data tables and mobile result cards
- Copy controls and accessible live feedback
- Empty, error, degraded, retry, and reset states
- Shared layout, typography, surface, verdict, provenance, motion, focus, and responsive tokens

SourceStamp supports exactly:

- `LIVE`
- `DATED`
- `ILLUSTRATIVE`
- `DEGRADED`
- `UNKNOWN`

Each state has visible text and accessible explanatory copy; color is not the only signal.

## Route implementation

### Homepage

- Repositioned Warden as “Verifiable pre-action security for AI agents.”
- Leads with “Stop poisoned agent output before it becomes an action.”
- Added an explicit live-scan CTA, five-minute integration CTA, and attestation-verification path.
- Added four manually selectable, non-networked incident examples.
- Rebuilt the central live incident console with explicit activation, retry/reset, source state, check time, raw responses, downstream invocation receipt, and honest unsigned-demo evidence boundary.
- Added the complete action-boundary architecture and examples spanning payments, tools, links, and secrets.
- Integrated Scan, Attest, Verify, and Audit with “what it proves / does not prove” boundaries.
- Expanded local WebCrypto verification to expose key ID, freshness, browser check time, signature, chain, and one-byte tamper rejection.
- Added verified integration paths without inventing registry publication.
- Replaced broad competitor rhetoric with checkable Warden properties.
- Loads price, service, benchmark, marketplace, and evidence counts from versioned data sources rather than hardcoding them.
- Groups secondary surfaces into product, evidence, research, and marketplace intelligence.

### Product and research tools

- `/playground`: responsive two-panel workspace, curated attack classes, removable validated recipient context, exact verdict/reason/diff/raw output, bounded ALLOW copy, and explicit error/rate-limit/timeout states.
- `/theater`: manual Start/Pause/Next/Replay/Reset sequence across three attacks, evidence feed, no automatic production call, and reduced-motion equivalent.
- `/showcase`: Product Tour with six scenes, progress rail, sticky summary, keyboard navigation, and links into real product surfaces. Its live scan proves the verdict only; the page explicitly states that it does not invoke a wallet or produce a caller-side execution receipt.
- `/gauntlet`: authorization and consent boundaries, safe submission contract, private payload handling, submission/review/duplicate/confirmed states, honest counters, and no implied cash bounty.

### Commercial and developer routes

- `/hire`: renamed in the interface to “Use Warden,” rebuilt as a four-step reviewable x402 flow with a persistent order summary, current terms, price/asset/network/recipient validation, clear signing responsibility, safe shell quoting, and progressive command unlocks.
- `/integrate`: exact five-minute source-install path, action-boundary placement, Python, TypeScript, direct HTTP/x402, OnchainOS, LangChain, LlamaIndex, and MCP contracts that exist in the repository; includes typed three-decision handling, timeout/retry policy, fail-open/fail-closed guidance, payload privacy, secret handling, and wallet boundaries.
- `/docs`: persistent navigation, mobile-compatible structure, on-page contents, metadata, deep links, quickstart, concepts, decision contract, integrations, APA, transparency, endpoint audit, limits, troubleshooting, and a filterable reason-code reference.
- Reason pages now expose machine-readable values, real corpus examples, detector boundaries, false-positive considerations, and integration guidance.

### Evidence and operational routes

- `/badges`: reframed as Endpoint Audit Records with search, record state, issuer/subject/date/version/grade/integrity, raw inspection, verification action, and the point-in-time-not-certification boundary.
- `/verify`: supports pasted records/envelopes/identifiers/URLs, a real public sample, local file/drop input, key resolution, signature, freshness, subject, revocation/version errors, and progressive cryptographic detail.
- `/apa/log`: chain head, checkpoint, continuity visualization, timeline, raw JSON, local recomputation, one-byte tamper demonstration, and explicit broken/missing/stale/unavailable states.
- `/trust`: four distinct proof layers, each stating what it proves, what it does not, who can verify it, and where to inspect it.
- `/status`: separates live health, readiness objective, dated product evidence, benchmark snapshot, marketplace source, corpus/detector version, and payment boundary. It does not invent uptime history or present an objective as an SLA.
- `/agents`: reframed as Marketplace Evidence Index, with dated/degraded coverage, search, filters, APA/audit/public-text states, sort/reset, shareable filter parameters, responsive table/cards, detail pages, evidence links, and no malicious/safe labeling based on public text.

### Legal routes

- Privacy and Terms now use the same shell, breadcrumbs, table of contents, deep links, last-updated metadata, cross-links, comfortable reading width, and print semantics.

## Copy and evidence boundaries

Removed or avoided:

- “Provable safety”
- “No trust required”
- unsupported “first” claims
- universal ALLOW safety language
- certification language for endpoint snapshots
- malicious/safe labels inferred from listing text
- invented uptime, logos, testimonials, awards, certifications, comparisons, or customer proof

Implemented bounded alternatives:

- Verifiable enforcement
- Inspectable evidence
- Signed decision record
- Verify the signature locally
- Action withheld before execution
- No implemented detector fired; this is not a guarantee that the content is safe
- Point-in-time evidence, not certification
- Pattern match / no implemented pattern match / no public text / partial discovery

## Dynamic data and provenance

- Initial remote panels use stable dimensions and explicit “not requested,” “not established,” or unavailable language.
- No false zero or false success is rendered.
- Live requests require explicit user activation.
- Remote panels expose retry, reset, timestamp, rate-limit, timeout, malformed-response, and unavailable states as applicable.
- Raw responses are inspectable without upgrading them into claims.
- Product proof, evaluation, marketplace summary, service catalog, badge counts, and Gauntlet counts retain their source timestamps and schema checks.
- The current committed marketplace build is explicitly degraded: captured `2026-07-16T02:47:26Z`, sampled 730 of an expected 752, dropped 22, with 3 public-text signals and 0 linked signed endpoint audits.
- The static sitemap contains 28 stable canonical routes. Volatile `/agents/{id}` pages remain linked from the marketplace index but are not frozen into a sitemap that would become stale between index refreshes.
- Crawler files are written atomically with public-read permissions; `/agents` remains in the stable sitemap even before separately generated marketplace detail pages exist; obsolete generated docs are removed; custom docs builds do not mutate the repository site; and a supplied site root must own the marketplace output it indexes.

## Accessibility work

Implemented and statically verified:

- Skip links and landmark structure
- One logical `<h1>` per generated page
- Canonical accessible mobile navigation
- Keyboard navigation for menus, tabs, Product Tour, Theater, and recipient controls
- Focus return and Escape behavior for shared navigation
- Visible focus tokens
- Labels, descriptions, inline errors, and live regions
- Text plus shape/icon/state labels rather than color alone
- Shared initialization normalizes canonical and legacy SourceStamp markup into the same five-state, accessible contract
- 44px minimum interactive target rule
- Reduced-motion styles and non-autoplay interactions
- Static alternatives for animated narratives
- Accessible table semantics and mobile result cards
- Copy feedback through live status text
- Dark/light theme state support
- 360px responsive rules and horizontal-overflow regression contracts

Not verified because no browser backend was connected:

- Manual keyboard walkthrough
- Screen-reader walkthrough
- 200% zoom
- Actual 320–390px reflow
- Browser-computed contrast
- Automated axe run

No WCAG conformance claim or accessibility score is made beyond the implemented and tested static contracts.

## Performance work

- Retained the static-first multi-page architecture.
- Kept scripts same-origin and route-specific.
- Added no trackers, external fonts, videos, WebGL, chart framework, or animation dependency.
- Uses CSS and lightweight SVG for product storytelling.
- Prevents demo network requests on page load or viewport entry.
- Uses explicit activation and stable remote-data containers to reduce layout shift.
- Preserves CSP and cache-busted local assets.
- Final unminified asset sizes:
  - `site/styles.css`: 151,291 bytes
  - `site/app.js`: 35,060 bytes
  - top-level route JavaScript combined: 329,606 bytes; pages load only their relevant modules
  - social preview PNG: 80,891 bytes

Lighthouse and Core Web Vitals were not measured because rendered browser tooling was unavailable. No LCP, CLS, INP, Lighthouse performance, or Lighthouse accessibility score is claimed.

## Security-sensitive decisions

- No scanner, detector, cryptographic signature, key-history, transparency-chain, badge-verification, payment-settlement, wallet-signing, or frozen HTTP contract behavior was changed for the redesign.
- Browser demos fail closed when evidence is malformed, inconsistent, unavailable, or incomplete.
- The incident console does not call an action successful unless the live verdict and downstream receipt agree.
- Valid signatures remain separate from freshness, revocation, subject identity, issuer provenance, and endpoint safety.
- Generated commercial commands validate IDs, canonical endpoints, amount/asset/network/recipient terms, authorized target URLs, and quote untrusted shell arguments.
- The x402 payment command serializes only the acceptance entry that passed service, network, asset, amount, token, and recipient validation; unchecked alternatives from a challenge cannot reach the CLI command.
- Payment signing remains outside Warden and outside the browser.
- User-controlled values are rendered through text nodes rather than HTML interpolation.
- No pasted payload, secret, private submission, or wallet material was added to analytics.
- Marketplace text signals remain explicitly non-diagnostic.
- Gauntlet payloads are not made public without separate consent.
- The TypeScript compiler now explicitly lists the three SDK source files so the locked TypeScript 7 build works on OneDrive reparse-point files; no SDK runtime behavior changed.

## SEO and sharing

- Unique title and description per generated route
- Canonical URLs
- Open Graph and Twitter card metadata
- Current Warden action-boundary social image
- `robots.txt`
- Deterministic `sitemap.xml`
- Clean documentation and marketplace detail URLs
- Deep-linkable documentation, methodology, legal, and evidence sections
- No keyword stuffing or unsupported “best” claim

Static audit result across 758 HTML files:

- Missing title: 0
- Missing description: 0
- Missing canonical: 0
- Missing `<main>`: 0
- Incorrect `<h1>` count: 0
- Duplicate title: 0

## Build and test results

Passed:

- `python scripts/build_index.py`
  - 730 agents indexed
  - 3 public-text matches
  - 0 independently audited in the committed snapshot
- `python scripts/build_site.py`
  - 11 reason pages, docs index, APA spec, asset fingerprints, robots, and sitemap generated
- `python -m pytest -q`
  - 816 passed
  - 1 skipped
  - 1 existing Starlette/httpx deprecation warning
- `node --test tests/js/*.test.js`
  - 166 passed
- `python -m pytest -q sdk/python/tests`
  - 95 passed
- `npm test` in `sdk/ts`
  - 31 passed
- `npm run build` in `sdk/ts`
  - passed
- `npm pack --dry-run` in `sdk/ts`
  - passed; 18 package files, 14.6 kB tarball estimate
- `python spec/verify_apa.py --selftest`
  - passed genuine, tampered, and wrong-key cases
- Local clean-route preview
  - 42 route cases passed
- `ruff check .`
  - passed
- Ruff format check on all Python files changed by this redesign
  - passed
- `git diff --check` and staged diff check
  - passed

The repository-wide `ruff format --check scripts warden tests` still reports pre-existing formatting candidates outside the redesign scope. They were not mass-rewritten.

## Screenshots and Lighthouse

Baseline screenshots:

- Not captured; no connected browser backend was available.

Final screenshots:

- Not captured for the same reason.

Lighthouse:

- Not run.

This is an unresolved deliverable, not a claimed pass.

## Remaining limitations

1. Rendered desktop/tablet/mobile visual QA, screenshot comparison, Lighthouse, axe, keyboard, screen-reader, zoom, reduced-motion, slow-network, and console/hydration checks still require a connected browser.
2. The bundled reference attestation has a valid signature but is archival/expired. The UI reports that boundary; it is not current endpoint evidence.
3. The transparency chain has no published independent external anchor. A valid internal chain alone cannot expose every complete internally consistent rewrite.
4. Marketplace discovery is partial and dated. Its current committed snapshot dropped 22 expected results and links no signed endpoint audits.
5. Endpoint audit records remain point-in-time fixed-battery evidence. The previously documented evidence-model limitations are not silently upgraded into certification.
6. The live audit observed `/health` but not a separate `/health/ready` route. The redesigned status page therefore separates current health from a readiness objective rather than claiming a live readiness endpoint or SLA.
7. No genuine historical uptime series exists, so no uptime chart was invented.
8. The unminified CSS is 151 KB. Actual transfer size and render cost still need browser/network measurement before a performance target can be claimed.
9. No production deploy, VPS smoke test, live payment, wallet signature, or on-chain action was performed.

## Important changed files

Shared foundation:

- `warden/site_render.py`
- `site/styles.css`
- `site/app.js`
- `site/index.html`
- `site/home-examples.js`
- `site/incident-console.js`

Product and research:

- `site/playground.html`
- `site/playground.js`
- `site/theater.html`
- `site/theater.js`
- `site/showcase.html`
- `site/showcase.js`
- `site/gauntlet.html`
- `site/gauntlet.js`

Commerce, developer, and legal:

- `site/hire.html`
- `site/hire.js`
- `site/integrate.html`
- `site/integrate.js`
- `warden/site_docs.py`
- `site/privacy.html`
- `site/terms.html`

Evidence and operations:

- `site/badges.html`
- `site/badge.html`
- `site/badge.js`
- `site/verify.html`
- `site/verify.js`
- `site/log.html`
- `site/log.js`
- `site/trust.html`
- `site/status.html`
- `site/status.js`
- `warden/marketplace/render.py`
- `site/agents.js`

SEO and build:

- `warden/sitemap.py`
- `scripts/build_site.py`
- `scripts/build_index.py`
- `site/robots.txt`
- `site/sitemap.xml`
- `sdk/ts/tsconfig.json`

Targeted regression coverage was expanded across `tests/test_site.py`, `tests/test_preview.py`, `tests/test_marketplace.py`, `tests/test_sitemap.py`, `tests/test_redesign_contract.py`, and the route-specific `tests/js` suites.
