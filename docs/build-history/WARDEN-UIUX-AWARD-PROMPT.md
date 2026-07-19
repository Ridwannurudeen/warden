# GPT-5.6 (Codex) task — turn warden.gudman.xyz into an award-winning UI/UX

You are redesigning the **entire** UI/UX of Warden's website to an Awwwards / enterprise-flagship standard that stands next to — and beats on distinctiveness — https://www.lakera.ai/ and https://www.paloaltonetworks.com/ai-security/prisma-airs. Work autonomously in the repo `warden` (static site under `site/`, generated-page templates under `warden/`). This is a design overhaul, not a rewrite of the product.

## What Warden is (so the design tells the truth)
Warden is a **payload firewall for AI agents**, live and paid on OKX. It screens untrusted agent input for prompt injection, wallet-drain address swaps, tool hijacks, and secret exfiltration → **ALLOW / SANITIZE / BLOCK** in under a second, and **cryptographically signs every verdict** (APA: Ed25519 attestations + a hash-chained transparency log + an in-browser WebCrypto verifier). The ONE thing no competitor ships: **a verdict you can verify yourself, not one you're told to trust.** Design must lead with that.

## The bar: what makes it award-winning (not just "clean")
Study Lakera and Palo Alto, then EXCEED them on art direction and interaction, because we can't beat their content/customer library — we beat them on a singular, confident, memorable experience:
1. **A signature hero moment** — the first screen must be arresting and unmistakably Warden: dramatic dark-first art direction, a live/animated product visual (use the real incident console or the signed-attestation receipt), purposeful entrance motion. Not a text block with a static card.
2. **Motion & interaction design** — scroll-choreographed reveals, tasteful parallax/depth, hover/press micro-interactions (150–300ms, spring/ease-out), a live "verdict" animation. Everything gated behind `prefers-reduced-motion`.
3. **A cohesive, deepened design system** — refine the existing 85 CSS tokens into a rigorous scale (type ramp, 8pt spacing, elevation, radius, motion tokens, a gold-on-obsidian gradient language). Consistent components across all 15 pages.
4. **Distinctive typography** — the site already ships Fraunces (display serif) + Plus Jakarta Sans + mono, self-hosted in `/fonts/`. Use them with confident scale/rhythm; the serif display is your signature — lean into it.
5. **Signature visual motifs** — a recurring "attestation receipt / hash-chain / verdict boundary" visual language rendered as inline SVG/CSS (self-contained), used across hero, sections, and diagrams, so the brand feels designed, not templated.
6. **Dark-first drama** — the brand is obsidian (`#090a0a`/`#0b0c0b`) + gold (`#d7aa49`) + danger red. Consider making **dark the default** hero experience (more striking, like Lakera's navy) while keeping the polished light theme fully working. Both themes must be first-class.

## Scope — EVERY component, every page
- **Homepage** (`site/index.html`) — the flagship. Hero, stat band, capability cards (Scan·Attest·Verify·Audit), the live incident console, the offline WebCrypto verify-yourself block, the honest comparison table, proof band, integration, footer. Elevate all of it into one choreographed scroll.
- **All 15 static pages** consistently: index, playground, hire, docs (`integrate.html`), verify, log, status, agents, gauntlet, showcase, badges, theater, trust, privacy, terms. Each must feel like the same premium product, with page-specific hero treatments (not clones).
- **Generated pages** — the per-agent pages (`site/agents/*`) and docs shells come from templates in `warden/site_render.py`, `warden/site_docs.py`, `warden/marketplace/render.py`, `scripts/build_index.py`. Update those templates so generated pages inherit the new nav, footer, tokens, and favicon — the whole site must be uniform (this is currently the weakest gap).
- **Global chrome** — nav (already slimmed to Product / Developers / Evidence + footer utilities; keep that IA), footer, theme toggle, favicons/OG, loading/empty/error states.

## HARD CONSTRAINTS (non-negotiable)
- **Self-contained** — ZERO external resource requests. Self-host all fonts (already in `/fonts/`), inline all SVG/icons, embed any images as local assets or data URIs. No CDN, Google Fonts, remote images, analytics. The test `tests/test_ph1_product_experience.py::test_homepage_runtime_resources_remain_same_origin` MUST stay green; keep every page same-origin.
- **Honesty** — award-winning ≠ fabricated credibility. NO fake customer logos, testimonials, analyst/Gartner badges, or invented statistics. Every number must come from `site/data/product-proof.json` and `site/data/evaluation.json` (currently: 71.43% held-out recall, 0% false positives, 0.23ms p50, 124-case corpus, 15 sold, 4.8/5 from 5 reviews, 0.5 USD₮0). If you can't source a stat, omit it. Keep the honest "Illustrative receipt" labeling on any mockup.
- **Don't touch the product** — no changes to any `warden/*.py` scanner/API/engine logic or the frozen `/scan` `/audit` contract. You may only edit the **presentation** templates listed above (site_render/site_docs/marketplace.render/build_index HTML output) — not detection, payments, or crypto logic.
- **Keep tests green** — `python -m pytest tests/test_ph1_product_experience.py tests/test_site.py tests/test_preview.py -q` must pass. If new true copy legitimately changes an asserted string, update the assertion to the new true value; never weaken what it checks. Run the full `pytest -q` and `node --test tests/js/*.test.js` too.
- **Preserve behavior** — the incident console, offline WebCrypto verify + one-byte tamper, playground scan, theme toggle, and all data-bound numbers must keep working. Only re-skin and re-motion them; don't break the JS contracts.
- **Cache-busting** — keep the `build_site.py` content-hash `?v=` versioning on `styles.css`/`app.js`.
- **Accessibility (WCAG AA)** — 4.5:1 contrast in BOTH themes, visible focus rings, 44px touch targets, semantic landmarks/headings, aria on icons/dropdowns/live regions, full keyboard nav, `prefers-reduced-motion` honored everywhere.
- **Responsive & performant** — flawless at 360 / 390 / 768 / 1024 / 1440 / 2560; ZERO horizontal overflow at any width (audit fixed px widths and decorative glows); wide content scrolls inside its own container. Keep CSS/JS lean; lazy-load below-the-fold heavy visuals; no layout shift (CLS).
- **No AI/Codex/Anthropic attribution** anywhere; no Co-Authored-By.

## Method (follow in order)
1. **Audit** every page and the token system; write a short design-direction note (art direction, motion language, signature motif, type/color system) before coding.
2. **Build the design system first** (tokens, primitives, motion utilities, components) so all pages inherit it.
3. **Redesign the homepage** as the flagship; get it award-tier.
4. **Cascade** to all 15 static pages with page-specific hero treatments.
5. **Update the generated-page templates** so `site/agents/*` and docs match.
6. **Add the motion layer** (scroll reveals, micro-interactions, hero animation), reduced-motion-gated.
7. **QA pass** — accessibility, responsive, performance, self-containment.

## Self-verification BEFORE you finish (required — report real results)
- `python -m pytest tests/test_ph1_product_experience.py tests/test_site.py tests/test_preview.py -q` and full `python -m pytest -q` → report counts; `node --test tests/js/*.test.js`; `ruff check .` if you touched Python templates.
- `python scripts/build_site.py` → clean, versioned asset URLs emitted.
- Render with headless Chrome at **2560, 1440, 768, and 390** (both light AND dark theme) for the homepage + at least playground, verify, agents, docs — confirm: no horizontal overflow at any width, hero animation/visual present, theme toggle works, all numbers populate (no stuck "Loading"). Save screenshots and report their paths.
- Grep every page for external URLs — there must be none beyond same-origin + spec identifiers.
- Verify og.png + favicons still resolve and reflect the new design.

## Deliverables
A redesigned, award-tier, fully self-contained, accessible, responsive site across every page + generated templates, with all tests green, plus a written report: the design-direction note, per-page what changed, the token/motion system, the verification results (test counts + screenshot paths), and anything intentionally omitted for honesty. Commit incrementally with clear no-attribution messages.

Do not report success for anything you did not actually verify. If a change would break the frozen backend, a test's real assertion, self-containment, or honesty, stop and flag it instead of forcing it.
