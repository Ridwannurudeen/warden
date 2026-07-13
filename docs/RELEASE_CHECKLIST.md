# Warden frontend release checklist

This checklist stages validation only. Deployment, DNS changes, paid tasks, reviews, social posts, and
hackathon submission require explicit user approval.

## Code and contracts

- [x] `python -m pytest -q` passes.
- [x] `python -m ruff check .` passes.
- [x] `node --test tests/js/*.test.js` passes.
- [x] Every `site/*.js` file passes `node --check`.
- [x] `python scripts/build_site.py` regenerates all 11 reason pages plus the docs index.
- [x] `python scripts/build_index.py` regenerates the committed marketplace snapshot without refresh.
- [x] `git diff --check` passes.
- [x] `/scan`, `/audit`, badge, demo, Gauntlet, and health request/response contracts are unchanged.
- [x] Nginx still has explicit clean routes, no SPA fallback, and the self-only CSP.

## Accessibility and interaction

- [x] Skip links target the main landmark on every audited route.
- [ ] Header, grouped navigation, theme, forms, tabs, disclosures, copy buttons, and showcase controls
      work with keyboard only.
- [ ] Mobile navigation traps focus, closes on Escape/outside interaction, and restores focus.
- [x] Heading references and form labels are present and valid on every generated and hand-authored route.
- [x] Dynamic results use restrained live regions; no decorative container is announced.
- [x] ALLOW, SANITIZE, BLOCK, health, and verification states include text—not color alone.
- [ ] Both themes meet WCAG 2.2 AA contrast; visible focus remains clear.
- [ ] At 200% zoom, controls remain reachable and content does not overlap.
- [x] Reduced-motion CSS suppresses transitions and showcase auto-advance is disabled by script.

## Responsive and visual review

- [ ] Review `/`, `/playground`, `/agents`, `/gauntlet`, `/hire`, `/docs`, `/integrate`, `/badges`,
      `/status`, `/privacy`, `/terms`, and `/showcase` at 360, 390, 768, 1024, 1440, and 1920px.
- [ ] Verify long payloads, addresses, reason codes, service names, and code blocks wrap or scroll.
- [ ] Marketplace rows become readable mobile cards rather than clipped tables.
- [x] Loading, empty, error, rate-limit, malformed-response, duplicate, candidate, invalid-signature,
      and offline states have deliberate layouts.
- [ ] Capture approved desktop and mobile screenshots into `docs/screenshots/` and record their route,
      viewport, theme, and commit.

## Performance and browser quality

- [ ] Production pages have no console errors, unhandled rejections, or failed local assets.
- [x] Source/resource inspection shows no auto-loaded third-party fonts, scripts, images, embeds, or trackers.
- [ ] Homepage and Playground Lighthouse runs target 95+ for Performance, Accessibility, Best
      Practices, and SEO when a supported browser is available.
- [ ] Representative LCP is ≤2.5s, INP ≤200ms, and CLS ≤0.1 under meaningful local conditions.
- [x] Layout reserves space for asynchronous status, marketplace, badge, and result content.
- [x] Page behavior remains useful when JavaScript data refresh fails and dated fallbacks are labeled.

## Content, evidence, and data freshness

- [x] Marketplace count and timestamp match `site/data/marketplace-summary.json`.
- [x] Service IDs, prices, token, network, and endpoints match `site/data/warden-services.json` and a
      freshly inspected live x402 challenge.
- [x] Agent #3808 listing state was re-verified for this local build; re-check again before publication.
- [x] Public listing-text signals are never described as endpoint compromise or safety proof.
- [x] Badge copy says point-in-time signed evidence, not certification or permanent safety.
- [x] Gauntlet ALLOW results remain candidates until human confirmation.
- [x] Status separates current reachability from dated repository and marketplace metadata.
- [x] Privacy and Terms retain Gauntlet retention, authorization, payment, badge, independence, and
      no-tracker boundaries.
- [x] No fabricated orders, reviews, customers, uptime, badges, attempts, receipts, or endorsements.

## Unavailable local checks

The in-app browser reported no attached session on 2026-07-13. Keyboard-only manual review,
viewport/zoom review, axe, console/network capture, Lighthouse, Core Web Vitals, and current screenshots
remain unchecked above. `nginx -t` must run on an environment with Nginx installed. Do not convert any
of those unchecked items to passed based only on source inspection.

## Launch authorization

- [ ] The exact tested commit is recorded.
- [ ] `nginx -t` passes on the target environment.
- [ ] Rollback procedure and previous site artifact are known.
- [ ] User explicitly approves deployment before any VPS change.
- [ ] User explicitly approves any X post, paid task, review, hackathon form, or other submission.
