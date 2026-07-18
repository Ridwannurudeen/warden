# Warden frontend release checklist

This checklist stages validation only. Deployment, DNS changes, paid tasks, reviews, social posts,
and hackathon submission require explicit user approval.

## Code and contracts

- [x] `python -m pytest -q` passes for the recorded working tree.
- [x] `python -m ruff check .` passes.
- [x] `node --test tests/js/*.test.js` passes.
- [x] `cd sdk/ts && npm ci && npm test && npm run build` passes from the committed lockfile.
- [x] Every `site/*.js` file passes `node --check`.
- [x] `python scripts/build_site.py` regenerates the reason-code docs and publishes
      `spec/APA-SPEC.md` byte-identically at `site/spec/APA-SPEC.md`.
- [x] `python scripts/build_index.py` regenerates the committed marketplace snapshot without refresh.
- [x] `python -m pytest -q tests/test_marketplace.py tests/test_refresh_safety_index.py tests/test_deploy_index.py`
      verifies schema-v2 coverage, atomic promotion, and the 30-minute source units.
- [x] The committed Safety Index reports exact `sampled`, `expected`, and `dropped` counts for discovery query
      `a`; equality means a complete response for that query, while a mismatch renders partial/degraded
      without attributing a cause.
- [x] `scripts/refresh_safety_index.py` stages, validates, and atomically promotes a candidate release before
      switching `current`.
- [x] `git diff --check` passes.
- [x] `/scan`, `/audit`, `/api/demo/scan`, `/health`, and legacy `/badge/*` behavior is unchanged;
      `/api/demo/theater` is additive and uses the same real fast-path verdict engine.
- [x] APA routes retain their canonical contracts: `/.well-known/agent-protection`,
      `/.well-known/apa-issuer.json`, `/apa/register`, `/apa/attestation/{id}`,
      `/apa/attestation/{id}/badge.svg`, `/apa/log`, and `/apa/revoke`.
- [x] Nginx retains explicit clean routes, no SPA fallback, and the self-only CSP.

## Accessibility and interaction

- [x] Skip links target the main landmark on every audited route.
- [x] Automated contrast contracts cover both the light-default and explicit dark token sets without
      lowering WCAG thresholds.
- [ ] Header, grouped navigation, theme, forms, tabs, disclosures, copy buttons, Theater controls,
      and verifier controls work with keyboard only.
- [ ] Mobile navigation traps focus, closes on Escape/outside interaction, and restores focus.
- [x] Heading references and form labels are present and valid on generated and hand-authored routes.
- [x] Dynamic results use restrained live regions; no decorative container is announced.
- [x] ALLOW, SANITIZE, BLOCK, health, APA status, and verification states include text, not color alone.
- [ ] Both themes receive a manual WCAG 2.2 AA review; visible focus remains clear.
- [ ] At 200% zoom, controls remain reachable and content does not overlap.
- [x] Reduced-motion CSS suppresses motion and Attack Theater disables autoplay when requested.

## Responsive and visual review

- [ ] Review `/`, `/theater`, `/trust`, `/verify`, `/apa/log`, `/playground`, `/agents`, `/gauntlet`,
      `/hire`, `/docs`, `/integrate`, `/badges`, `/status`, `/privacy`, `/terms`, and `/showcase` at
      360, 390, 768, 1024, 1440, and 1920px.
- [ ] Verify long payloads, endpoint hosts, attestation IDs, reason codes, service names, and code blocks
      wrap or scroll.
- [ ] Verify the `/theater` one-pass counter advances only on accepted live verdict-and-receipt
      responses and that errors or malformed receipts stay stopped and visible.
- [ ] Verify `/verify` shows clear valid, invalid, stale, key-changed, revoked, and request-error states.
- [ ] Verify `/apa/log` renders real entries or an honest empty state; never seed display-only events.
- [ ] Marketplace rows become readable mobile cards rather than clipped tables.
- [ ] Capture approved desktop and mobile screenshots into `docs/screenshots/` and record their route,
      viewport, theme, and commit.

## Performance and browser quality

- [ ] Production pages have no console errors, unhandled rejections, or failed local assets.
- [x] Source inspection shows no auto-loaded third-party fonts, scripts, images, embeds, or trackers.
- [ ] Homepage and Attack Theater Lighthouse runs target 95+ for Performance, Accessibility, Best
      Practices, and SEO in a supported browser.
- [ ] Representative LCP is <=2.5s, INP <=200ms, and CLS <=0.1 under meaningful local conditions.
- [x] Layout reserves space for asynchronous status, marketplace, badge, Theater, and result content.
- [x] Request errors and malformed responses remain explicit rather than becoming success states.

## Content, evidence, and data freshness

- [x] The homepage leads with the immune-system metaphor, the live demo, and the open standard.
- [x] `/trust` keeps local enforcement, APA proof, and the Safety Map as distinct pillars.
- [x] Free hosted SDK copy says `fail_open=True`, 20 requests/minute per IP, forced fast depth, and a
      4,000-character truncation; it is labeled best-effort telemetry, not enforcement.
- [x] Local SDK copy uses `WardenClient(local=True, fail_open=False)` for enforcement.
- [x] APA copy says a fresh attestation proves endpoint-key control, live guard state, and a signed
      rolling 24-hour count or an explicit unavailable state; it does not claim every request traversed the guard or independently audit
      the endpoint owner's counter state.
- [x] APA badges use issued IDs only; no fabricated badge or attestation identifier appears.
- [x] Marketplace counts and timestamps match committed data and are not described as endpoint safety.
- [x] TypeScript integration copy says `sdk/ts` is source-built, not claimed published, defaults to best-effort
      hosted `failOpen: true`, and has no local TypeScript engine.
- [x] Safety Index copy describes schema-v2 `sampled`/`expected`/`dropped` coverage and labels the atomic
      30-minute timer source-ready but not deployed.
- [x] No fabricated orders, reviews, customers, uptime, badges, attempts, receipts, or endorsements.

## Manual checks still required

No browser or device review is recorded for this working tree. Keyboard-only review, viewport and zoom
review, axe, console/network capture, Lighthouse, Core Web Vitals, and current screenshots remain unchecked
above. The Nginx and systemd commands below must run on the target VPS. Do not convert those items to passed
from source inspection or automated unit tests alone.

## Launch authorization

- [ ] The exact tested commit is recorded.
- [ ] User explicitly approves deployment before any VPS change.
- [ ] `nginx -t` passes on the target environment.
- [ ] `/opt/warden/.venv/bin/python scripts/refresh_safety_index.py --index-root /opt/warden-index --from-committed-snapshot`
      seeds the first validated release on the target VPS.
- [ ] `test -L /opt/warden-index/current` confirms the atomic `current` release link after seeding.
- [ ] `systemctl start warden-index.service` completes one live query-`a` refresh before timer activation.
- [ ] `systemd-analyze verify /etc/systemd/system/warden-index.service /etc/systemd/system/warden-index.timer`
      passes on the target VPS.
- [ ] `systemd-analyze calendar '*-*-* *:00/30:00 UTC'` confirms the intended 30-minute schedule.
- [ ] `systemctl list-timers warden-index.timer --all` shows the installed timer and its next run.
- [ ] `journalctl -u warden-index.service -n 100 --no-pager` shows a successful atomic capture or an explicit
      failure without replacing `current`.
- [ ] Rollback procedure and previous site artifact are known.
- [ ] User explicitly approves any X post, paid task, review, hackathon form, or other submission.
