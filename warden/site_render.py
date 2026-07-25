"""Shared HTML shell for generated Warden site pages."""

from __future__ import annotations

import html
from collections.abc import Sequence


NAV_GROUPS = (
    (
        "Product",
        (
            ("/", "Overview", "overview"),
            ("/playground", "Live playground", "playground"),
            ("/theater", "Incident replay", "theater"),
            ("/hire", "Use Warden", "hire"),
        ),
    ),
    (
        "Developers",
        (
            ("/integrate#sdk-first", "5-minute quickstart", "integrate-quickstart"),
            ("/integrate", "Integration guide", "integrate"),
            ("/docs", "Documentation", "docs"),
        ),
    ),
    (
        "Evidence",
        (
            ("/verify", "Verify an attestation", "verify"),
            ("/apa/log", "Transparency log", "apa-log"),
            ("/badges", "Endpoint audit records", "badges"),
            ("/lineage", "Audit evidence lineage", "lineage"),
            ("/agents", "Marketplace evidence index", "agents"),
            ("/status", "Service status", "status"),
        ),
    ),
    (
        "Research",
        (
            ("/gauntlet", "Gauntlet", "gauntlet"),
            ("/agents#methodology", "Methodology", "agents-methodology"),
            ("/showcase", "Product tour", "showcase"),
        ),
    ),
)

PRIMARY_NAV = (
    ("/", "Product", ("overview", "theater", "hire")),
    ("/playground", "Playground", ("playground",)),
    ("/integrate", "Developers", ("integrate", "integrate-quickstart")),
    ("/docs", "Docs", ("docs",)),
    ("/verify", "Evidence", ("verify", "apa-log", "badges", "lineage", "agents", "status")),
    ("/gauntlet", "Research", ("gauntlet", "agents-methodology", "showcase")),
)


def _render_navigation(active: str, canonical_path: str) -> str:
    links = []
    for href, label, active_keys in PRIMARY_NAV:
        classes = ["nav-link"]
        current = ""
        if canonical_path == href:
            current = ' aria-current="page"'
        elif active in active_keys:
            classes.append("is-active-section")
        links.append(f'<a class="{" ".join(classes)}" href="{href}"{current}>{label}</a>')
    return "".join(links)


def page_shell(
    title: str,
    description: str,
    body: str,
    *,
    active: str = "",
    scripts: Sequence[str] = (),
    body_class: str = "",
    canonical_path: str | None = None,
) -> str:
    canonical = canonical_path or (f"/{active}" if active else "/")
    if not canonical.startswith("/") or canonical.startswith("//"):
        raise ValueError("canonical_path must be an absolute site path")
    canonical_url = f"https://warden.gudman.xyz{canonical}"
    script_tags = [
        '<script src="/app.js" defer></script>',
        *(
            f'<script src="/{html.escape(script, quote=True)}" defer></script>'
            for script in scripts
        ),
    ]
    class_attribute = f' class="{html.escape(body_class, quote=True)}"' if body_class else ""
    footer_groups = []
    for group_name, items in NAV_GROUPS:
        links = "".join(f'<a href="{href}">{label}</a>' for href, label, _ in items)
        footer_groups.append(
            '<div class="site-footer__col">'
            f'<span class="site-footer__label">{group_name}</span>'
            f"{links}"
            "</div>"
        )
    footer_groups.append(
        '<div class="site-footer__col">'
        '<span class="site-footer__label">Policy</span>'
        '<a href="/trust">Trust &amp; security</a>'
        '<a href="/privacy">Privacy</a>'
        '<a href="/terms">Terms</a>'
        "</div>"
    )
    footer_navigation = "".join(footer_groups)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="{html.escape(description, quote=True)}">
    <meta name="color-scheme" content="dark light">
    <title>{html.escape(title)}</title>
    <link rel="canonical" href="{html.escape(canonical_url, quote=True)}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="Warden">
    <meta property="og:title" content="{html.escape(title, quote=True)}">
    <meta property="og:description" content="{html.escape(description, quote=True)}">
    <meta property="og:url" content="{html.escape(canonical_url, quote=True)}">
    <meta property="og:image" content="https://warden.gudman.xyz/assets/warden-social-card.png">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:image" content="https://warden.gudman.xyz/assets/warden-social-card.png">
    <link rel="icon" href="/assets/warden-mark.svg">
    <script src="/theme.js"></script>
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body{class_attribute}>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header class="site-header page-shell">
      <a class="brand" href="/" aria-label="Warden home"><img src="/assets/warden-mark.svg" alt="" width="32" height="32"><span>Warden</span></a>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="primary-nav" data-nav-toggle>Menu</button>
      <nav class="site-nav" id="primary-nav" aria-label="Primary" data-site-nav>{_render_navigation(active, canonical)}<div class="nav-mobile-actions"><a class="button secondary" href="/integrate">Integrate</a><a class="button primary" href="/playground">Run a live scan</a></div></nav>
      <div class="header-actions">
        <a class="status-pill" href="/status" aria-label="Service status: unknown" data-health-state="unknown"><span class="live-dot is-unknown" data-health-dot aria-hidden="true"></span><span data-health-label>Status unknown</span></a>
        <a class="header-integrate" href="/integrate">Integrate</a>
        <a class="header-scan" href="/playground">Run a live scan</a>
        <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch color theme">Theme</button>
      </div>
    </header>
    <main id="main" class="page-shell site-main">{body}</main>
    <footer class="site-footer page-shell">
      <div><strong>Warden</strong><span>Pre-action security for agent systems.</span></div>
      <nav aria-label="Footer">{footer_navigation}</nav>
    </footer>
    {"".join(script_tags)}
  </body>
</html>
"""
