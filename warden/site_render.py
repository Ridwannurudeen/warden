"""Shared HTML shell for generated Warden site pages."""

from __future__ import annotations

import html
from collections.abc import Sequence


NAV_GROUPS = (
    (
        "Product",
        (
            ("/theater", "Attack Theater", "theater"),
            ("/playground", "Playground", "playground"),
            ("/agents", "Marketplace index", "agents"),
            ("/gauntlet", "Gauntlet", "gauntlet"),
            ("/showcase", "Walkthrough", "showcase"),
        ),
    ),
    (
        "Developers",
        (
            ("/docs", "Documentation", "docs"),
            ("/integrate", "Integrate", "integrate"),
            ("/trust", "Trust Layer", "trust"),
            ("/status", "API status", "status"),
        ),
    ),
    (
        "Evidence",
        (
            ("/verify", "Verify APA", "verify"),
            ("/apa/log", "Transparency log", "apa-log"),
            ("/badges", "Audit badges", "badges"),
            ("/agents#methodology", "Public-text methodology", "agents-methodology"),
            ("/gauntlet#policy", "Adversarial challenge", "gauntlet-policy"),
        ),
    ),
)


def _render_navigation(active: str) -> str:
    groups = []
    for group_name, items in NAV_GROUPS:
        contains_current = any(key == active for _, _, key in items)
        links = []
        for href, label, key in items:
            current = ' aria-current="page"' if key == active else ""
            links.append(f'<a href="{href}"{current}>{label}</a>')
        current_class = " has-current" if contains_current else ""
        groups.append(
            f'<details class="nav-group{current_class}">'
            f"<summary>{group_name}</summary>"
            f'<div class="nav-menu">{"".join(links)}</div>'
            "</details>"
        )
    return "".join(groups)


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
    <link rel="icon" href="/assets/warden-avatar.png">
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body{class_attribute}>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header class="site-header page-shell">
      <a class="brand" href="/" aria-label="Warden home"><img src="/assets/warden-avatar.png" alt="" width="36" height="36"><span>Warden</span></a>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="primary-nav" data-nav-toggle>Menu</button>
      <nav class="site-nav" id="primary-nav" aria-label="Primary" data-site-nav>{_render_navigation(active)}<div class="nav-mobile-actions"><a class="button secondary" href="/hire">Hire on OKX.AI</a><a class="button primary" href="/playground">Run a live scan</a></div></nav>
      <div class="header-actions">
        <a class="status-pill" href="/status" aria-label="Open API status"><span class="live-dot" data-health-dot aria-hidden="true"></span><span data-health-label>Checking API</span></a>
        <a class="header-hire" href="/hire">Hire</a>
        <a class="header-scan" href="/playground">Run scan</a>
        <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch color theme">Theme</button>
      </div>
    </header>
    <main id="main" class="page-shell site-main">{body}</main>
    <footer class="site-footer page-shell">
      <div><strong>Warden</strong><span>The immune system of the agent economy.</span><span>Independent service listed on OKX.AI.</span></div>
      <nav aria-label="Footer"><a href="/theater">Attack Theater</a><a href="/playground">Run a scan</a><a href="/showcase">Showcase</a><a href="/docs">Docs</a><a href="/badges">Evidence</a><a href="/status">Status</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="https://www.okx.ai/" rel="noreferrer">Agent #3808</a></nav>
    </footer>
    {"".join(script_tags)}
  </body>
</html>
"""
