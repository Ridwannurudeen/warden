"""Shared HTML shell for generated Warden site pages."""

from __future__ import annotations

import html
from collections.abc import Sequence


NAV_ITEMS = (
    ("/playground", "Playground", "playground"),
    ("/agents", "Agents", "agents"),
    ("/gauntlet", "Gauntlet", "gauntlet"),
    ("/hire", "Hire", "hire"),
    ("/docs", "Docs", "docs"),
    ("/integrate", "Integrate", "integrate"),
    ("/badges", "Badges", "badges"),
)


def page_shell(
    title: str,
    description: str,
    body: str,
    *,
    active: str = "",
    scripts: Sequence[str] = (),
    body_class: str = "",
) -> str:
    nav = []
    for href, label, key in NAV_ITEMS:
        current = ' aria-current="page"' if key == active else ""
        nav.append(f'<a href="{href}"{current}>{label}</a>')
    script_tags = [
        '<script src="/app.js" defer></script>',
        *(f'<script src="/{html.escape(script, quote=True)}" defer></script>' for script in scripts),
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
    <link rel="icon" href="/assets/warden-avatar.png">
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body{class_attribute}>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header class="site-header page-shell">
      <a class="brand" href="/" aria-label="Warden home"><img src="/assets/warden-avatar.png" alt="" width="36" height="36"><span>Warden</span></a>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="primary-nav" data-nav-toggle>Menu</button>
      <nav class="site-nav" id="primary-nav" aria-label="Primary" data-site-nav>{"".join(nav)}</nav>
      <div class="header-actions">
        <a class="status-pill" href="/status"><span class="live-dot" data-health-dot aria-hidden="true"></span><span data-health-label>API status</span></a>
        <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch color theme">Theme</button>
      </div>
    </header>
    <main id="main" class="page-shell site-main">{body}</main>
    <footer class="site-footer page-shell">
      <div><strong>Warden</strong><span>Deterministic security before autonomous action.</span></div>
      <nav aria-label="Footer"><a href="/status">Status</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="https://www.okx.ai/" rel="noreferrer">Agent #3808</a></nav>
    </footer>
    {"".join(script_tags)}
  </body>
</html>
"""
