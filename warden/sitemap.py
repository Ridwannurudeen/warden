"""Generate crawler files from Warden's canonical public HTML routes."""

from __future__ import annotations

import os
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from xml.sax.saxutils import escape

PUBLIC_ORIGIN = "https://warden.gudman.xyz"
PUBLIC_TOP_LEVEL_ROUTES = {
    "badge.html": "/badge",
    "badges.html": "/badges",
    "gauntlet.html": "/gauntlet",
    "hire.html": "/hire",
    "index.html": "/",
    "integrate.html": "/integrate",
    "log.html": "/apa/log",
    "playground.html": "/playground",
    "privacy.html": "/privacy",
    "showcase.html": "/showcase",
    "status.html": "/status",
    "terms.html": "/terms",
    "theater.html": "/theater",
    "trust.html": "/trust",
    "verify.html": "/verify",
}
_DOC_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class _CanonicalLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "link":
            return
        attributes = dict(attrs)
        rel = (attributes.get("rel") or "").lower().split()
        href = attributes.get("href")
        if "canonical" in rel and href is not None:
            self.hrefs.append(href)


def _validate_canonical(page: Path, route: str) -> None:
    parser = _CanonicalLinkParser()
    parser.feed(page.read_text(encoding="utf-8"))
    expected = f"{PUBLIC_ORIGIN}{route}"
    if parser.hrefs != [expected]:
        raise RuntimeError(
            f"{page} must contain exactly one canonical link for {expected}; found {parser.hrefs!r}"
        )


def discover_public_routes(site_root: Path) -> tuple[str, ...]:
    """Return validated canonical routes present in one complete static site tree."""
    routes: set[str] = set()
    for filename, route in PUBLIC_TOP_LEVEL_ROUTES.items():
        page = site_root / filename
        if not page.is_file():
            raise RuntimeError(f"tracked public page is missing: {page}")
        _validate_canonical(page, route)
        routes.add(route)

    docs_root = site_root / "docs"
    if not (docs_root / "index.html").is_file():
        raise RuntimeError(f"documentation index is missing: {docs_root / 'index.html'}")
    for page in sorted(docs_root.glob("*.html")):
        if page.name == "index.html":
            route = "/docs"
        elif _DOC_SLUG.fullmatch(page.stem):
            route = f"/docs/{page.stem}"
        else:
            continue
        _validate_canonical(page, route)
        routes.add(route)

    routes.add("/agents")
    agents_root = site_root / "agents"
    if agents_root.exists():
        index_page = agents_root / "index.html"
        if not index_page.is_file():
            raise RuntimeError(f"marketplace index is missing: {index_page}")
        _validate_canonical(index_page, "/agents")
        routes.add("/agents")

    return tuple(sorted(routes, key=lambda route: (route != "/", route)))


def render_sitemap(routes: tuple[str, ...]) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    lines.extend(f"  <url><loc>{escape(f'{PUBLIC_ORIGIN}{route}')}</loc></url>" for route in routes)
    lines.append("</urlset>")
    return "\n".join(lines) + "\n"


def _write_text_atomic(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def write_crawler_files(site_root: Path) -> tuple[str, ...]:
    """Write deterministic sitemap and robots files for a complete static site tree."""
    routes = discover_public_routes(site_root)
    _write_text_atomic(site_root / "sitemap.xml", render_sitemap(routes))
    _write_text_atomic(
        site_root / "robots.txt",
        f"User-agent: *\nAllow: /\n\nSitemap: {PUBLIC_ORIGIN}/sitemap.xml\n",
    )
    return routes
