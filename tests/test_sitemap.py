"""Deterministic crawler-artifact tests."""

from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from scripts import build_index, build_site
from warden import sitemap as sitemap_module
from warden.site_docs import render_docs
from warden.sitemap import (
    PUBLIC_ORIGIN,
    PUBLIC_TOP_LEVEL_ROUTES,
    discover_public_routes,
    write_crawler_files,
)


def _write_page(path: Path, route: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'<html><head><link rel="canonical" href="{PUBLIC_ORIGIN}{route}"></head></html>',
        encoding="utf-8",
    )


def _complete_site(site_root: Path) -> None:
    for filename, route in PUBLIC_TOP_LEVEL_ROUTES.items():
        _write_page(site_root / filename, route)
    _write_page(site_root / "docs" / "index.html", "/docs")
    _write_page(site_root / "docs" / "prompt-injection.html", "/docs/prompt-injection")


def test_crawler_files_are_canonical_complete_and_deterministic(tmp_path):
    site_root = tmp_path / "site"
    _complete_site(site_root)
    _write_page(site_root / "private.html", "/private")
    _write_page(site_root / "docs" / "_draft.html", "/docs/_draft")
    _write_page(site_root / "agents" / "index.html", "/agents")
    _write_page(site_root / "agents" / "2.html", "/agents/2")
    _write_page(site_root / "agents" / "10.html", "/agents/10")
    _write_page(site_root / "agents" / "draft.html", "/agents/draft")

    routes = write_crawler_files(site_root)
    first_sitemap = (site_root / "sitemap.xml").read_bytes()
    first_robots = (site_root / "robots.txt").read_bytes()
    assert routes == discover_public_routes(site_root)

    namespace = {"sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    document = ElementTree.fromstring(first_sitemap)
    locations = [element.text for element in document.findall("sitemap:url/sitemap:loc", namespace)]
    assert locations == [f"{PUBLIC_ORIGIN}{route}" for route in routes]
    assert locations[0] == f"{PUBLIC_ORIGIN}/"
    assert f"{PUBLIC_ORIGIN}/agents" in locations
    assert f"{PUBLIC_ORIGIN}/agents/2" not in locations
    assert f"{PUBLIC_ORIGIN}/agents/10" not in locations
    assert f"{PUBLIC_ORIGIN}/docs/prompt-injection" in locations
    assert f"{PUBLIC_ORIGIN}/private" not in locations
    assert f"{PUBLIC_ORIGIN}/docs/_draft" not in locations
    assert f"{PUBLIC_ORIGIN}/agents/draft" not in locations
    assert all(".html" not in location for location in locations)
    assert first_robots.decode() == (
        f"User-agent: *\nAllow: /\n\nSitemap: {PUBLIC_ORIGIN}/sitemap.xml\n"
    )

    write_crawler_files(site_root)
    assert (site_root / "sitemap.xml").read_bytes() == first_sitemap
    assert (site_root / "robots.txt").read_bytes() == first_robots


def test_crawler_generation_rejects_a_false_canonical(tmp_path):
    site_root = tmp_path / "site"
    _complete_site(site_root)
    _write_page(site_root / "trust.html", "/verify")

    with pytest.raises(RuntimeError, match="exactly one canonical link"):
        write_crawler_files(site_root)


def test_stable_marketplace_route_does_not_depend_on_generated_detail_pages(tmp_path):
    site_root = tmp_path / "site"
    _complete_site(site_root)

    assert "/agents" in discover_public_routes(site_root)


def test_crawler_files_are_published_with_public_read_permissions(tmp_path, monkeypatch):
    site_root = tmp_path / "site"
    _complete_site(site_root)
    modes: list[int] = []
    monkeypatch.setattr(
        sitemap_module.os,
        "chmod",
        lambda path, mode: modes.append(mode),
    )

    write_crawler_files(site_root)

    assert modes == [0o644, 0o644]


def test_marketplace_build_only_targets_the_tree_that_owns_its_output(tmp_path):
    assert (
        build_index._crawler_site_root(Namespace(output=build_index.DEFAULT_OUTPUT, site_root=None))
        == build_index.ROOT / "site"
    )
    site_root = tmp_path / "public"
    assert (
        build_index._crawler_site_root(Namespace(output=site_root / "agents", site_root=site_root))
        == site_root
    )
    with pytest.raises(RuntimeError, match="must own the marketplace output"):
        build_index._crawler_site_root(
            Namespace(output=tmp_path / "elsewhere" / "agents", site_root=site_root)
        )
    assert (
        build_index._crawler_site_root(
            Namespace(output=tmp_path / "index-release" / "agents", site_root=None)
        )
        is None
    )


@pytest.mark.asyncio
async def test_marketplace_build_regenerates_crawler_files_for_an_explicit_site_root(
    tmp_path, monkeypatch
):
    snapshot = SimpleNamespace(
        agents=[],
        metadata=SimpleNamespace(
            captured_at="2026-07-17T00:00:00Z",
            query="a",
        ),
    )
    summary = SimpleNamespace(
        sampled=0,
        expected=0,
        dropped=0,
        matched_count=0,
        audited_count=0,
    )
    crawler_roots: list[Path] = []

    async def index_no_agents(agents, engine):
        return []

    monkeypatch.setattr(build_index, "load_snapshot", lambda path: snapshot)
    monkeypatch.setattr(build_index, "build_hire_catalog", lambda loaded: {})
    monkeypatch.setattr(build_index, "index_agents", index_no_agents)
    monkeypatch.setattr(
        build_index,
        "load_evidence_links",
        lambda path: build_index.EvidenceLinks(audit_by_id={}, attestation_by_id={}),
    )
    monkeypatch.setattr(build_index, "list_badges", lambda path: [])
    monkeypatch.setattr(build_index, "associate_badges", lambda agents, badges, links: {})
    monkeypatch.setattr(build_index, "render_marketplace", lambda *args, **kwargs: summary)
    monkeypatch.setattr(build_index, "_write_json_atomic", lambda path, document: None)
    monkeypatch.setattr(
        build_index,
        "write_crawler_files",
        lambda site_root: crawler_roots.append(site_root),
    )

    site_root = tmp_path / "site"
    await build_index.build(
        Namespace(
            snapshot=tmp_path / "snapshot.jsonl",
            output=site_root / "agents",
            hire_catalog=tmp_path / "services.json",
            marketplace_summary=tmp_path / "summary.json",
            badge_store=tmp_path / "badges.jsonl",
            badge_links=tmp_path / "links.json",
            apa_db=tmp_path / "protection.db",
            apa_issuer_pub=None,
            apa_issuer_history=None,
            site_root=site_root,
        )
    )

    assert crawler_roots == [site_root]


def test_custom_docs_build_does_not_rewrite_the_repository_site(tmp_path):
    assert (
        build_site._crawler_site_root(
            Namespace(
                docs_output=tmp_path / "docs",
                spec_output=tmp_path / "spec" / "APA-SPEC.md",
                site_root=None,
            )
        )
        is None
    )
    assert (
        build_site._crawler_site_root(
            Namespace(
                docs_output=build_site.DEFAULT_DOCS_OUTPUT,
                spec_output=build_site.DEFAULT_SPEC_OUTPUT,
                site_root=None,
            )
        )
        == build_site.DEFAULT_SITE_ROOT
    )


def test_docs_generation_removes_obsolete_generated_pages(tmp_path):
    obsolete = tmp_path / "obsolete-page.html"
    obsolete.write_text(
        '<link rel="canonical" href="https://warden.gudman.xyz/docs/obsolete-page">',
        encoding="utf-8",
    )

    render_docs(build_site.ROOT, tmp_path)

    assert not obsolete.exists()
