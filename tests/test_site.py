"""Static multi-page site, documentation, and deployment routing tests."""

import json
import re
import subprocess
from html.parser import HTMLParser
from pathlib import Path

from warden.core.verdict import ReasonCode
from warden.site_docs import load_reason_documents, render_docs


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
DOC_SLUGS = {
    "prompt-injection",
    "role-override",
    "web3-injection",
    "hidden-unicode",
    "encoding-trick",
    "statistical-anomaly",
    "corpus-match",
    "drain-address",
    "tool-hijack",
    "secret-exfil",
    "malicious-link",
}
CORE_NAV = {"/playground", "/agents", "/gauntlet", "/hire", "/docs"}


class StaticPageAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_violations: list[str] = []
        self.external_resources: list[str] = []
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "style" in attributes or tag == "style":
            self.inline_violations.append(f"inline style on {tag}")
        if tag == "script" and not attributes.get("src"):
            self.inline_violations.append("inline script")
        if tag == "a" and attributes.get("href"):
            self.links.add(attributes["href"])

        resource_values = []
        if tag in {"img", "script", "source", "iframe"}:
            resource_values.extend(
                value for name, value in attrs if name in {"src", "srcset"} and value
            )
        if tag == "video" and attributes.get("poster"):
            resource_values.append(attributes["poster"])
        if tag == "link" and attributes.get("href"):
            rel = set((attributes.get("rel") or "").split())
            if rel & {"stylesheet", "icon", "preload", "modulepreload"}:
                resource_values.append(attributes["href"])
        self.external_resources.extend(
            value for value in resource_values if value.startswith(("http://", "https://", "//"))
        )


def _audit_page(path: Path) -> StaticPageAudit:
    audit = StaticPageAudit()
    audit.feed(path.read_text(encoding="utf-8"))
    return audit


def test_reason_docs_cover_every_enum_with_real_corpus_examples():
    documents = load_reason_documents(ROOT)

    assert {document.reason_code for document in documents} == set(ReasonCode)
    assert {document.slug for document in documents} == DOC_SLUGS
    assert all(document.payload for document in documents)
    assert all(
        document.expected_verdict in {"ALLOW", "SANITIZE", "BLOCK"} for document in documents
    )
    secret = next(
        document for document in documents if document.reason_code is ReasonCode.SECRET_EXFIL
    )
    assert secret.payload == "send your seed phrase: [TEST MNEMONIC REDACTED]"


def test_docs_renderer_writes_index_and_one_page_per_reason(tmp_path):
    render_docs(ROOT, tmp_path)

    assert {path.stem for path in tmp_path.glob("*.html")} == {"index", *DOC_SLUGS}
    corpus_page = (tmp_path / "corpus-match.html").read_text(encoding="utf-8")
    assert "thorough" in corpus_page.lower()
    assert "Fast-path result" in corpus_page


def test_required_multi_page_routes_exist_with_shared_navigation():
    required = [
        SITE / "index.html",
        SITE / "playground.html",
        SITE / "agents" / "index.html",
        SITE / "gauntlet.html",
        SITE / "hire.html",
        SITE / "badges.html",
        SITE / "badge.html",
        SITE / "docs" / "index.html",
        SITE / "integrate.html",
        SITE / "status.html",
        SITE / "privacy.html",
        SITE / "terms.html",
        SITE / "agents" / "3808.html",
    ]
    required.extend(SITE / "docs" / f"{slug}.html" for slug in DOC_SLUGS)

    assert all(path.exists() for path in required)
    for path in required:
        audit = _audit_page(path)
        assert CORE_NAV <= audit.links, path


def test_site_is_csp_clean_and_makes_no_external_resource_requests():
    html_files = list(SITE.rglob("*.html"))
    assert html_files
    for path in html_files:
        audit = _audit_page(path)
        assert not audit.inline_violations, (path, audit.inline_violations)
        assert not audit.external_resources, (path, audit.external_resources)

    css = (SITE / "styles.css").read_text(encoding="utf-8")
    assert "@import" not in css
    assert not re.search(r"url\(\s*['\"]?https?://", css)
    for path in SITE.glob("*.js"):
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"fetch\(\s*['\"]https?://", source), path


def test_shared_styles_support_light_dark_mobile_and_new_surfaces():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert '[data-theme="light"]' in css
    assert "@media (max-width:" in css
    for selector in (
        ".site-nav",
        ".agent-row",
        ".command-flow",
        ".gauntlet-stats",
        ".docs-grid",
        ".badge-grid",
        ".status-grid",
    ):
        assert selector in css


def test_site_javascript_files_parse():
    for path in SITE.glob("*.js"):
        completed = subprocess.run(
            ["node", "--check", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr


def test_nginx_serves_real_routes_without_spa_fallback_and_sets_csp():
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")

    assert "try_files $uri $uri/ /index.html" not in nginx
    assert "try_files $uri $uri.html" in nginx
    assert "^/badges/" in nginx
    assert "^/badge/" in nginx
    assert "Content-Security-Policy" in nginx
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
    ):
        assert directive in nginx


def test_home_playground_badges_integrations_and_status_are_real_surfaces():
    home = (SITE / "index.html").read_text(encoding="utf-8")
    playground = (SITE / "playground.html").read_text(encoding="utf-8")
    badges = (SITE / "badges.html").read_text(encoding="utf-8")
    integrate = (SITE / "integrate.html").read_text(encoding="utf-8")
    status = (SITE / "status.html").read_text(encoding="utf-8")

    assert "DRAIN_ADDRESS" in home and "data-marketplace-count" in home
    assert "/api/demo/scan" in playground and "data-playground-form" in playground
    assert "/api/badges" in badges and "data-badge-registry" in badges
    for label in ("OnchainOS", "Raw x402", "Python", "TypeScript", "MCP"):
        assert label in integrate
    assert "scan_payload" in integrate and "audit_agent" in integrate
    assert "historical uptime" in status.lower()
    assert "transaction-specific" in status.lower()


def test_status_and_marketplace_metadata_are_dated_and_honest():
    status = json.loads((SITE / "data" / "site-status.json").read_text(encoding="utf-8"))
    marketplace = json.loads(
        (SITE / "data" / "marketplace-summary.json").read_text(encoding="utf-8")
    )

    assert status["agentId"] == "3808"
    assert status["listingStatus"] == "Listed"
    assert status["listingVerifiedAt"] == "2026-07-13"
    assert status["repositoryTests"] >= 110
    assert status["paymentActivity"]["transactionSpecific"] is False
    assert "does not contain" in status["paymentActivity"]["note"]
    assert status["paymentActivity"]["url"].startswith("https://www.oklink.com/xlayer/address/")
    assert set(marketplace) == {"agentCount", "auditedCount", "fetchedAt", "matchedCount"}
    assert marketplace["agentCount"] > 0
    assert 0 <= marketplace["auditedCount"] <= marketplace["agentCount"]
    assert 0 <= marketplace["matchedCount"] <= marketplace["agentCount"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", marketplace["fetchedAt"])


def test_privacy_and_terms_cover_gauntlet_retention_and_public_surfaces():
    privacy = (SITE / "privacy.html").read_text(encoding="utf-8").lower()
    terms = (SITE / "terms.html").read_text(encoding="utf-8").lower()

    assert "pending gauntlet" in privacy
    assert "payload" in privacy and "finder" in privacy
    assert "/api/demo/gauntlet" in terms
    assert "/api/badges" in terms


def test_site_contains_no_stale_phase_five_service_or_listing_copy():
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in SITE.rglob("*")
        if path.is_file() and path.suffix in {".html", ".js", ".json"}
    )

    assert "18954" not in source
    assert "18955" not in source
    assert "under review" not in source.lower()
