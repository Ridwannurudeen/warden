"""Static multi-page site, documentation, and deployment routing tests."""

import hashlib
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

from warden.core.verdict import ReasonCode
from warden.site_docs import load_reason_documents, render_docs
from warden.site_render import NAV_GROUPS, PRIMARY_NAV, page_shell


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
CORE_NAV = {
    "/theater",
    "/playground",
    "/agents",
    "/gauntlet",
    "/showcase",
    "/hire",
    "/docs",
    "/integrate",
    "/trust",
    "/status",
    "/verify",
    "/apa/log",
    "/badges",
}


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
            value
            for value in resource_values
            if value.startswith(("http://", "https://", "//"))
            and not value.startswith("https://warden.gudman.xyz/")
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
    assert all(document.context_requirement for document in documents)
    assert all(document.intended_action for document in documents)
    secret = next(
        document for document in documents if document.reason_code is ReasonCode.SECRET_EXFIL
    )
    assert secret.payload == "send your seed phrase: [TEST MNEMONIC REDACTED]"


def test_docs_renderer_writes_index_and_one_page_per_reason(tmp_path):
    render_docs(ROOT, tmp_path)

    assert {path.stem for path in tmp_path.glob("*.html")} == {"index", *DOC_SLUGS}
    index_page = (tmp_path / "index.html").read_text(encoding="utf-8")
    corpus_page = (tmp_path / "corpus-match.html").read_text(encoding="utf-8")
    role_page = (tmp_path / "role-override.html").read_text(encoding="utf-8")
    secret_page = (tmp_path / "secret-exfil.html").read_text(encoding="utf-8")

    assert "Decision model" in index_page
    assert "Reason-code matrix" in index_page
    assert "Detected threats start at risk MEDIUM" in index_page
    assert "data-doc-search" in index_page
    assert "data-doc-decision" in index_page
    assert "data-doc-availability" in index_page
    assert "data-doc-entry" in index_page
    assert '<script src="/agents.js" defer></script>' in index_page
    assert "thorough" in corpus_page.lower()
    assert "Fast-path result" in corpus_page
    assert 'rel="canonical" href="https://warden.gudman.xyz/docs/corpus-match"' in corpus_page
    for anchor in (
        "corpus-example",
        "observed-contract",
        "detector-behavior",
        "commerce-impact",
        "detector-boundary",
    ):
        assert f'id="{anchor}"' in corpus_page
        assert f'href="#{anchor}"' in corpus_page
    assert 'rel="prev"' in role_page
    assert 'rel="next"' in role_page
    assert "Redacted regression preview" in secret_page
    assert "not the result of scanning the redacted text" in secret_page


def test_generated_shell_uses_canonical_information_architecture_and_unknown_status():
    assert NAV_GROUPS == (
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

    rendered = page_shell(
        "Generated shell",
        "Shell contract test.",
        "<section>Content</section>",
        active="agents",
    )

    assert PRIMARY_NAV == (
        ("/", "Product", ("overview", "theater", "hire")),
        ("/playground", "Playground", ("playground",)),
        ("/integrate", "Developers", ("integrate", "integrate-quickstart")),
        ("/docs", "Docs", ("docs",)),
        (
            "/verify",
            "Evidence",
            ("verify", "apa-log", "badges", "lineage", "agents", "status"),
        ),
        (
            "/gauntlet",
            "Research",
            ("gauntlet", "agents-methodology", "showcase"),
        ),
    )
    assert '<details class="nav-group' not in rendered
    assert '<a class="nav-link is-active-section" href="/verify">Evidence</a>' in rendered
    assert 'aria-current="page"' not in rendered
    assert 'aria-label="Service status: unknown"' in rendered
    assert 'data-health-state="unknown"' in rendered
    assert ">Status unknown</span>" in rendered
    assert "Checking API" not in rendered
    assert 'class="header-hire"' not in rendered
    assert '<a class="header-integrate" href="/integrate">Integrate</a>' in rendered
    assert '<a class="header-scan" href="/playground">Run a live scan</a>' in rendered
    footer = re.search(
        r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
        rendered,
        re.DOTALL,
    )
    assert footer
    footer_positioning = footer.group("body").split("<nav", maxsplit=1)[0]
    assert footer_positioning.count("<span>") == 1
    for group_name, items in NAV_GROUPS:
        assert f'<span class="site-footer__label">{group_name}</span>' in footer.group("body")
        for href, label, _ in items:
            assert f'<a href="{href}">{label}</a>' in footer.group("body")
    assert 'aria-current="page"' not in footer.group("body")


def test_build_site_publishes_apa_spec_byte_identically(tmp_path):
    docs_output = tmp_path / "docs"
    spec_output = tmp_path / "spec" / "APA-SPEC.md"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/build_site.py",
            "--docs-output",
            str(docs_output),
            "--spec-output",
            str(spec_output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert spec_output.read_bytes() == (ROOT / "spec" / "APA-SPEC.md").read_bytes()


def test_public_apa_spec_matches_source_byte_for_byte():
    assert (SITE / "spec" / "APA-SPEC.md").read_bytes() == (
        ROOT / "spec" / "APA-SPEC.md"
    ).read_bytes()


def test_apa_spec_matches_source_ready_reference_contract():
    spec = (ROOT / "spec" / "APA-SPEC.md").read_text(encoding="utf-8")

    assert "source-ready; not deployed" in spec
    assert 'GET /apa/log        → { "entries": [...], "total": N }' in spec
    for overclaim in ("First deployment", "first deployment", "Deployment #1"):
        assert overclaim not in spec
    assert "paginated JSONL" not in spec
    assert "Default_Ignorable_Code_Point" in spec


def test_required_multi_page_routes_exist_with_shared_navigation():
    required = [
        SITE / "index.html",
        SITE / "theater.html",
        SITE / "playground.html",
        SITE / "agents" / "index.html",
        SITE / "gauntlet.html",
        SITE / "showcase.html",
        SITE / "hire.html",
        SITE / "badges.html",
        SITE / "badge.html",
        SITE / "docs" / "index.html",
        SITE / "integrate.html",
        SITE / "trust.html",
        SITE / "verify.html",
        SITE / "log.html",
        SITE / "status.html",
        SITE / "privacy.html",
        SITE / "terms.html",
        SITE / "agents" / "3808.html",
    ]
    required.extend(SITE / "docs" / f"{slug}.html" for slug in DOC_SLUGS)

    assert all(path.exists() for path in required)
    social_card = SITE / "assets" / "warden-social-card.png"
    assert social_card.exists() and social_card.stat().st_size > 0
    for path in required:
        source = path.read_text(encoding="utf-8")
        assert "https://warden.gudman.xyz/assets/warden-social-card.png" in source
        assert 'name="twitter:image"' in source
        assert "warden-social-card.svg" not in source
        audit = _audit_page(path)
        assert CORE_NAV <= audit.links, path


def test_every_site_shell_links_complete_trust_navigation():
    html_files = list(SITE.rglob("*.html"))
    assert html_files

    for path in html_files:
        source = path.read_text(encoding="utf-8")
        header = re.search(
            r'<header class="site-header page-shell">(?P<body>.*?)</header>',
            source,
            re.DOTALL,
        )
        footer = re.search(
            r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
            source,
            re.DOTALL,
        )
        assert header, path
        assert footer, path
        for href in ("/playground", "/integrate", "/docs", "/verify", "/gauntlet"):
            assert f'href="{href}"' in header.group("body"), path
        for href in ("/theater", "/trust", "/privacy", "/terms"):
            assert f'href="{href}"' in footer.group("body"), path
        assert "Warden" in footer.group("body"), path


def test_evidence_pages_mark_exact_and_section_navigation_context():
    verify = (SITE / "verify.html").read_text(encoding="utf-8")
    log = (SITE / "log.html").read_text(encoding="utf-8")

    assert '<a class="nav-link" href="/verify" aria-current="page">Evidence</a>' in verify
    assert '<a class="nav-link is-active-section" href="/verify">Evidence</a>' in log
    assert 'aria-current="page"' not in re.search(
        r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
        log,
        re.DOTALL,
    ).group("body")
    assert 'class="breadcrumbs"' in verify
    assert 'class="breadcrumbs"' in log

    trust = (SITE / "trust.html").read_text(encoding="utf-8")
    assert 'aria-current="page">Trust' in trust
    assert 'href="/trust"' in trust
    assert 'href="/trust" aria-current="page"' not in trust


def test_top_nav_is_curated_and_utility_pages_live_in_footer():
    curated_hrefs = ["/", "/playground", "/integrate", "/docs", "/verify", "/gauntlet"]
    policy_footer = ("/trust", "/privacy", "/terms")
    top_level_pages = [
        "index.html",
        "theater.html",
        "playground.html",
        "gauntlet.html",
        "showcase.html",
        "hire.html",
        "badges.html",
        "badge.html",
        "integrate.html",
        "trust.html",
        "verify.html",
        "log.html",
        "status.html",
        "privacy.html",
        "terms.html",
    ]

    for filename in top_level_pages:
        source = (SITE / filename).read_text(encoding="utf-8")
        navigation = re.search(
            r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
            source,
            re.DOTALL,
        )
        assert navigation, filename
        assert '<details class="nav-group' not in navigation.group("body")
        hrefs = re.findall(
            r'<a class="nav-link(?: is-active-section)?" href="([^"]+)"',
            navigation.group("body"),
        )
        assert hrefs == curated_hrefs, (filename, hrefs)
        footer = re.search(
            r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
            source,
            re.DOTALL,
        )
        assert footer, filename
        for href in policy_footer:
            assert f'href="{href}"' in footer.group("body"), (filename, href)


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
        ".gauntlet-receipt",
        ".docs-grid",
        ".badge-grid",
        ".status-grid",
        ".scan-workspace",
        ".surface-tabs",
        ".reason-matrix",
        ".theater-stage",
    ):
        assert selector in css
    assert "prefers-reduced-motion: reduce" in css
    assert "prefers-reduced-motion: reduce" in (SITE / "theater.js").read_text(encoding="utf-8")


def test_shared_shell_design_system_exposes_evidence_and_archetype_contracts():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    for state in ("LIVE", "DATED", "ILLUSTRATIVE", "DEGRADED", "UNKNOWN"):
        assert f'[data-source-state="{state}"]' in css
        assert f'[data-source-stamp="{state}"]' in css

    for selector in (
        ".source-stamp",
        ".evidence-boundary",
        ".breadcrumbs",
        ".action-boundary",
        ".signed-receipt",
        ".async-state-panel",
        '.async-state-panel[data-state="loading"]',
        'body[data-page-archetype="landing"]',
        'body[data-page-archetype="lab"]',
        'body[data-page-archetype="evidence"]',
        'body[data-page-archetype="commerce"]',
        'body[data-page-archetype="marketplace"]',
        'body[data-page-archetype="docs"]',
        'del[data-diff="removed"]',
        'ins[data-diff="added"]',
        ".control-trace",
        ".decision-ledger",
        ".showcase-scene",
        ".raw-evidence",
        ".integration-preview__code",
        ".route-index",
    ):
        assert selector in css

    assert "@media (max-width: 380px)" in css
    assert "height: 100dvh" in css
    assert "env(safe-area-inset-bottom)" in css
    assert "min-height: 44px" in css
    assert "overscroll-behavior-inline: contain" in css
    assert "prefers-reduced-motion: reduce" in css


def test_attack_theater_is_real_owned_one_pass_surface():
    page = (SITE / "theater.html").read_text(encoding="utf-8")
    script = (SITE / "theater.js").read_text(encoding="utf-8")

    assert "Incident replay · controlled test" in page
    assert "Inspect the handoff." in page
    assert "live demo scanner" not in page
    assert "Warden-owned handler" in page
    assert "data-theater" in page
    assert "data-theater-feed" in page
    assert "data-theater-count" in page
    assert "data-theater-latency" in page
    assert "data-theater-stage-delivery" in page
    assert "data-theater-toggle" in page
    assert "data-theater-next" in page
    assert "Not run" in page
    assert "SANITIZE \u00b7 PROMPT_INJECTION" not in page
    assert page.index("/scan-client.js") < page.index("/theater.js")
    assert '"/api/demo/theater"' in script
    assert 'postJson("/api/demo/scan"' not in script
    assert "assertScanResponse" in script
    assert "hasValidAspReceipt" in script
    assert "prefers-reduced-motion: reduce" in script
    assert "fallback" not in script.lower()


def test_trust_layer_page_exposes_honest_open_contracts():
    page = (SITE / "trust.html").read_text(encoding="utf-8")

    for pillar in (
        "Local enforcement",
        "Agent Protection Attestation",
        "Marketplace Evidence Index",
    ):
        assert pillar in page
    assert "<table>" in page
    assert page.count('<th scope="row">') == 4
    assert 'class="badge-evidence"' not in page
    assert "safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)" in page
    assert 'href="/agents"' in page
    assert 'href="/verify"' in page
    assert 'href="/apa/log"' in page
    assert 'href="/spec/APA-SPEC.md"' in page
    badge_sources = re.findall(r'<img[^>]+src="([^"]+/badge\.svg)"', page)
    assert badge_sources == ["https://warden.gudman.xyz/apa/attestation/ATTESTATION_ID/badge.svg"]
    assert "does not prove that every request" in page


def test_public_apa_copy_discloses_the_explicit_unavailable_counter_state():
    surfaces = (
        ROOT / "README.md",
        SITE / "trust.html",
        SITE / "verify.html",
        SITE / "verify.js",
    )

    for path in surfaces:
        source = path.read_text(encoding="utf-8")
        assert "explicit unavailable state" in source, path


def test_verifier_copy_describes_rotation_and_transparency_without_upgrading_proof():
    page = (SITE / "verify.html").read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", page)

    assert "applicable current or recent key" in normalized
    assert "independently anchored log checkpoint" in normalized
    assert "an unanchored chain cannot expose a complete rewrite" in normalized
    assert "transparency log makes silent re-binding detectable" not in normalized


def test_integrate_leads_with_source_installed_sdk_and_honest_tiers():
    page = (SITE / "integrate.html").read_text(encoding="utf-8")
    normalized_page = re.sub(r"\s+", " ", page)

    assert page.index('id="sdk-first"') < page.index("x402-protected")
    assert "python -m pip install -e . -e sdk/python" in page
    assert "safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)" in page
    assert "WardenClient()" in page
    assert "fail_open=True" in page
    assert "best-effort telemetry, not enforcement" in normalized_page
    assert "4,000" in page
    assert "pip install warden-guard" not in page
    assert "unrelated" in page
    assert (
        page.count(
            "Source-backed OnchainOS, x402, Python, TypeScript, MCP, and agent-framework integration patterns for Warden."
        )
        == 2
    )
    assert page.count("returned transformed text") >= 2
    assert "returned safe text" not in page
    assert "forwards only safe text" not in page


def test_handoff_docs_describe_the_real_theater_and_unchecked_capture_work():
    demo = (ROOT / "docs" / "HACKATHON_DEMO.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    screenshots = (ROOT / "docs" / "screenshots" / "README.md").read_text(encoding="utf-8")

    assert "/theater" in demo
    assert "/api/demo/theater" in demo
    assert "`/theater` starts idle" in demo
    assert "Run test sequence" in demo
    assert "There is no autoplay on page load" in demo
    assert "let autoplay start" not in demo
    assert "fallback" not in demo.lower()
    assert "90 seconds or shorter" in demo
    for route in ("/theater", "/trust", "/verify", "/apa/log"):
        assert route in release
    assert "remain unchecked" in release
    for route in ("/theater", "/trust", "/verify"):
        assert route in screenshots
    assert "fallback" not in screenshots.lower()


def test_readme_leads_with_the_trust_layer_and_exact_quickstart_contracts():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Verifiable pre-action security for AI agents" in readme
    assert "The immune system of the agent economy" not in readme
    assert "Safety Map" not in readme
    assert "auto-playing pass" not in readme
    assert "python -m pip install -e . -e sdk/python" in readme
    assert "safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)" in readme
    assert "best-effort telemetry, not enforcement" in readme
    assert "20 requests per minute per" in readme
    assert "4,000 characters" in readme
    assert "### APA and endpoint audit evidence" in readme
    assert "HMAC-SHA256" in readme
    for route in ("/theater", "/trust", "/verify", "/apa/log"):
        assert route in readme
    assert "pip install warden-guard" not in readme


def test_current_submission_surfaces_are_staged_and_use_hardened_claims():
    form = (ROOT / "submission" / "FORM-ANSWERS.md").read_text(encoding="utf-8")
    audit = (ROOT / "submission" / "COMPETITIVE-AUDIT.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Private repository" in form
    assert "Public GitHub repo" not in form
    assert "Do not change visibility" in form
    assert "Warden Guard Live" in audit
    assert "query `a`" in audit
    assert "marketplace-wide safety index" not in audit
    assert "any agent adopts" not in audit
    assert "infrastructure the whole marketplace can run on" not in audit
    assert "[Attack Theater](site/theater.html)" in readme
    assert "[Attack Theater](https://warden.gudman.xyz/theater)" not in readme


def test_marketplace_rows_and_mobile_navigation_fit_narrow_viewports():
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    app = (SITE / "app.js").read_text(encoding="utf-8")

    card_layout = re.search(
        r"@media \(max-width: 900px\) \{(?P<body>.*?)\n\}\n\n@media \(max-width: 780px\)",
        css,
        re.DOTALL,
    )
    assert card_layout
    assert ".agent-row--header" in card_layout.group("body")
    assert "display: none" in card_layout.group("body")
    assert ".agent-row [data-label]::before" in card_layout.group("body")
    assert re.search(
        r"\.agent-row > \*\s*\{[^}]*min-width:\s*0;[^}]*overflow-wrap:\s*anywhere;",
        css,
        re.DOTALL,
    )
    assert re.search(
        r"\.hero-text,\s*\.section-copy,\s*\.note\s*\{[^}]*overflow-wrap:\s*anywhere;",
        css,
        re.DOTALL,
    )
    assert re.search(
        r"\.marketplace-service__description\s*\{[^}]*overflow-wrap:\s*anywhere;",
        css,
        re.DOTALL,
    )

    mobile_navigation = re.search(
        r"@media \(max-width: 1060px\) \{(?P<body>.*?)\n\}\n\n@media \(max-width: 900px\)",
        css,
        re.DOTALL,
    )
    assert mobile_navigation
    assert "overscroll-behavior: contain" in mobile_navigation.group("body")
    assert "body.nav-open" in mobile_navigation.group("body")
    assert ".nav-close" in mobile_navigation.group("body")
    assert ".js-enabled .site-nav" in mobile_navigation.group("body")

    focusables = re.search(
        r"function focusableNavigationElements\(\) \{(?P<body>.*?)\n    \}",
        app,
        re.DOTALL,
    )
    assert focusables
    assert "siteNav.querySelectorAll" in focusables.group("body")
    assert "navToggle," not in focusables.group("body")
    assert "element.getClientRects().length > 0" in focusables.group("body")
    assert 'navClose.className = "nav-close"' in app
    assert "siteNav.prepend(navClose)" in app
    assert 'navClose.addEventListener("click"' in app
    assert 'document.documentElement.classList.add("js-enabled")' in app
    assert "element.inert = isolated" in app


def test_playground_recipient_remove_control_has_a_mobile_touch_target():
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    script = (SITE / "playground.js").read_text(encoding="utf-8")

    remove_control = re.search(
        r"\.address-chip-remove\s*\{(?P<body>[^}]*)\}",
        css,
        re.DOTALL,
    )
    assert remove_control
    assert "min-width: 44px" in remove_control.group("body")
    assert "min-height: 44px" in remove_control.group("body")
    assert 'remove.textContent = "\u00d7";' in script
    assert "Remove expected recipient" in script


def test_playground_keeps_the_verdict_compact_and_leads_with_caller_action():
    page = (SITE / "playground.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert 'class="status-label verdict-label" data-demo-verdict' in page
    assert 'id="demo-result-heading" data-demo-action' in page
    assert re.search(r"<h2[^>]+data-demo-verdict", page) is None
    outcome_heading = re.search(
        r"\.verdict-summary h2\s*\{(?P<body>[^}]*)\}",
        css,
        re.DOTALL,
    )
    assert outcome_heading
    assert "font-size: clamp(22px, 3vw, 30px)" in outcome_heading.group("body")


def test_shared_styles_meet_wcag_contrast_contract():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    def theme_tokens(selector):
        match = re.search(
            rf"{re.escape(selector)}\s*\{{(?P<body>.*?)\n\}}",
            css,
            re.DOTALL,
        )
        assert match, selector
        return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6});", match.group("body")))

    def relative_luminance(color):
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast_ratio(foreground, background):
        luminances = sorted(
            (relative_luminance(foreground), relative_luminance(background)),
            reverse=True,
        )
        return (luminances[0] + 0.05) / (luminances[1] + 0.05)

    light = theme_tokens(":root")
    dark = {**light, **theme_tokens(':root[data-theme="dark"]')}
    required_tokens = {
        "on-accent",
        "on-danger",
        "on-mint",
        "on-amber",
        "control-border",
    }
    assert required_tokens <= dark.keys()
    assert required_tokens <= light.keys()
    assert light["accent-bright"] == "#8c6516"
    assert light["danger"] == "#b64045"
    assert light["faint"] == "#675e4f"
    assert light["control-border"] == "#8a7c64"
    assert dark["control-border"] == "#7a6f58"

    text_pairs = (
        ("on-accent", "accent"),
        ("on-danger", "block"),
        ("on-mint", "allow"),
        ("on-amber", "sanitize"),
        ("faint", "bg-deep"),
        ("faint", "surface-soft"),
    )
    control_backgrounds = ("surface-raised", "surface", "bg", "bg-deep")
    for theme_name, tokens in (("dark", dark), ("light", light)):
        for foreground, background in text_pairs:
            ratio = contrast_ratio(tokens[foreground], tokens[background])
            assert ratio >= 4.5, f"{theme_name} {foreground}/{background}: {ratio:.3f}"
        for background in control_backgrounds:
            ratio = contrast_ratio(tokens["control-border"], tokens[background])
            assert ratio >= 3, f"{theme_name} control-border/{background}: {ratio:.3f}"

    selector_contracts = (
        r"\.button\.primary\s*\{[^}]*color: var\(--on-accent\);[^}]*background: var\(--accent\)",
        r"\.status-label,\s*\.verdict-badge\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--block\)",
        r"\.status-label--allow,\s*\.risk-label--none,\s*\.risk-label--low\s*\{[^}]*color: var\(--on-mint\);[^}]*background: var\(--allow\)",
        r"\.status-label--sanitize,\s*\.status-label--pending,\s*\.risk-label--medium\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--sanitize\)",
        r"\.risk-label--high,\s*\.risk-label--critical\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--block\)",
        r"\.receipt-state--candidate\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--sanitize\)",
        r"\.receipt-state--duplicate\s*\{[^}]*color: var\(--on-accent\);[^}]*background: var\(--accent\)",
        r"\.receipt-state--detected\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--block\)",
        r"input,\s*select,\s*textarea\s*\{[^}]*border: 1px solid var\(--control-border\)",
    )
    assert all(re.search(pattern, css, re.DOTALL) for pattern in selector_contracts)

    allow_rule = re.search(
        r"\.status-label--allow,\s*\.risk-label--none,\s*"
        r"\.risk-label--low\s*\{(?P<body>[^}]*)\}",
        css,
        re.DOTALL,
    )
    assert allow_rule
    assert "color: var(--on-mint)" in allow_rule.group("body")
    assert "background: var(--allow)" in allow_rule.group("body")


def test_every_page_applies_the_persisted_theme_before_css():
    initializer = (SITE / "theme.js").read_text(encoding="utf-8")
    assert 'localStorage.getItem("warden-theme")' in initializer
    assert "document.documentElement.dataset.theme = storedTheme" in initializer

    for path in SITE.rglob("*.html"):
        page = path.read_text(encoding="utf-8")
        head = page.split("</head>", 1)[0]
        theme_script = re.search(
            r'<script src="/theme\.js(?:\?v=[0-9a-f]{8})?"></script>',
            head,
        )
        stylesheet = re.search(
            r'<link rel="stylesheet" href="/styles\.css(?:\?v=[0-9a-f]{8})?"',
            head,
        )
        assert theme_script, path
        assert stylesheet, path
        assert theme_script.start() < stylesheet.start(), path


def test_primary_navigation_controls_meet_the_touch_target_floor():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    nav_link = re.search(r"\.nav-link\s*\{(?P<body>[^}]*)\}", css, re.DOTALL)
    assert nav_link
    assert "min-height: 44px" in nav_link.group("body")
    header_override = re.search(
        r"\.status-pill,\s*\.theme-toggle,\s*\.nav-toggle,\s*"
        r"\.nav-close,\s*\.header-integrate,\s*\.header-scan\s*\{(?P<body>[^}]*)\}",
        css,
        re.DOTALL,
    )
    assert header_override
    assert "min-height: 40px" not in header_override.group("body")


def test_hire_readiness_and_shell_controls_match_semantic_styles():
    hire = (SITE / "hire.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    hire_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", hire))

    assert hire.count("data-readiness-check") == 4
    for requirement in (
        "I control the OKX User-role agent identity",
        "CLI is installed and authenticated to that agent",
        "wallet can cover the displayed USDT amount",
        "authorized to test any audit target",
    ):
        assert requirement in hire_text
    assert "Confirm all four" in hire_text
    assert "Four confirmations required" in hire_text

    assert hire.count('name="hire-shell"') == 2
    assert 'class="segmented-control-options"' in hire
    for selector in (
        ".readiness-checklist label",
        ".readiness-checklist input",
        ".readiness-checklist label:has(input:checked)",
        ".segmented-control-options",
        ".segmented-control label",
        ".segmented-control input",
        ".segmented-control label:has(input:checked)",
    ):
        assert selector in css
    mobile_css = css.split("@media (max-width: 560px)", maxsplit=1)[1]
    assert ".segmented-control-options" in mobile_css


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
    gauntlet = (SITE / "gauntlet.html").read_text(encoding="utf-8")
    hire = (SITE / "hire.html").read_text(encoding="utf-8")
    badges = (SITE / "badges.html").read_text(encoding="utf-8")
    badge = (SITE / "badge.html").read_text(encoding="utf-8")
    integrate = (SITE / "integrate.html").read_text(encoding="utf-8")
    status = (SITE / "status.html").read_text(encoding="utf-8")

    assert "A security boundary for agent actions." in home
    assert "data-product-proof" in home
    assert "data-incident-console" in home
    assert "data-home-proof" in home
    assert "data-hero-examples" not in home
    assert 'id="action-boundary"' in home
    assert "data-service-snapshot" in home
    assert home.count('href="/hire"') >= 2
    assert 'class="button secondary" href="/integrate"' in home
    assert "/api/demo/scan" in playground and "data-playground-form" in playground
    assert "data-demo-diff" in playground and "data-demo-json" in playground
    assert "data-gauntlet-error" in gauntlet and "data-gauntlet-retry" in gauntlet
    assert 'data-copy-step="1"' in hire and 'data-copy-step="4"' in hire
    assert "This step spends the displayed USDT amount" in hire
    assert "/api/badges" in badges and "data-badge-registry" in badges
    assert 'rel="canonical" href="https://warden.gudman.xyz/badge"' in badge
    for label in ("OnchainOS", "Raw x402", "Python", "TypeScript", "MCP"):
        assert label in integrate
    assert all(tool in integrate for tool in ("scan_payload", "audit_agent", "harden_agent"))
    assert "historical uptime" in status.lower()
    assert "transaction-specific" in status.lower()


def test_gauntlet_breaker_board_is_empty_honest_and_requires_public_credit_consent():
    gauntlet_source = (SITE / "gauntlet.html").read_text(encoding="utf-8")
    privacy_source = (SITE / "privacy.html").read_text(encoding="utf-8")
    gauntlet = " ".join(gauntlet_source.lower().split())
    privacy = " ".join(privacy_source.lower().split())

    assert "submit a bypass test" in gauntlet
    assert "only a reproducible, human-confirmed miss receives a signed" in gauntlet
    assert gauntlet.count("not a confirmed bypass") == 1
    assert "data-breaker-board" in gauntlet_source
    assert "data-breaker-empty" in gauntlet_source
    assert "data-breaker-certificate" in gauntlet_source
    assert "data-breaker-row" not in gauntlet_source
    assert "50 most recent human-confirmed certificates" in gauntlet
    assert "transparency chain remains the complete public record" in gauntlet

    assert "data-gauntlet-public-credit-consent" in gauntlet_source
    assert "consent to publish" in gauntlet
    assert "normalized visible form" in gauntlet
    assert "finder handle" in gauntlet
    assert "raw submitted payload is not published" in privacy
    assert "redacted reproducer" in privacy
    assert "payload digest" in privacy
    assert "consented finder handle" in privacy


def test_status_and_marketplace_metadata_are_dated_and_honest():
    status = json.loads((SITE / "data" / "site-status.json").read_text(encoding="utf-8"))
    product_proof = json.loads((SITE / "data" / "product-proof.json").read_text(encoding="utf-8"))
    marketplace = json.loads(
        (SITE / "data" / "marketplace-summary.json").read_text(encoding="utf-8")
    )
    corpus_bytes = b"".join(
        path.read_bytes().replace(b"\r\n", b"\n")
        for path in (ROOT / "corpus" / "attacks.jsonl", ROOT / "corpus" / "benign.jsonl")
    )

    assert status["agentId"] == "3808"
    assert status["listingStatus"] == "Listed"
    assert status["listingVerifiedAt"] == "2026-07-13"
    assert status["repositoryTests"] == 2250
    assert status["repositoryTestsVerifiedAt"] == "2026-07-26"
    assert "1973 Python" in status["repositoryTestsNote"]
    assert "196 site JavaScript" in status["repositoryTestsNote"]
    assert "81 TypeScript SDK" in status["repositoryTestsNote"]
    assert "2 Python tests skipped" in status["repositoryTestsNote"]
    # corpusCount is the loaded training/scan corpus; evaluationCorpus is the
    # held-out benchmark set the recall is measured on — deliberately different
    # corpora, each tied to its real source.
    training_rows = sum(1 for line in corpus_bytes.split(b"\n") if line.strip())
    assert status["corpusCount"] == training_rows
    held_out_rows = sum(
        1
        for name in ("held_out_attacks.jsonl", "held_out_benign.jsonl")
        for line in (ROOT / "benchmark" / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    assert product_proof["evaluationCorpus"]["total"] == held_out_rows
    assert (
        product_proof["evaluationCorpus"]["attacks"] + product_proof["evaluationCorpus"]["benign"]
        == product_proof["evaluationCorpus"]["total"]
    )
    assert status["corpusFingerprint"] == f"sha256:{hashlib.sha256(corpus_bytes).hexdigest()}"
    assert status["paymentActivity"]["transactionSpecific"] is False
    assert "does not contain" in status["paymentActivity"]["note"]
    assert status["paymentActivity"]["url"].startswith("https://www.oklink.com/xlayer/address/")
    assert set(marketplace) == {
        "schemaVersion",
        "capturedAt",
        "query",
        "sampled",
        "expected",
        "dropped",
        "matchedCount",
        "auditedCount",
    }
    assert marketplace["schemaVersion"] == 2
    assert marketplace["query"] == "a"
    assert marketplace["sampled"] > 0
    assert marketplace["expected"] >= 0
    assert marketplace["dropped"] == max(marketplace["expected"] - marketplace["sampled"], 0)
    assert 0 <= marketplace["auditedCount"] <= marketplace["sampled"]
    assert 0 <= marketplace["matchedCount"] <= marketplace["sampled"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", marketplace["capturedAt"])


def test_privacy_and_terms_cover_gauntlet_retention_and_public_surfaces():
    privacy_source = (SITE / "privacy.html").read_text(encoding="utf-8")
    terms_source = (SITE / "terms.html").read_text(encoding="utf-8")
    privacy = privacy_source.lower()
    terms = terms_source.lower()

    assert "pending gauntlet" in privacy
    assert "payload" in privacy and "finder" in privacy
    assert "does not authenticate account ownership" in privacy
    assert "/api/demo/gauntlet" in terms
    assert "/api/badges" in terms
    assert "does not prove the submitter controls" in terms
    assert 'rel="canonical" href="https://warden.gudman.xyz/privacy"' in privacy_source
    assert 'rel="canonical" href="https://warden.gudman.xyz/terms"' in terms_source
    for source in (privacy_source, terms_source):
        assert 'href="/privacy"' in source
        assert 'href="/terms"' in source
        assert 'href="/showcase"' in source


def test_site_contains_no_stale_phase_five_service_or_listing_copy():
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in SITE.rglob("*")
        if path.is_file() and path.suffix in {".html", ".js", ".json"}
    )

    assert "18954" not in source
    assert "18955" not in source
    assert "under review" not in source.lower()


def test_audit_evidence_lineage_page_is_honest_and_wired_to_shared_verification():
    page = (SITE / "lineage.html").read_text(encoding="utf-8")
    script = (SITE / "lineage.js").read_text(encoding="utf-8")

    # The page reads the real read-only lineage route and reuses the shared log
    # verifier rather than shipping its own crypto.
    assert "/api/shield/" in script
    assert "/lineage" in script
    assert "WardenTransparencyLog" in script
    # build_site.py appends a cache-busting version, so allow it as elsewhere.
    assert re.search(r'src="/log\.js(?:\?v=[0-9a-f]{8})?"', page)
    assert re.search(r'src="/lineage\.js(?:\?v=[0-9a-f]{8})?"', page)
    assert not re.search(r"crypto\.subtle", script)

    # Ordered history, per-entry lifecycle, verification links, and an explicit
    # empty state must all be present.
    for hook in (
        "data-lineage-entries",
        "data-lineage-empty",
        "data-lineage-verify",
        "data-lineage-verification",
    ):
        assert hook in page, hook
    assert "/badge?audit_id=" in script

    # I5: this surface reports audit evidence, never certification.
    assert "point-in-time evidence, not certification" in page
    assert "certification lineage" not in page.lower()
    for forbidden in ("certified", "compliant", "guaranteed safe", "accredited"):
        assert forbidden not in page.lower(), forbidden


def test_hire_leads_with_a_paste_into_your_agent_prompt_before_the_cli_flow():
    """The no-CLI path must come first: OKX's own listing sells by pasted prompt,
    so a buyer who never installs onchainos still has a way to purchase."""
    hire = (SITE / "hire.html").read_text(encoding="utf-8")
    script = (SITE / "hire.js").read_text(encoding="utf-8")
    hire_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", hire))

    assert "data-agent-prompt" in hire
    assert "data-copy-agent-prompt" in hire
    assert "Ask your agent to buy it" in hire_text
    # The prompt block precedes the four-command flow on the page.
    assert hire.index("data-agent-prompt") < hire.index('data-command-step="1"')
    # No price or endpoint baked into the markup; both come from the catalog.
    assert "0.1 USDT" not in hire_text
    assert "buildAgentPrompt" in script
    assert "OKX Agent Payments Protocol" in script


def test_hire_links_to_the_real_okx_listing_page_instead_of_telling_people_to_search():
    """okx.ai/agents/<id> is a real page; the marketplace root is only the
    pre-catalog fallback, and the id is never baked into the markup."""
    hire = (SITE / "hire.html").read_text(encoding="utf-8")
    script = (SITE / "hire.js").read_text(encoding="utf-8")

    assert "data-okx-listing" in hire
    assert 'href="https://www.okx.ai/"' in hire
    assert "https://www.okx.ai/agents/3808" not in hire
    assert "https://www.okx.ai/agents/${provider}" in script


def test_verify_page_distinguishes_a_stale_record_from_a_forged_one():
    """A genuine signature on an expired record is the freshness rule working, not
    a failure, and must not be dressed in the same language as a bad signature."""
    script = (SITE / "verify.js").read_text(encoding="utf-8")
    page = (SITE / "verify.html").read_text(encoding="utf-8")
    page_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))

    assert "Signature genuine · ${verification.effectiveStatus}" in script
    assert "Signature genuine — record out of date" in script
    assert "A real signature does not make an old claim true." in script
    # The forged case keeps the hard word; only the stale case is reframed.
    assert '"Rejected · invalid signature"' in script
    assert "Rejected · ${verification.effectiveStatus}" not in script

    # The page says up front that an unaccepted archival record is the point.
    assert "read that as the demonstration" in page_text
    assert "freshness window" in page_text


def test_badges_page_can_print_a_correction_beside_a_signed_record():
    script = (SITE / "badge.js").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert "RECORD_CORRECTIONS" in script
    assert "7885a4880f5d258e" in script
    assert "badge-card-correction" in script
    assert ".badge-card-correction" in css
