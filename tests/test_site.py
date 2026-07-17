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
    og_card = SITE / "assets" / "og.png"
    assert og_card.exists() and og_card.stat().st_size > 0
    for path in required:
        source = path.read_text(encoding="utf-8")
        expected_card = (
            "https://warden.gudman.xyz/assets/og.png"
            if path == SITE / "index.html"
            else "https://warden.gudman.xyz/assets/warden-social-card.png"
        )
        assert expected_card in source
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
        for href in ("/theater", "/trust", "/verify", "/apa/log"):
            assert f'href="{href}"' in header.group("body"), path
        assert 'href="/theater"' in footer.group("body"), path
        assert "The immune system of the agent economy." in footer.group("body"), path


def test_trust_evidence_pages_mark_the_correct_navigation_item_current():
    pages = (
        ("trust.html", "Evidence", "/trust"),
        ("verify.html", "Evidence", "/verify"),
        ("log.html", "Evidence", "/apa/log"),
    )

    for filename, group_name, href in pages:
        source = (SITE / filename).read_text(encoding="utf-8")
        current_group = re.search(
            rf'<details class="nav-group has-current">\s*<summary>{group_name}</summary>'
            r"(?P<body>.*?)</details>",
            source,
            re.DOTALL,
        )
        assert current_group, filename
        assert f'href="{href}" aria-current="page"' in current_group.group("body")
        assert source.count('aria-current="page"') == 1


def test_top_nav_is_curated_and_utility_pages_live_in_footer():
    curated_groups = {
        "Product": ["/playground", "/theater", "/agents"],
        "Developers": ["/docs", "/integrate"],
        "Evidence": ["/verify", "/apa/log", "/trust"],
    }
    relocated_to_footer = ("/gauntlet", "/showcase", "/status", "/badges")
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
        for group_name, expected_hrefs in curated_groups.items():
            block = re.search(
                rf'<details class="nav-group[^"]*">\s*<summary>{group_name}</summary>'
                r'\s*<div class="nav-menu">(?P<body>.*?)</div>',
                source,
                re.DOTALL,
            )
            assert block, (filename, group_name)
            hrefs = re.findall(r'href="([^"]+)"', block.group("body"))
            assert hrefs == expected_hrefs, (filename, group_name, hrefs)
        footer = re.search(
            r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
            source,
            re.DOTALL,
        )
        assert footer, filename
        for href in relocated_to_footer:
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
        ".gauntlet-stats",
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
    assert "prefers-reduced-motion: reduce" in (SITE / "showcase.js").read_text(encoding="utf-8")
    assert "prefers-reduced-motion: reduce" in (SITE / "theater.js").read_text(encoding="utf-8")


def test_attack_theater_is_real_owned_one_pass_surface():
    page = (SITE / "theater.html").read_text(encoding="utf-8")
    script = (SITE / "theater.js").read_text(encoding="utf-8")

    assert "Attack Theater · live immune response · one pass" in page
    assert "live demo scanner" not in page
    assert "Warden-owned demo agent" in page
    assert "data-theater" in page
    assert "data-theater-feed" in page
    assert "data-theater-count" in page
    assert "data-theater-latency" in page
    assert "data-theater-stage-delivery" in page
    assert "data-theater-toggle" in page
    assert "data-theater-next" in page
    assert "AWAITING LIVE VERDICT" in page
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

    for pillar in ("Local enforcement", "Agent Protection Attestation", "Safety Map"):
        assert pillar in page
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
        SITE / "index.html",
        SITE / "trust.html",
        SITE / "theater.html",
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


def test_handoff_docs_describe_the_real_theater_and_unchecked_capture_work():
    demo = (ROOT / "docs" / "HACKATHON_DEMO.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    screenshots = (ROOT / "docs" / "screenshots" / "README.md").read_text(encoding="utf-8")

    assert "/theater" in demo
    assert "/api/demo/theater" in demo
    assert "autoplay" in demo.lower()
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

    assert "The immune system of the agent economy" in readme
    assert "python -m pip install -e . -e sdk/python" in readme
    assert "safe = WardenClient(local=True, fail_open=False).guard(untrusted_text)" in readme
    assert "best-effort telemetry, not enforcement" in readme
    assert "20 requests per minute per" in readme
    assert "4,000 characters" in readme
    assert "### APA and legacy audit badges" in readme
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
        r"\.hero-text,\s*\.service-card p\s*\{[^}]*overflow-wrap:\s*anywhere;",
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
    assert light["danger"] == "#c83737"
    assert light["faint"] == "#625b4e"
    assert light["control-border"] == "#837969"
    assert dark["control-border"] == "#756d5e"

    text_pairs = (
        ("on-accent", "accent-bright"),
        ("on-danger", "danger"),
        ("on-mint", "mint"),
        ("on-amber", "amber"),
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
        r"\.button\.primary\s*\{[^}]*color: var\(--on-accent\);[^}]*background: var\(--accent-bright\)",
        r"\.verdict-badge,\s*\.status-label\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--danger\)",
        r"\.status-label--allow\s*\{[^}]*color: var\(--on-mint\);[^}]*background: var\(--mint\)",
        r"\.status-label--pending\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--amber\)",
        r"\.status-label--sanitize\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--sanitize\)",
        r"\.risk-label--none,\s*\.risk-label--low\s*\{[^}]*color: var\(--on-mint\);[^}]*background: var\(--mint\)",
        r"\.risk-label--medium\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--amber\)",
        r"\.risk-label--high,\s*\.risk-label--critical\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--danger\)",
        r"\.receipt-state\s*\{[^}]*color: var\(--on-accent\);[^}]*background: var\(--accent-bright\)",
        r"\.receipt-state--detected\s*\{[^}]*color: var\(--on-danger\);[^}]*background: var\(--danger\)",
        r"\.receipt-state--candidate\s*\{[^}]*color: var\(--on-amber\);[^}]*background: var\(--amber\)",
        r"input,\s*select,\s*textarea\s*\{[^}]*border: 1px solid var\(--control-border\)",
    )
    assert all(re.search(pattern, css, re.DOTALL) for pattern in selector_contracts)

    allow_rules = re.findall(r"\.status-label--allow\s*\{(?P<body>[^}]*)\}", css, re.DOTALL)
    assert allow_rules
    assert "color: var(--on-mint)" in allow_rules[-1]
    assert "background: var(--mint)" in allow_rules[-1]


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
    mobile_css = css.split("@media (max-width: 520px)", maxsplit=1)[1]
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

    assert "The first agent-security service where you can cryptographically" in home
    assert "data-product-proof" in home
    assert "data-incident-console" in home
    assert "data-home-proof" in home
    assert "data-service-snapshot" in home
    assert 'class="button primary button--hero" href="/hire"' in home
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
    assert "scan_payload" in integrate and "audit_agent" in integrate
    assert "historical uptime" in status.lower()
    assert "transaction-specific" in status.lower()


def test_gauntlet_breaker_board_is_empty_honest_and_requires_public_credit_consent():
    gauntlet_source = (SITE / "gauntlet.html").read_text(encoding="utf-8")
    privacy_source = (SITE / "privacy.html").read_text(encoding="utf-8")
    gauntlet = " ".join(gauntlet_source.lower().split())
    privacy = " ".join(privacy_source.lower().split())

    assert "warden signs its own defeats" in gauntlet
    assert (
        "every attack that beat us, cryptographically proven, already in our benchmark."
        in gauntlet
    )
    assert "data-breaker-board" in gauntlet_source
    assert "data-breaker-empty" in gauntlet_source
    assert "data-breaker-certificate" in gauntlet_source
    assert "data-breaker-row" not in gauntlet_source
    assert "50 most recent certificates" in gauntlet
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
    corpus_bytes = (ROOT / "corpus" / "attacks.jsonl").read_bytes() + (
        ROOT / "corpus" / "benign.jsonl"
    ).read_bytes()

    assert status["agentId"] == "3808"
    assert status["listingStatus"] == "Listed"
    assert status["listingVerifiedAt"] == "2026-07-13"
    assert status["repositoryTests"] == 719
    assert status["repositoryTestsVerifiedAt"] == "2026-07-16"
    assert "566 Python" in status["repositoryTestsNote"]
    assert "122 site JavaScript" in status["repositoryTestsNote"]
    assert "31 TypeScript SDK" in status["repositoryTestsNote"]
    assert "1 Python test skipped" in status["repositoryTestsNote"]
    assert status["corpusCount"] == product_proof["evaluationCorpus"]["total"]
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
