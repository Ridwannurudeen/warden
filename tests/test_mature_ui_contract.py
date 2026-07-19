"""Regression contracts for Warden's restrained, mature product presentation."""

import math
import re
from html.parser import HTMLParser
from pathlib import Path

from warden.site_render import NAV_GROUPS, page_shell


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
MANUAL_TOP_LEVEL_PAGES = (
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
)


class _HomepageStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_main = False
        self.section_depth = 0
        self.top_level_sections: list[str] = []
        self.in_home_hero = False
        self.hero_depth = 0
        self.capture: str | None = None
        self.hero_heading = ""
        self.hero_copy = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if tag == "main":
            self.in_main = True
        if tag == "section" and self.in_main:
            if self.section_depth == 0:
                self.top_level_sections.append(attributes.get("id") or " ".join(classes))
            self.section_depth += 1
            if "home-hero" in classes:
                self.in_home_hero = True
                self.hero_depth = self.section_depth
        if not self.in_home_hero:
            return
        if tag == "h1" and not self.hero_heading:
            self.capture = "heading"
        elif tag == "p" and "hero-text" in classes and not self.hero_copy:
            self.capture = "copy"

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "p"}:
            self.capture = None
        if tag == "section" and self.in_main:
            if self.in_home_hero and self.section_depth == self.hero_depth:
                self.in_home_hero = False
            self.section_depth -= 1
        if tag == "main":
            self.in_main = False

    def handle_data(self, data: str) -> None:
        if self.capture == "heading":
            self.hero_heading += data
        elif self.capture == "copy":
            self.hero_copy += data


def _words(value: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*", value)


def _theme_properties(css: str) -> tuple[dict[str, str], dict[str, str]]:
    light_match = re.search(r":root\s*\{(?P<body>[^}]*)\}", css)
    dark_match = re.search(
        r':root:not\(\[data-theme\]\),\s*:root\[data-theme="dark"\]\s*'
        r"\{(?P<body>[^}]*)\}",
        css,
    )
    assert light_match and dark_match

    def declarations(body: str) -> dict[str, str]:
        return {
            name: value.strip() for name, value in re.findall(r"--([\w-]+)\s*:\s*([^;]+);", body)
        }

    return declarations(light_match.group("body")), declarations(dark_match.group("body"))


def _resolve_hex(properties: dict[str, str], name: str) -> tuple[int, int, int]:
    value = properties[name]
    visited = {name}
    while match := re.fullmatch(r"var\(--([\w-]+)\)", value):
        name = match.group(1)
        assert name not in visited
        visited.add(name)
        value = properties[name]
    match = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    assert match, f"--{name} must resolve to a six-digit hex color, got {value!r}"
    raw = match.group(1)
    return tuple(int(raw[index : index + 2], 16) for index in (0, 2, 4))


def _contrast_ratio(
    foreground: tuple[int, int, int],
    background: tuple[int, int, int],
) -> float:
    def luminance(color: tuple[int, int, int]) -> float:
        channels = [
            channel / 255 / 12.92
            if channel / 255 <= 0.04045
            else ((channel / 255 + 0.055) / 1.055) ** 2.4
            for channel in color
        ]
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    lighter, darker = sorted(
        (luminance(foreground), luminance(background)),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def test_homepage_replaces_the_screaming_block_receipt_with_a_compact_outcome():
    page = (SITE / "index.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert "hero-receipt__badge" not in page
    assert "DRAIN BLOCKED" not in page
    assert "NO ACTION ACCEPTED" not in page
    assert "data-incident-outcome" in page
    assert re.search(r"data-incident-verdict[^>]*>\s*BLOCK\s*<", page)
    trace_label = re.search(
        r"\.control-trace__decision > span\.status-label\s*\{(?P<body>[^}]*)\}",
        css,
    )
    assert trace_label
    assert "color: var(--on-danger);" in trace_label.group("body")


def test_homepage_uses_a_short_direct_narrative_of_at_most_seven_sections():
    parser = _HomepageStructureParser()
    parser.feed((SITE / "index.html").read_text(encoding="utf-8"))

    assert len(parser.top_level_sections) <= 7, parser.top_level_sections
    assert 1 <= len(_words(parser.hero_heading)) <= 12
    assert 1 <= len(_words(parser.hero_copy)) <= 26
    assert parser.hero_copy.count(".") <= 2


def test_stylesheet_is_one_restrained_system_without_layered_award_effects():
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    forbidden = (
        "Enterprise polish pass",
        "Award pass",
        "Scroll-reveal motion",
        ".js-enabled .reveal",
        ".reveal.reveal-in",
        "receipt-sheen",
        "background-clip: text",
    )
    present = [marker for marker in forbidden if marker in css]

    assert not present, f"Remove layered visual-effect systems: {present}"


def test_brand_accent_is_visually_distinct_from_sanitize_and_block_in_both_themes():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    for theme, properties in zip(("light", "dark"), _theme_properties(css), strict=True):
        accent = _resolve_hex(properties, "accent")
        for semantic_name in ("sanitize", "block"):
            semantic = _resolve_hex(properties, semantic_name)
            distance = math.dist(accent, semantic)
            assert distance >= 48, (
                f"{theme} --accent and --{semantic_name} are only {distance:.1f} RGB units apart"
            )


def test_control_borders_and_error_text_meet_non_text_and_text_contrast():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    for theme, properties in zip(("light", "dark"), _theme_properties(css), strict=True):
        control_border = _resolve_hex(properties, "control-border")
        for surface_name in ("bg", "surface"):
            ratio = _contrast_ratio(control_border, _resolve_hex(properties, surface_name))
            assert ratio >= 3, f"{theme} control border contrast is {ratio:.2f}:1"

        error_text = _resolve_hex(properties, "error-text")
        surface_soft = _resolve_hex(properties, "surface-soft")
        ratio = _contrast_ratio(error_text, surface_soft)
        assert ratio >= 4.5, f"{theme} error text contrast is {ratio:.2f}:1"

        block = _resolve_hex(properties, "block")
        diff_background = tuple(
            round(block_channel * 0.1 + surface_channel * 0.9)
            for block_channel, surface_channel in zip(block, surface_soft, strict=True)
        )
        diff_ratio = _contrast_ratio(error_text, diff_background)
        assert diff_ratio >= 4.5, f"{theme} removed-diff contrast is {diff_ratio:.2f}:1"

    button_rule = re.search(
        r"\.button,\s*\.copy-button\s*\{(?P<body>[^}]*)\}",
        css,
    )
    assert button_rule
    assert "border: 1px solid var(--control-border);" in button_rule.group("body")


def test_mobile_status_keeps_a_visible_non_color_state_label():
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert '.status-pill[data-health-state="live"]::after' in css
    assert '.status-pill[data-health-state="unavailable"]::after' in css
    assert 'content: "UP";' in css
    assert 'content: "OFF";' in css


def test_shared_shell_uses_direct_navigation_and_one_footer_positioning_line():
    rendered = page_shell(
        "Mature shell",
        "Shared shell maturity contract.",
        "<section>Content</section>",
        active="playground",
    )
    navigation = re.search(
        r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
        rendered,
        re.DOTALL,
    )
    footer = re.search(
        r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
        rendered,
        re.DOTALL,
    )
    assert navigation and footer

    assert '<details class="nav-group' not in navigation.group("body")
    assert navigation.group("body").count("<summary>") <= 1
    for href in ("/playground", "/integrate", "/docs"):
        assert f'href="{href}"' in navigation.group("body")
    assert '<a class="header-integrate" href="/integrate">Integrate</a>' in rendered

    footer_positioning = footer.group("body").split("<nav", 1)[0]
    assert footer_positioning.count("<span>") == 1


def test_manual_top_level_footers_match_the_canonical_information_architecture():
    expected = [(href, label) for _, items in NAV_GROUPS for href, label, _ in items] + [
        ("/trust", "Trust &amp; security"),
        ("/privacy", "Privacy"),
        ("/terms", "Terms"),
    ]

    for filename in MANUAL_TOP_LEVEL_PAGES:
        source = (SITE / filename).read_text(encoding="utf-8")
        footer = re.search(
            r'<footer class="site-footer page-shell">(?P<body>.*?)</footer>',
            source,
            re.DOTALL,
        )
        assert footer, filename
        links = [
            (href, re.sub(r"\s+", " ", label).strip())
            for href, label in re.findall(
                r'<a href="([^"]+)"[^>]*>(.*?)</a\s*>',
                footer.group("body"),
                re.DOTALL,
            )
        ]
        assert links == expected, filename


def test_manual_scan_ctas_and_compact_labels_use_the_canonical_mature_copy():
    for filename in MANUAL_TOP_LEVEL_PAGES:
        source = (SITE / filename).read_text(encoding="utf-8")
        assert "Run live scan" not in source, filename
        assert source.count("Run a live scan") >= 2, filename
        assert re.search(
            r'<a class="header-integrate" href="/integrate">\s*Integrate\s*</a',
            source,
        ), filename

    css = (SITE / "styles.css").read_text(encoding="utf-8")
    command_stage = re.search(
        r"\.command-stage-state\s*\{(?P<body>[^}]*)\}",
        css,
    )
    agent_label = re.search(
        r"\.agent-row \[data-label\]::before\s*\{(?P<body>[^}]*)\}",
        css,
    )
    assert command_stage
    assert agent_label
    assert re.search(r"font-size:\s*10px;", command_stage.group("body"))
    assert re.search(r"font-size:\s*11px;", agent_label.group("body"))

    for selector in (
        r"\.incident-readout dt",
        r"\.incident-readout dd",
        r"\.offline-proof__evidence dt",
        r"\.offline-proof__evidence dd",
    ):
        rule = re.search(
            rf"{selector}\s*\{{(?=[^}}]*font-size:\s*11px;)[^}}]*\}}",
            css,
        )
        assert rule

    open_header = re.search(
        r"body\.nav-open \.site-header\s*\{(?P<body>[^}]*)\}",
        css,
    )
    assert open_header
    assert "backdrop-filter: none;" in open_header.group("body")


def test_product_routes_use_one_claim_model_and_one_step_vocabulary():
    theater = (SITE / "theater.html").read_text(encoding="utf-8")
    playground = (SITE / "playground.html").read_text(encoding="utf-8")
    showcase = (SITE / "showcase.html").read_text(encoding="utf-8")
    showcase_script = (SITE / "showcase.js").read_text(encoding="utf-8")
    gauntlet = (SITE / "gauntlet.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert '<a class="nav-link is-active-section" href="/">Product</a>' in theater
    assert 'aria-current="page"' not in re.search(
        r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
        theater,
        re.DOTALL,
    ).group("body")
    assert 'href="/gauntlet" aria-current="page"' not in theater
    assert "endpoint-key control" not in theater
    assert "guard freshness" not in theater
    assert "explicit unavailable state" in theater
    assert "does not prove every request traversed the guard" in theater

    assert "02 / Warden decision" in playground
    assert "03 / Caller action" in playground
    assert "02 / Recommended next action" not in playground

    assert 'class="showcase-gate"' not in showcase
    assert 'class="action-sequence"' in showcase
    assert "Integrate in 5 minutes" in showcase
    assert "Run scan" not in showcase
    assert '"Run scan"' not in showcase_script
    assert "Run a live scan" in showcase
    assert "Run a live scan" in showcase_script
    assert ".showcase-gate" not in css
    assert ".gate-rail" not in css

    normalized_gauntlet = " ".join(gauntlet.lower().split())
    assert normalized_gauntlet.count("not a confirmed bypass") == 1
    assert '<p class="eyebrow">Findings</p>' not in gauntlet
    assert '<p class="eyebrow">Confirmed findings</p>' not in gauntlet
    assert '<p class="eyebrow">Latest certificate</p>' not in gauntlet


def test_section_proxy_navigation_is_visual_without_claiming_the_current_page():
    proxies = {
        "theater.html": ("/", "Product"),
        "hire.html": ("/", "Product"),
        "showcase.html": ("/gauntlet", "Research"),
        "badges.html": ("/verify", "Evidence"),
        "badge.html": ("/verify", "Evidence"),
        "log.html": ("/verify", "Evidence"),
        "status.html": ("/verify", "Evidence"),
    }

    for filename, (href, label) in proxies.items():
        source = (SITE / filename).read_text(encoding="utf-8")
        navigation = re.search(
            r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
            source,
            re.DOTALL,
        )
        assert navigation, filename
        assert (
            f'<a class="nav-link is-active-section" href="{href}">{label}</a>'
            in navigation.group("body")
        ), filename
        assert 'aria-current="page"' not in navigation.group("body"), filename

    for canonical_path in ("/agents", "/agents/3808"):
        generated = page_shell(
            "Marketplace evidence",
            "Generated marketplace route.",
            "<section>Content</section>",
            active="agents",
            canonical_path=canonical_path,
        )
        navigation = re.search(
            r'<nav class="site-nav"[^>]*>(?P<body>.*?)</nav>',
            generated,
            re.DOTALL,
        )
        assert navigation
        assert (
            '<a class="nav-link is-active-section" href="/verify">Evidence</a>'
            in navigation.group("body")
        )
        assert 'aria-current="page"' not in navigation.group("body")


def test_endpoint_audit_lifecycle_uses_the_gold_evidence_ledger():
    page = (SITE / "badge.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")

    assert 'class="console-card badge-detail"' in page
    assert page.count('class="badge-evidence"') == 5
    for selector in (
        ".badge-detail",
        ".badge-detail::before",
        ".badge-detail .badge-evidence-grid",
        ".badge-detail .badge-evidence",
        ".badge-detail .badge-evidence:first-child",
        ".badge-detail .badge-evidence:last-child",
    ):
        assert selector in css
