"""Production redesign contracts for information architecture and evidence UX."""

import re
from pathlib import Path

from warden.site_docs import load_reason_documents, render_docs


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def test_documentation_index_covers_the_complete_integration_journey(tmp_path):
    render_docs(ROOT, tmp_path)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")

    for section_id in (
        "quickstart",
        "concepts",
        "decision-contract",
        "reason-matrix",
        "integration-patterns",
        "evidence-apa",
        "transparency",
        "endpoint-audit",
        "limits",
        "troubleshooting",
    ):
        assert f'id="{section_id}"' in page
        assert f'href="#{section_id}"' in page
    assert "python -m pip install -e . -e sdk/python" in page
    assert "WardenClient(local=True, fail_open=False)" in page
    assert "ALLOW means no implemented detector fired" in page
    assert "point-in-time evidence, not certification" in page.lower()
    assert "data-doc-search" in page
    assert "Documentation version" in page
    assert "Last updated" in page


def test_documentation_index_leads_with_reference_content_not_marketing_cards(tmp_path):
    render_docs(ROOT, tmp_path)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")

    assert "<h1>Warden documentation</h1>" in page
    assert page.index('id="quickstart"') < page.index('id="reason-matrix"')
    assert page.index('id="reason-matrix"') < page.index('id="concepts"')
    assert "Filter reason codes" in page
    assert page.count('<div class="docs-reference-table"><table>') == 2
    assert page.count("<caption>") == 3
    assert "Implemented reason codes and observed regression outcomes" in page
    assert "Core concepts and their operational meaning" in page
    assert "Decision response fields and caller guidance" in page
    assert '<table class="docs-reference-table">' not in page
    assert "docs-decision-grid" not in page
    assert '<p class="eyebrow">Concepts</p>' not in page


def test_reason_pages_publish_machine_value_false_positive_and_guidance(tmp_path):
    documents = load_reason_documents(ROOT)
    render_docs(ROOT, tmp_path)

    for document in documents:
        page = (tmp_path / f"{document.slug}.html").read_text(encoding="utf-8")
        assert f"<code>{document.reason_code.value}</code>" in page
        assert "False-positive considerations" in page
        assert "Related integration guidance" in page
        assert '<div class="docs-reference-table"><table>' in page
        assert page.count("<caption>") == 1
        assert (
            f"<caption>{document.reason_code.value} observed detector contract</caption>"
            in page
        )
        assert '<table class="docs-reference-table">' not in page
        assert re.search(r'<nav class="table-of-contents"', page)
