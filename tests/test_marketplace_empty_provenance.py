"""Regression coverage for an empty but complete marketplace snapshot."""

from warden.marketplace.fetch import SnapshotMetadata
from warden.marketplace.render import render_marketplace


def test_empty_complete_marketplace_snapshot_is_dated_not_degraded(tmp_path):
    coverage = SnapshotMetadata(
        schema_version=2,
        captured_at="2026-07-18T12:00:00Z",
        query="no-results",
        page_size=10,
        sampled=0,
        expected=0,
        dropped=0,
    )

    render_marketplace([], tmp_path, coverage=coverage)

    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert 'data-source-stamp="DATED"' in page
    assert 'data-source-stamp="DEGRADED"' not in page
    assert "Complete discovery response" in page
    assert "Partial/degraded discovery response" not in page
