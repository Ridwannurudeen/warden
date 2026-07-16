"""R3 regression for the production flat static-site layout."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_flat_nginx_root_serves_the_committed_index_artifacts() -> None:
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")

    assert "root /opt/warden-site;" in nginx
    assert "/opt/warden-site/current" not in nginx
    assert "/opt/warden-index" not in nginx
    assert "try_files /agents/index.html =404;" in nginx
    assert "location /data/" in nginx
    for artifact in (
        ROOT / "site" / "agents" / "index.html",
        ROOT / "site" / "data" / "marketplace-summary.json",
        ROOT / "site" / "data" / "warden-services.json",
    ):
        assert artifact.is_file()
