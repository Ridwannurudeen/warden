"""Routing and static contracts for the human APA transparency log."""

from __future__ import annotations

import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from scripts.preview_site import _is_api_path, app
from warden.badges import b64u_encode

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def test_preview_routes_all_apa_and_issuer_requests_to_the_api(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))

    assert _is_api_path("/apa/log") is True
    assert _is_api_path("/apa/attestation/missing") is True
    assert _is_api_path("/.well-known/apa-issuer.json") is True
    assert _is_api_path("/log.js") is False

    with TestClient(app) as client:
        log_json = client.get("/apa/log")
        log_html = client.get("/apa/log", headers={"accept": "text/html"})
        missing = client.get("/apa/attestation/missing")
        issuer = client.get("/.well-known/apa-issuer.json")
        script = client.get("/log.js")

    assert log_json.json() == {"entries": [], "total": 0, "next_cursor": None}
    assert log_html.headers["content-type"].startswith("text/html")
    assert "data-apa-log" in log_html.text
    assert missing.status_code == 404
    assert missing.headers["content-type"].startswith("application/json")
    assert issuer.json()["issuer"] == "warden"
    assert script.status_code == 200
    assert script.headers["content-type"].startswith(("text/javascript", "application/javascript"))


def test_log_page_is_csp_compatible_and_states_the_verification_boundary():
    page = (SITE / "log.html").read_text(encoding="utf-8")
    script = (SITE / "log.js").read_text(encoding="utf-8")

    assert 'rel="canonical" href="https://warden.gudman.xyz/apa/log"' in page
    assert "data-apa-log" in page
    assert "data-apa-log-entries" in page
    assert "data-apa-log-retry" in page
    assert re.search(r'<script src="/log\.js\?v=[0-9a-f]{8}" defer></script>', page)
    assert "independently timestamped or witnessed" in page
    assert "coherent database rollback" in page
    assert "fetchLogPages" in script
    assert "`/apa/log?cursor=${cursor}&limit=${pageSize}`" in script
    assert 'accept: "application/json"' in script
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "<style" not in page
    assert " style=" not in page
    assert "<script>" not in page


def test_nginx_proxies_apa_and_issuer_routes_without_changing_static_fallbacks():
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")

    assert "location /apa/" in nginx
    assert "location = /.well-known/apa-issuer.json" in nginx
    assert nginx.count("proxy_pass http://127.0.0.1:8031;") >= 7
    assert "try_files $uri $uri.html =404;" in nginx
