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


# Every app route must be a deliberate decision: either nginx proxies it to the
# app, or it is knowingly not reachable in production. The runbook drifted once
# because /harden was added to the app and the conf without this check existing.
PROXIED_APP_ROUTES = frozenset(
    {
        "/scan",
        "/audit",
        "/harden",
        "/variant-audit",
        "/variant-audit/{report_id}",
        "/variant-audit/{report_id}/badge",
        "/variant-audit/{report_id}/badge.svg",
        "/health",
        "/.well-known/apa-issuer.json",
        "/badge/{audit_id}",
        # /api/ and /apa/ are prefix-proxied, so every route beneath them is public.
        "/api/badges",
        "/api/demo/examples",
        "/api/demo/gauntlet",
        "/api/demo/gauntlet/breakers",
        "/api/demo/gauntlet/breakers/{certificate_id}",
        "/api/demo/gauntlet/stats",
        "/api/demo/scan",
        "/api/demo/theater",
        "/api/feedback",
        "/api/policy",
        "/api/shield/{target_id}/lineage",
        "/api/threat-intel/v1/summary",
        "/apa/attestation/{attestation_id}",
        "/apa/attestation/{attestation_id}/badge.svg",
        "/apa/audit/{audit_id}",
        "/apa/hardening/{pack_id}",
        "/apa/log",
        "/apa/log/anchor",
        "/apa/log/checkpoint",
        "/apa/register",
        "/apa/revoke",
    }
)

# Deliberately unreachable in production. Each entry needs a stated reason.
UNEXPOSED_APP_ROUTES = {
    "/": "shadowed by the static index.html; the JSON stub is local-only",
    "/health/stats": "operational counters, not a public surface (location = /health is exact-match)",
    "/health/ready": "consumed on localhost by warden-monitor.service, not published",
    "/docs": "nginx maps /docs to the generated static reason docs, not FastAPI's Swagger UI",
    "/docs/oauth2-redirect": "FastAPI Swagger helper; never published",
    "/openapi.json": "FastAPI schema; not published",
    "/redoc": "FastAPI ReDoc; not published",
}


def test_every_app_route_is_either_proxied_or_deliberately_unexposed() -> None:
    from warden.api import app

    app_routes = {route.path for route in app.routes if getattr(route, "path", "")}
    classified = PROXIED_APP_ROUTES | set(UNEXPOSED_APP_ROUTES)

    unclassified = app_routes - classified
    assert not unclassified, (
        "new app route(s) with no production exposure decision: "
        f"{sorted(unclassified)} — add to PROXIED_APP_ROUTES (and nginx) or to "
        "UNEXPOSED_APP_ROUTES with a reason"
    )
    stale = classified - app_routes
    assert not stale, f"route(s) listed here no longer exist on the app: {sorted(stale)}"


def test_nginx_proxies_every_route_marked_public() -> None:
    nginx = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")

    for exact in (
        "/scan",
        "/audit",
        "/harden",
        "/variant-audit",
        "/health",
        "/.well-known/apa-issuer.json",
    ):
        assert f"location = {exact} {{" in nginx, exact
    # Prefix and regex blocks that cover the remaining public routes.
    assert "location /api/ {" in nginx
    assert "location /apa/ {" in nginx
    assert "location ~ ^/badge/[^/]+/?$ {" in nginx
    assert r'location ~ "^/variant-audit/[a-f0-9]{64}(/badge(\.svg)?)?$" {' in nginx
    # No trailing-slash form: nothing routes it, and Starlette's redirect would
    # be built from the client-supplied Host header.
    assert r"(/badge(\.svg)?)?/?$" not in nginx
    # The paid route keeps its exact-match block: a regex location outranks a
    # prefix one, so an unanchored variant-audit regex would swallow it.
    assert "location = /variant-audit {" in nginx

    # The exact-match /health block must not accidentally become a prefix, which
    # would publish /health/stats and /health/ready.
    assert "location /health/" not in nginx
    assert "location = /health {" in nginx
