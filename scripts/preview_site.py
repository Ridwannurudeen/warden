"""Serve the production-shaped static site and local API on one origin."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from warden.api import app as api_app


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
API_PATHS = {"/audit", "/harden", "/health", "/scan"}
PREVIEW_SECURITY_HEADERS = {
    b"content-security-policy": (
        b"default-src 'self'; base-uri 'none'; object-src 'none'; "
        b"frame-ancestors 'none'; form-action 'self'; script-src 'self'; "
        b"style-src 'self'; img-src 'self' data:; font-src 'self'; "
        b"connect-src 'self'; worker-src 'none'"
    ),
    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
    b"referrer-policy": b"strict-origin-when-cross-origin",
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
}


def _is_api_path(path: str) -> bool:
    return (
        path in API_PATHS
        or path.startswith("/api/")
        or path.startswith("/apa/")
        or path == "/.well-known/apa-issuer.json"
        or re.fullmatch(r"/badge/[^/]+/?", path) is not None
    )


def _static_candidate(path: str) -> str:
    if "\\" in path:
        return path
    route = path.strip("/")
    trailing_slash = path != "/" and path.endswith("/")
    if route in {"", "."}:
        return "index.html"
    if route in {"agents", "docs"}:
        return f"{route}/index.html"
    if route == "badges":
        return "badges.html"
    if re.fullmatch(r"agents/\d+", route):
        return f"{route}.html"
    if re.fullmatch(r"docs/[a-z0-9-]+", route):
        return f"{route}.html"
    if re.fullmatch(r"badges/[a-f0-9]{16}", route):
        return "badge.html"
    if "/" not in route and not PurePosixPath(route).suffix and not trailing_slash:
        return f"{route}.html"
    return path


def _has_exact_site_path(candidate: str) -> bool:
    if "\\" in candidate or candidate.endswith("/"):
        return False
    relative = candidate.replace("\\", "/").lstrip("/")
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False

    current = SITE
    for part in parts:
        try:
            current = next(entry for entry in current.iterdir() if entry.name == part)
        except (OSError, StopIteration):
            return False
    return current.is_file()


class PreviewStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope: Scope):
        candidate = _static_candidate(scope.get("path", path))
        if not _has_exact_site_path(candidate):
            return PlainTextResponse("Not Found", status_code=404)
        relative_candidate = candidate.replace("\\", "/").lstrip("/")
        try:
            response = await super().get_response(relative_candidate, scope)
        except HTTPException as exc:
            return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
        if relative_candidate == ".well-known/warden-consent":
            response.headers["content-type"] = "text/plain; charset=utf-8"
        return response


class PreviewApplication:
    def __init__(self, api: ASGIApp, static: ASGIApp) -> None:
        self.api = api
        self.static = static

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.api(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                headers.extend(
                    (name, value)
                    for name, value in PREVIEW_SECURITY_HEADERS.items()
                    if name not in existing
                )
                message["headers"] = headers
            await send(message)

        target = self.api if _is_api_path(scope.get("path", "")) else self.static
        await target(scope, receive, send_with_security_headers)


app = PreviewApplication(api_app, PreviewStaticFiles(directory=SITE, html=False))
