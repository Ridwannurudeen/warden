"""Standalone SSRF-safe URL validation shared by the auditor and APA prober."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import ParseResult, urlparse


async def validate_public_http_url(target_url: str) -> tuple[str, str, ParseResult]:
    """
    Validate target_url and pin it to one resolved IP.

    DNS is resolved exactly once here; the returned connect_url embeds that
    IP so the later request cannot be re-resolved to a different (rebound)
    address. TLS SNI and the Host header still use the original hostname.
    Returns ``(connect_url, host_header, parsed)``.
    """
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target_url must use http or https")
    if not parsed.hostname:
        raise ValueError("target_url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("target_url must not include credentials")

    addresses = await resolve_host(parsed.hostname)
    if not addresses:
        raise ValueError("target_url hostname did not resolve")
    pinned_ip: str | None = None
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if is_blocked_ip(ip):
            raise ValueError("target_url resolves to a blocked internal address")
        if pinned_ip is None:
            pinned_ip = address

    host_for_url = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    connect_url = f"{parsed.scheme}://{host_for_url}:{port}{path}"
    return connect_url, parsed.hostname, parsed


async def resolve_host(hostname: str) -> set[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return set()
    return {info[4][0] for info in infos}


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not ip.is_global
