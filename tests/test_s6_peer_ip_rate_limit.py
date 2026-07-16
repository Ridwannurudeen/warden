"""Regression coverage for trusted rate-limit client identity."""

import re
from pathlib import Path
from types import SimpleNamespace

from warden import ratelimit


ROOT = Path(__file__).resolve().parents[1]


def _request(peer: str, real_ip: str):
    return SimpleNamespace(
        headers={"x-real-ip": real_ip},
        client=SimpleNamespace(host=peer),
    )


def test_non_loopback_peer_cannot_rotate_buckets_with_x_real_ip():
    ratelimit._reset_state()

    for suffix in range(2):
        request = _request("198.51.100.20", f"203.0.113.{suffix}")
        assert ratelimit.check_rate_limit(request, 2) is False

    forged = _request("198.51.100.20", "203.0.113.200")
    assert ratelimit.check_rate_limit(forged, 2) is True
    assert ratelimit._client_ip(forged) == "198.51.100.20"


def test_loopback_proxy_uses_nginx_overwritten_real_ip():
    assert ratelimit._client_ip(_request("127.0.0.1", "203.0.113.21")) == "203.0.113.21"


def test_every_nginx_proxy_location_overwrites_x_real_ip():
    config = (ROOT / "deploy" / "nginx-warden.conf").read_text(encoding="utf-8")
    proxy_locations = re.findall(r"location\s+[^\{]+\{[^\}]*proxy_pass[^\}]*\}", config, re.DOTALL)

    assert proxy_locations
    assert all(
        "proxy_set_header X-Real-IP $remote_addr;" in location
        for location in proxy_locations
    )
