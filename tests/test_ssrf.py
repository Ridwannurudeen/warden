"""SSRF IP filtering tests for the audit endpoint."""

import asyncio
import ipaddress

import pytest

from warden.auditor import AgentAuditor


def test_audit_blocks_non_global_ips():
    blocked_addresses = [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "::127.0.0.1",
        "::169.254.169.254",
        "64:ff9b::169.254.169.254",
        "224.0.0.1",
    ]

    for address in blocked_addresses:
        ip = ipaddress.ip_address(address)
        assert AgentAuditor._is_blocked_ip(ip) is True


def test_audit_allows_global_ip():
    ip = ipaddress.ip_address("93.184.216.34")
    assert AgentAuditor._is_blocked_ip(ip) is False


def test_audit_allows_nat64_mapped_global_ip():
    ip = ipaddress.ip_address("64:ff9b::8.8.8.8")
    assert AgentAuditor._is_blocked_ip(ip) is False


@pytest.mark.asyncio
async def test_audit_url_validation_has_a_deadline(monkeypatch):
    auditor = AgentAuditor()

    async def never_resolves(target_url: str):
        await asyncio.Event().wait()

    monkeypatch.setattr(auditor, "_validate_public_http_url", never_resolves)
    monkeypatch.setattr("warden.auditor.AUDIT_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(ValueError, match="target_url validation timed out"):
        await asyncio.wait_for(auditor.audit("https://example.org/scan"), timeout=0.1)
