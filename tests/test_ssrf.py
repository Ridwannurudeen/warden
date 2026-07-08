"""SSRF IP filtering tests for the audit endpoint."""

import ipaddress

from warden.auditor import AgentAuditor


def test_audit_blocks_non_global_ips():
    blocked_addresses = [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
    ]

    for address in blocked_addresses:
        ip = ipaddress.ip_address(address)
        assert AgentAuditor._is_blocked_ip(ip) is True


def test_audit_allows_global_ip():
    ip = ipaddress.ip_address("93.184.216.34")
    assert AgentAuditor._is_blocked_ip(ip) is False
