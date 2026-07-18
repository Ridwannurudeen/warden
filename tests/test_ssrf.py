"""SSRF IP filtering tests for the audit endpoint."""

import asyncio
import ipaddress
from urllib.parse import urlparse

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


@pytest.mark.asyncio
async def test_whole_audit_battery_has_a_deadline(monkeypatch):
    auditor = AgentAuditor()

    async def validate(target_url: str):
        return "https://93.184.216.34/scan", "example.org", urlparse(target_url)

    async def verify_consent(*args, **kwargs):
        return True

    async def never_finishes(*args, **kwargs):
        await asyncio.Event().wait()

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", verify_consent)
    monkeypatch.setattr(auditor, "_run_battery", never_finishes)
    monkeypatch.setattr("warden.auditor.httpx.AsyncClient", Client)
    monkeypatch.setattr("warden.auditor.AUDIT_TOTAL_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(
        "warden.auditor.issue_badge",
        lambda **kwargs: pytest.fail("a timed-out audit must not issue a partial badge"),
    )
    monkeypatch.setattr(
        "warden.auditor.record_badge",
        lambda badge: pytest.fail("a timed-out audit must not record a partial badge"),
    )

    with pytest.raises(
        ValueError,
        match="audit timed out; no partial grade or badge was issued",
    ):
        await asyncio.wait_for(auditor.audit("https://example.org/scan"), timeout=0.1)


@pytest.mark.parametrize(
    ("target_url", "hostname", "expected_authority"),
    [
        ("https://example.org:8443/scan", "example.org", "example.org:8443"),
        (
            "https://[2001:4860:4860::8888]:8443/scan",
            "2001:4860:4860::8888",
            "[2001:4860:4860::8888]:8443",
        ),
    ],
)
@pytest.mark.asyncio
async def test_audit_preserves_target_authority_for_requests(
    monkeypatch,
    target_url,
    hostname,
    expected_authority,
):
    auditor = AgentAuditor()
    captured: dict[str, object] = {}

    async def validate(candidate: str):
        return "https://93.184.216.34:8443/scan", hostname, urlparse(candidate)

    async def verify_consent(*args, **kwargs):
        return False

    class _Response:
        status_code = 200
        headers: dict[str, str] = {}

        async def aiter_raw(self, chunk_size: int | None = None):
            yield b"{}"

    class _Stream:
        async def __aenter__(self):
            return _Response()

        async def __aexit__(self, *args):
            return False

    class _Client:
        def __init__(self, *args, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url, **kwargs):
            captured["method"] = method
            captured["host_header"] = kwargs["headers"]["Host"]
            captured["sni_hostname"] = kwargs["extensions"]["sni_hostname"]
            return _Stream()

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate)
    monkeypatch.setattr(auditor, "_verify_target_consent", verify_consent)
    monkeypatch.setattr(
        auditor,
        "_load_representative_attacks",
        lambda: [{"id": "t1", "category": "TEST", "payload": "payload"}],
    )
    monkeypatch.setattr("warden.auditor.httpx.AsyncClient", _Client)

    response = await auditor.audit(target_url)

    assert response.consent_verified is False
    assert captured == {
        "method": "POST",
        "host_header": expected_authority,
        "sni_hostname": hostname,
    }
