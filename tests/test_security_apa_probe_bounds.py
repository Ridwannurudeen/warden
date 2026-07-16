import asyncio

import pytest

from warden import protection


@pytest.mark.asyncio
async def test_probe_deadline_and_concurrency_include_dns_resolution(monkeypatch):
    active = 0
    maximum_active = 0

    async def blocked_validation(endpoint):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        try:
            await asyncio.Future()
        finally:
            active -= 1

    monkeypatch.setattr(protection, "validate_public_http_url", blocked_validation)
    monkeypatch.setattr(protection, "PROBE_TIMEOUT_SECONDS", 0.01)

    results = await asyncio.wait_for(
        asyncio.gather(
            *(protection._fetch_proof(f"https://probe-{index}.example") for index in range(8)),
            return_exceptions=True,
        ),
        timeout=0.25,
    )

    assert maximum_active <= 4
    assert all(isinstance(result, protection.ProtectionProbeUnavailable) for result in results)
    assert all("timed out" in str(result) for result in results)
