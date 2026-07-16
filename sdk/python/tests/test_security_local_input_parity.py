import pytest

from warden.core.verdict import Verdict
from warden.models import MAX_PAYLOAD_LENGTH
from warden_guard.client import LocalEngine


@pytest.mark.asyncio
async def test_local_engine_rejects_oversized_payload_before_scanning():
    local = LocalEngine()
    calls = []

    class RecordingEngine:
        async def scan(self, payload, *, depth, context):
            calls.append(payload)
            return Verdict(
                verdict="ALLOW",
                risk_level="NONE",
                sanitized_payload=payload,
            )

    local._engine = RecordingEngine()
    maximum = "x" * MAX_PAYLOAD_LENGTH

    accepted = await local.scan(maximum, depth="fast", expected_addresses=None)
    with pytest.raises(ValueError):
        await local.scan(maximum + "x", depth="fast", expected_addresses=None)

    assert accepted["sanitized_payload"] == maximum
    assert calls == [maximum]
