import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.reprobe_protections import reprobe_protections
from warden import protection, protection_store
from warden.badges import b64u_encode


@pytest.fixture(autouse=True)
def _apa_environment(tmp_path, monkeypatch):
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )


@pytest.mark.asyncio
async def test_inflight_reprobe_does_not_overwrite_newer_active_refresh():
    endpoint_host = "refresh-during-probe.example.org"
    endpoint_key = Ed25519PrivateKey.generate()
    endpoint_pub = b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")
    original = protection.issue_attestation(endpoint_host, endpoint_pub, 10)
    protection_store.commit_attestation_events(
        [("issued", original)],
        new_binding=(endpoint_host, endpoint_pub),
    )
    original_verified_at = int(original["verified_at"])
    newer = protection.refresh_attestation(
        original,
        99,
        verified_at=original_verified_at + 100,
    )

    async def probe_guard(endpoint):
        assert endpoint == f"https://{endpoint_host}"
        protection_store.commit_attestation_events([("refreshed", newer)])
        return endpoint_host, endpoint_pub, 11

    summary = await reprobe_protections(
        probe_guard=probe_guard,
        now=original_verified_at + 10,
    )

    assert protection_store.get_attestation(str(original["attestation_id"])) == newer
    assert summary["active"] == 0
    assert summary["skipped"] == 1
    assert [entry["event"] for entry in protection_store.read_log()] == [
        "issued",
        "refreshed",
    ]
