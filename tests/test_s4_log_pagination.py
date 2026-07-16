"""Regression coverage for paginated, rate-limited APA log reads."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import protection_store, ratelimit
from warden.api import app
from warden.badges import b64u_encode


@pytest.fixture(autouse=True)
def _apa_env(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setenv("WARDEN_APA_LOG_RATE_LIMIT_PER_MIN", "0")
    ratelimit._reset_state()


def _seed_log(size: int) -> list[dict[str, object]]:
    events = [
        (
            "issued",
            {
                "attestation_id": f"attestation-{index}",
                "endpoint_host": "asp.example.org",
                "status": "active",
            },
        )
        for index in range(size)
    ]
    protection_store.commit_attestation_events(events)
    return protection_store.read_log()


def test_log_cursor_pages_bound_serialization_including_default_page(monkeypatch):
    entries = _seed_log(5)
    monkeypatch.setattr("warden.api.APA_LOG_DEFAULT_PAGE_SIZE", 2)

    with TestClient(app) as client:
        legacy = client.get("/apa/log")
        first = client.get("/apa/log?cursor=0&limit=2")
        second = client.get("/apa/log?cursor=2&limit=2")
        final = client.get("/apa/log?cursor=4&limit=2")

    assert legacy.json() == {
        "entries": entries[:2],
        "total": 5,
        "next_cursor": 2,
    }
    assert first.json() == {
        "entries": entries[:2],
        "total": 5,
        "next_cursor": 2,
    }
    assert second.json() == {
        "entries": entries[2:4],
        "total": 5,
        "next_cursor": 4,
    }
    assert final.json() == {
        "entries": entries[4:],
        "total": 5,
        "next_cursor": None,
    }


def test_log_and_checkpoint_share_a_separate_bounded_read_bucket(monkeypatch):
    _seed_log(1)
    monkeypatch.setenv("WARDEN_APA_LOG_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()

    with TestClient(app) as client:
        assert client.get("/apa/log").status_code == 200
        assert client.get("/apa/log/checkpoint").status_code == 200
        exceeded = client.get("/apa/log")

    assert exceeded.status_code == 429
    assert exceeded.headers.get("Retry-After") is not None
