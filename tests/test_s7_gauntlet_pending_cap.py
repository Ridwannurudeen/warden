"""Regression coverage for bounded Gauntlet pending-claim retention."""

import json

from fastapi.testclient import TestClient

from warden import gauntlet_store, ratelimit
from warden.api import app


def test_public_gauntlet_retains_only_the_newest_pending_claims(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr(gauntlet_store, "_STORE_PATH", store_path)
    monkeypatch.setattr(gauntlet_store, "_MAX_RECORDS", 10)
    monkeypatch.setattr(gauntlet_store, "_MAX_PENDING_RECORDS", 2)
    monkeypatch.setenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "0")
    ratelimit._reset_state()

    with TestClient(app) as client:
        responses = [
            client.post(
                "/api/demo/gauntlet",
                json={
                    "intent": "custom bypass",
                    "payload": f"Ordinary calendar note number {index}.",
                },
            )
            for index in range(5)
        ]

    assert all(response.status_code == 200 for response in responses)
    assert all(response.json()["claim_status"] == "pending" for response in responses)
    records = [
        json.loads(line)
        for line in store_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert [record["payload"] for record in records] == [
        "Ordinary calendar note number 3.",
        "Ordinary calendar note number 4.",
    ]


def test_pending_cap_preserves_confirmed_bypasses(monkeypatch):
    monkeypatch.setattr(gauntlet_store, "_MAX_PENDING_RECORDS", 2)
    records = [
        {"status": "pending", "attempt_id": "pending-1"},
        {"status": "confirmed", "attempt_id": "confirmed"},
        {"status": "pending", "attempt_id": "pending-2"},
        {"status": "pending", "attempt_id": "pending-3"},
    ]

    retained = gauntlet_store._prune_records(records)

    assert [record["attempt_id"] for record in retained] == [
        "confirmed",
        "pending-2",
        "pending-3",
    ]
