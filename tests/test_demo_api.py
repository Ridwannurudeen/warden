"""Public demo API contract tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from warden import ratelimit
from warden.api import app
from warden.core.verdict import ReasonCode

ROOT = Path(__file__).resolve().parents[1]


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _corpus_entry(filename: str, entry_id: str) -> dict[str, object]:
    entries = _load_jsonl(ROOT / "corpus" / filename)
    return next(entry for entry in entries if entry["id"] == entry_id)


def test_demo_scan_blocks_known_corpus_attack():
    attack = _corpus_entry("attacks.jsonl", "drain-001")
    with TestClient(app) as client:
        response = client.post(
            "/api/demo/scan",
            json={"payload": attack["payload"], "context": attack["context"]},
        )

    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    assert "DRAIN_ADDRESS" in response.json()["threat_classes"]


def test_demo_scan_allows_known_benign_corpus_entry():
    benign = _corpus_entry("benign.jsonl", "benign-003")
    with TestClient(app) as client:
        response = client.post("/api/demo/scan", json={"payload": benign["payload"]})

    assert response.status_code == 200
    assert response.json()["verdict"] == "ALLOW"


def test_demo_scan_truncates_oversized_payload():
    payload = "z" * 4_001
    with TestClient(app) as client:
        response = client.post("/api/demo/scan", json={"payload": payload})

    assert response.status_code == 200
    assert len(response.json()["sanitized_payload"]) == 4_000


def test_demo_scan_rejects_oversized_context():
    with TestClient(app) as client:
        response = client.post(
            "/api/demo/scan",
            json={"payload": "clean", "context": {"expected_addresses": ["x"] * 21}},
        )

    assert response.status_code == 422


def test_demo_scan_never_honors_thorough_depth():
    attack = _corpus_entry("attacks.jsonl", "corpus-001")
    with TestClient(app) as client:
        response = client.post(
            "/api/demo/scan",
            json={"payload": attack["payload"], "depth": "thorough"},
        )

    assert response.status_code == 200
    assert response.json()["verdict"] == "ALLOW"
    assert response.json()["threat_classes"] == []


def test_demo_and_paid_rate_limit_budgets_are_independent(monkeypatch):
    monkeypatch.setenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "2")
    ratelimit._reset_state()
    headers = {"x-real-ip": "203.0.113.40"}

    with TestClient(app) as client:
        assert client.get("/api/demo/examples", headers=headers).status_code == 200
        assert client.get("/api/demo/examples", headers=headers).status_code == 200
        assert client.get("/api/demo/examples", headers=headers).status_code == 429

        assert client.post("/scan", json={"payload": "clean"}, headers=headers).status_code == 200
        assert client.post("/scan", json={"payload": "clean"}, headers=headers).status_code == 200
        assert client.post("/scan", json={"payload": "clean"}, headers=headers).status_code == 429


def test_demo_examples_are_curated_from_corpus():
    attacks = _load_jsonl(ROOT / "corpus" / "attacks.jsonl")
    benign = _load_jsonl(ROOT / "corpus" / "benign.jsonl")
    corpus_payloads = {entry["payload"] for entry in attacks + benign}

    with TestClient(app) as client:
        response = client.get("/api/demo/examples")

    assert response.status_code == 200
    examples = response.json()
    assert len({example["id"] for example in examples}) == len(examples)
    assert all(set(example) == {"id", "label", "reason_code", "payload"} for example in examples)
    assert all(example["payload"] in corpus_payloads for example in examples)
    assert {example["reason_code"] for example in examples if example["reason_code"]} == {
        reason.value for reason in ReasonCode if reason is not ReasonCode.CORPUS_MATCH
    }
    assert sum(example["reason_code"] is None for example in examples) == 2


def test_demo_scan_stays_free_when_payment_middleware_is_enabled():
    script = """
from fastapi.testclient import TestClient
from warden.api import app

with TestClient(app) as client:
    response = client.post('/api/demo/scan', json={'payload': 'normal settlement note'})
assert response.status_code == 200, response.text
assert 'payment-required' not in response.headers
"""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OKX_") and key != "PAY_TO_ADDRESS"
    }
    env.update(
        {
            "OKX_API_KEY": "demo-test-api-key",
            "OKX_SECRET_KEY": "demo-test-secret-key",
            "OKX_PASSPHRASE": "demo-test-passphrase",
            "OKX_BASE_URL": "http://127.0.0.1:9",
            "PAY_TO_ADDRESS": "0x0000000000000000000000000000000000000001",
            "WARDEN_BADGE_SECRET": "test-badge-secret",
            "WARDEN_DEMO_RATE_LIMIT_PER_MIN": "0",
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
