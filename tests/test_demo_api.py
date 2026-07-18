"""Public demo API contract tests."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import warden.api as api_module
from warden import ratelimit
from warden.api import app
from warden.core.verdict import ReasonCode

ROOT = Path(__file__).resolve().parents[1]
THEATER_CASES = json.loads(
    (ROOT / "tests" / "fixtures" / "theater_attacks.json").read_text(encoding="utf-8")
)


def test_attack_theater_fixture_contains_no_private_key_shaped_literal():
    source = (ROOT / "tests" / "fixtures" / "theater_attacks.json").read_text(encoding="utf-8")

    assert re.search(r"(?<![A-Fa-f0-9])0x[A-Fa-f0-9]{64}(?![A-Fa-f0-9])", source) is None


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


def test_attack_theater_sequence_uses_real_demo_verdicts():
    headers = {"x-real-ip": "203.0.113.91"}

    with TestClient(app) as client:
        for attack in THEATER_CASES:
            response = client.post("/api/demo/scan", json=attack["request"], headers=headers)

            assert response.status_code == 200
            result = response.json()
            assert result["verdict"] == attack["expectedVerdict"]
            assert result["threat_classes"] == [attack["expectedThreat"]]
            assert result["sanitized_payload"] != attack["request"]["payload"]
            assert isinstance(result["latency_ms"], float)
            assert result["latency_ms"] >= 0
            assert "asp_receipt" not in result


@pytest.mark.parametrize("attack", THEATER_CASES, ids=lambda attack: attack["id"])
def test_attack_theater_gates_the_demo_asp_with_exact_live_payloads(monkeypatch, attack):
    monkeypatch.setenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "0")
    delivered: list[str] = []

    def record_demo_delivery(payload: str) -> dict[str, object]:
        delivered.append(payload)
        return {
            "handler": "warden-demo-asp",
            "invoked": True,
            "received_payload": payload,
        }

    monkeypatch.setattr(api_module, "_demo_theater_asp_handler", record_demo_delivery)
    with TestClient(app) as client:
        response = client.post("/api/demo/theater", json=attack["request"])

    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == attack["expectedVerdict"]
    assert result["threat_classes"] == [attack["expectedThreat"]]
    receipt = result["asp_receipt"]
    assert set(receipt) == {"handler", "invoked", "received_payload"}
    assert receipt["handler"] == "warden-demo-asp"
    if attack["expectedVerdict"] == "BLOCK":
        assert delivered == []
        assert receipt == {
            "handler": "warden-demo-asp",
            "invoked": False,
            "received_payload": None,
        }
    else:
        assert result["sanitized_payload"] != attack["request"]["payload"]
        assert delivered == [result["sanitized_payload"]]
        assert receipt["invoked"] is True
        assert receipt["received_payload"] == result["sanitized_payload"]


def test_attack_theater_allows_only_the_original_payload_to_reach_demo_asp(monkeypatch):
    monkeypatch.setenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "0")
    original = "Agent response: invoice reconciled, no action required."
    delivered: list[str] = []

    def record_demo_delivery(payload: str) -> dict[str, object]:
        delivered.append(payload)
        return {
            "handler": "warden-demo-asp",
            "invoked": True,
            "received_payload": payload,
        }

    monkeypatch.setattr(api_module, "_demo_theater_asp_handler", record_demo_delivery)
    with TestClient(app) as client:
        response = client.post("/api/demo/theater", json={"payload": original})

    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "ALLOW"
    assert result["sanitized_payload"] == original
    assert delivered == [original]
    assert result["asp_receipt"] == {
        "handler": "warden-demo-asp",
        "invoked": True,
        "received_payload": original,
    }


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


def test_demo_scan_and_theater_stay_free_when_payment_middleware_is_enabled():
    script = """
from fastapi.testclient import TestClient
from warden.api import app

with TestClient(app) as client:
    for path in ('/api/demo/scan', '/api/demo/theater'):
        response = client.post(path, json={'payload': 'normal settlement note'})
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
            "OKX_BASE_URL": "https://web3.okx.com",
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
