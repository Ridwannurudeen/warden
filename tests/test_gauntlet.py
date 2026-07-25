"""Public Gauntlet API and persistence tests."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute

from warden import ratelimit
from warden.api import app
from warden.models import AuditRequest, AuditResponse, ScanRequest, ScanResponse


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def reset_rate_limits():
    ratelimit._reset_state()
    yield
    ratelimit._reset_state()


def _records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_gauntlet_blocks_known_attack_without_retaining_raw_payload(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)
    attack = next(
        json.loads(line)
        for line in (ROOT / "corpus" / "attacks.jsonl").read_text(encoding="utf-8").splitlines()
        if json.loads(line)["id"] == "drain-001"
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "drain_funds",
                "payload": attack["payload"],
                "context": attack["context"],
            },
        )

    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    assert response.json()["claim_status"] == "not_candidate"
    [record] = _records(store_path)
    assert record["verdict"] == "BLOCK"
    assert "payload" not in record
    assert "intent" not in record
    assert "context" not in record
    assert len(record["payload_hash"]) == 64


def test_allowed_claim_is_pending_and_never_auto_confirmed(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "hijack_tool_call",
                "payload": "A normal weather report for Lagos.",
                "finder": "researcher.example",
                "public_credit_consent": True,
                "training_use_consent": True,
            },
        )
        stats = client.get("/api/demo/gauntlet/stats")

    assert response.status_code == 200
    assert response.json()["verdict"] == "ALLOW"
    assert response.json()["claim_status"] == "pending"
    assert response.json()["claim_id"]
    [record] = _records(store_path)
    assert record["status"] == "pending"
    assert record["payload"] == "A normal weather report for Lagos."
    assert record["finder"] == "researcher.example"
    assert record["public_credit_consent"] is True
    assert record["training_use_consent"] is True
    assert len(record["training_consent_hash"]) == 64
    assert stats.json()["attempts"] == 1
    assert stats.json()["pending_claims"] == 1
    assert stats.json()["confirmed_bypasses"] == 0
    assert stats.json()["corpus_size"] >= 118


def test_gauntlet_normalizes_finder_format_controls_before_storage(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "other",
                "payload": "A routine account status note.",
                "finder": " \uff20researcher\u202e\u200b.example ",
                "public_credit_consent": True,
            },
        )

    assert response.status_code == 200
    [record] = _records(store_path)
    assert record["finder"] == "@researcher.example"


@pytest.mark.parametrize(
    "finder",
    [
        "researcher\u034f.example",
        "researcher\ufe0f.example",
        "researcher\u0085.example",
        "researcher.example\u0085",
        "\u001cresearcher.example",
        "researcher\ue000.example",
        "researcher\U0001ccd6.example",
        "researcher\u115f.example",
        "\u202e\u200b",
    ],
)
def test_gauntlet_rejects_non_visible_finder_characters(tmp_path, monkeypatch, finder):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "other",
                "payload": "A routine account status note.",
                "finder": finder,
                "public_credit_consent": True,
            },
        )

    assert response.status_code == 422
    assert not store_path.exists()


def test_gauntlet_accepts_visible_combining_script_finder(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)
    finder = "\u0928\u092e\u0938\u094d\u0924\u0947.example"

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "other",
                "payload": "A routine account status note.",
                "finder": finder,
                "public_credit_consent": True,
            },
        )

    assert response.status_code == 200
    [record] = _records(store_path)
    assert record["finder"] == finder


def test_duplicate_pending_claim_is_recorded_without_duplicate_raw_payload(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)
    request = {
        "intent": "exfiltrate_secret",
        "payload": "A routine account status note.",
        "finder": "first-finder",
    }

    with TestClient(app) as client:
        first = client.post("/api/demo/gauntlet", json=request)
        second = client.post("/api/demo/gauntlet", json={**request, "finder": "duplicate"})

    assert first.json()["claim_status"] == "pending"
    assert second.json()["claim_status"] == "duplicate"
    assert second.json()["claim_id"] == first.json()["claim_id"]
    records = _records(store_path)
    assert len(records) == 2
    assert "payload" in records[0]
    assert "payload" not in records[1]
    assert "intent" not in records[1]
    assert "context" not in records[1]
    assert records[1]["duplicate_of"] == records[0]["attempt_id"]


def test_duplicate_claim_normalizes_only_verdict_relevant_context(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)
    payload = "A routine account status note."

    with TestClient(app) as client:
        first = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "exfiltrate_secret",
                "payload": payload,
                "context": {
                    "expected_addresses": [
                        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "other-address",
                        "other-address",
                    ],
                    "source": "first-source",
                },
            },
        )
        second = client.post(
            "/api/demo/gauntlet",
            json={
                "intent": "exfiltrate_secret",
                "payload": payload,
                "context": {
                    "expected_addresses": [
                        "other-address",
                        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ],
                    "source": "second-source",
                },
            },
        )

    assert first.json()["claim_status"] == "pending"
    assert second.json()["claim_status"] == "duplicate"
    assert second.json()["claim_id"] == first.json()["claim_id"]
    records = _records(store_path)
    assert sum("payload" in record for record in records) == 1


def test_gauntlet_uses_shared_demo_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", tmp_path / "attempts.jsonl")
    monkeypatch.setenv("WARDEN_DEMO_RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setenv("WARDEN_RATE_LIMIT_PER_MIN", "1")
    ratelimit._reset_state()
    headers = {"x-real-ip": "203.0.113.88"}
    request = {"intent": "other", "payload": "Normal status update."}

    with TestClient(app) as client:
        assert client.get("/api/demo/examples", headers=headers).status_code == 200
        assert client.post("/api/demo/gauntlet", json=request, headers=headers).status_code == 200
        limited = client.post("/api/demo/gauntlet", json=request, headers=headers)
        assert client.post("/scan", json={"payload": "clean"}, headers=headers).status_code == 200
        paid_limited = client.post("/scan", json={"payload": "clean"}, headers=headers)

    assert limited.status_code == 429
    assert limited.headers["Retry-After"]
    assert paid_limited.status_code == 429


def test_gauntlet_rejects_blank_payload_and_invalid_intent(tmp_path, monkeypatch):
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", tmp_path / "attempts.jsonl")
    with TestClient(app) as client:
        blank = client.post(
            "/api/demo/gauntlet",
            json={"intent": "drain_funds", "payload": "   "},
        )
        invalid = client.post(
            "/api/demo/gauntlet",
            json={"intent": "   ", "payload": "test"},
        )

    assert blank.status_code == 422
    assert invalid.status_code == 422
    assert not (tmp_path / "attempts.jsonl").exists()


def test_gauntlet_truncates_candidate_to_demo_cap(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/demo/gauntlet",
            json={"intent": "custom attack", "payload": "z" * 4001},
        )

    assert response.status_code == 200
    [record] = _records(store_path)
    assert len(record["payload"]) == 4000


def test_concurrent_duplicate_claims_create_one_pending_raw_record(tmp_path, monkeypatch):
    store_path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", store_path)
    ratelimit._reset_state()
    request = {"intent": "custom bypass", "payload": "An ordinary calendar note."}

    def submit(index):
        with TestClient(app) as client:
            return client.post(
                "/api/demo/gauntlet",
                json=request,
                headers={"x-real-ip": f"198.51.100.{index}"},
            ).json()

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(submit, range(8)))

    records = _records(store_path)
    assert len(records) == 8
    assert sum(record["status"] == "pending" for record in records) == 1
    assert sum("payload" in record for record in records) == 1
    assert {response["claim_status"] for response in responses} == {"pending", "duplicate"}


def test_gauntlet_stats_from_fresh_store_exposes_counts_only(tmp_path, monkeypatch):
    monkeypatch.setattr("warden.gauntlet_store._STORE_PATH", tmp_path / "attempts.jsonl")
    with TestClient(app) as client:
        response = client.get("/api/demo/gauntlet/stats")
        health = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "attempts": 0,
        "pending_claims": 0,
        "confirmed_bypasses": 0,
        "corpus_size": health.json()["corpus_size"],
    }


def test_gauntlet_stays_free_when_payment_middleware_is_enabled():
    script = """
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from warden.api import app
import warden.gauntlet_store as store

with tempfile.TemporaryDirectory() as directory:
    store._STORE_PATH = Path(directory) / 'attempts.jsonl'
    with TestClient(app) as client:
        response = client.post(
            '/api/demo/gauntlet',
            json={'intent': 'test bypass', 'payload': 'normal calendar note'},
        )
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
            "OKX_API_KEY": "gauntlet-test-api-key",
            "OKX_SECRET_KEY": "gauntlet-test-secret-key",
            "OKX_PASSPHRASE": "gauntlet-test-passphrase",
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


def test_gauntlet_page_discloses_human_review_and_retention():
    page = (ROOT / "site" / "gauntlet.html").read_text(encoding="utf-8")
    normalized_page = " ".join(page.lower().split())
    terms = " ".join((ROOT / "site" / "terms.html").read_text(encoding="utf-8").lower().split())
    privacy = " ".join((ROOT / "site" / "privacy.html").read_text(encoding="utf-8").lower().split())
    status = " ".join((ROOT / "site" / "status.html").read_text(encoding="utf-8").lower().split())

    assert "data-gauntlet-form" in page
    assert "data-gauntlet-stats" in page
    assert 'data-source-state="unknown"' in page
    assert "human review" in normalized_page
    assert "pending claims retain" in normalized_page
    assert "confirmed bypass" in normalized_page
    for state in ("pending review", "confirmed", "rejected", "duplicate", "detected"):
        assert state in normalized_page
    assert "no reward or bounty is promised" in normalized_page
    assert "not authenticated identities" in normalized_page
    assert "separate second human review" in normalized_page
    assert "training-use consent" in normalized_page
    for disclosure in (terms, privacy, status):
        assert "training-use consent" in disclosure
        assert "distinct" in disclosure


def test_paid_http_contract_remains_frozen():
    assert set(ScanRequest.model_fields) == {"payload", "depth", "context"}
    # attack_probability is additive, optional and defaults to null; it is
    # advisory evidence from the offline learned scorer and never sets the
    # verdict. Every pre-existing field keeps its name, type and meaning, so
    # existing paid callers are unaffected.
    assert set(ScanResponse.model_fields) == {
        "verdict",
        "risk_level",
        "threat_classes",
        "detections",
        "sanitized_payload",
        "recommendation",
        "checks",
        "latency_ms",
        "attack_probability",
    }
    # input_field is additive and optional (defaults to "payload"); existing
    # callers that send only target_url are unaffected. Response envelope frozen.
    assert set(AuditRequest.model_fields) == {"target_url", "sample_prompts", "input_field"}
    assert set(AuditResponse.model_fields) == {
        "score",
        "grade",
        "results",
        "badge",
        "recommendations",
        "badge_record",
        "consent_verified",
    }
    paid_methods: dict[str, set[str]] = {"/scan": set(), "/audit": set()}
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path in paid_methods:
            paid_methods[route.path] |= set(route.methods or set())

    # POST is the documented call and stays frozen. GET is served because OKX's
    # paid x402 auto-replay re-requests with GET; a 405 there freezes the buyer's
    # task. No other method is exposed on a paid route.
    assert paid_methods == {
        "/scan": {"POST", "GET"},
        "/audit": {"POST", "GET"},
    }
