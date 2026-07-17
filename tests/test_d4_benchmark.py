"""D4 held-out benchmark integrity and published-result regressions."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.benchmark_recall import evaluate_benchmark, load_jsonl, normalized_payload
from warden.scanner.patterns import KNOWN_INJECTIONS
from warden.scanner.semantic import HttpSemanticAnalyzer

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = ROOT / "benchmark" / "held_out_attacks.jsonl"
BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"
PUBLISHED = ROOT / "benchmark" / "results.json"


def test_held_out_cases_are_fresh_and_disjoint_from_training_corpora():
    attacks = load_jsonl(ATTACKS)
    benign = load_jsonl(BENIGN)
    corpus = load_jsonl(ROOT / "corpus" / "attacks.jsonl")
    training_payloads = {
        normalized_payload(entry["payload"]) for entry in corpus
    } | {normalized_payload(payload) for payload in KNOWN_INJECTIONS}
    attack_payloads = {normalized_payload(entry["payload"]) for entry in attacks}
    benign_payloads = {normalized_payload(entry["payload"]) for entry in benign}

    assert len(attacks) >= 20
    assert len(benign) >= 12
    assert len({entry["id"] for entry in attacks}) == len(attacks)
    assert len({entry["id"] for entry in benign}) == len(benign)
    assert len(attack_payloads) == len(attacks)
    assert len(benign_payloads) == len(benign)
    assert attack_payloads.isdisjoint(training_payloads)
    assert attack_payloads.isdisjoint(benign_payloads)


@pytest.mark.asyncio
async def test_published_benchmark_exactly_matches_a_fresh_run():
    measured = await evaluate_benchmark(ATTACKS, BENIGN)
    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))

    assert measured == published
    assert measured["detected_attacks"] < measured["attack_cases"]
    assert 0 <= measured["attack_recall_percent"] <= 100
    assert 0 <= measured["false_positive_rate_percent"] <= 100
    readme = (ROOT / "benchmark" / "README.md").read_text(encoding="utf-8")
    assert "92.55% (87/94)" in readme
    assert "0.00% (0/42)" in readme


@pytest.mark.asyncio
async def test_benchmark_stays_deterministic_when_semantic_runtime_is_configured(monkeypatch):
    monkeypatch.setenv("WARDEN_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv(
        "WARDEN_SEMANTIC_ENDPOINT", "https://semantic.example/v1/chat/completions"
    )
    monkeypatch.setenv("WARDEN_SEMANTIC_MODEL", "security-classifier-v1")
    monkeypatch.setenv("WARDEN_SEMANTIC_API_KEY", "test-semantic-key")
    monkeypatch.setenv("OKX_API_KEY", "test-paywall-key")

    async def fail_if_called(_self, _content):
        pytest.fail("the deterministic benchmark must not call the semantic endpoint")

    monkeypatch.setattr(HttpSemanticAnalyzer, "classify", fail_if_called)

    measured = await evaluate_benchmark(ATTACKS, BENIGN)

    assert measured == json.loads(PUBLISHED.read_text(encoding="utf-8"))


def test_benchmark_cli_emits_the_published_json():
    completed = subprocess.run(
        [sys.executable, "scripts/benchmark_recall.py", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == json.loads(PUBLISHED.read_text(encoding="utf-8"))
