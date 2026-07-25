"""D4 held-out benchmark integrity and published-result regressions."""

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.benchmark_recall import evaluate_benchmark, load_jsonl, normalized_payload
from warden.scanner.patterns import KNOWN_INJECTIONS, SIMILARITY_THRESHOLD
from warden.scanner.scanner import InjectionScanner
from warden.scanner.semantic import HttpSemanticAnalyzer

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = ROOT / "benchmark" / "held_out_attacks.jsonl"
BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"
PUBLISHED = ROOT / "benchmark" / "results.json"


def test_held_out_cases_are_fresh_and_disjoint_from_training_corpora():
    attacks = load_jsonl(ATTACKS)
    benign = load_jsonl(BENIGN)
    corpus = load_jsonl(ROOT / "corpus" / "attacks.jsonl")
    training_payloads = {normalized_payload(entry["payload"]) for entry in corpus} | {
        normalized_payload(payload) for payload in KNOWN_INJECTIONS
    }
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
    assert "91.49% (86/94)" in readme
    assert "0.00% (0/45)" in readme


@pytest.mark.asyncio
async def test_benchmark_stays_deterministic_when_semantic_runtime_is_configured(monkeypatch):
    monkeypatch.setenv("WARDEN_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("WARDEN_SEMANTIC_ENDPOINT", "https://semantic.example/v1/chat/completions")
    monkeypatch.setenv("WARDEN_SEMANTIC_MODEL", "security-classifier-v1")
    monkeypatch.setenv("WARDEN_SEMANTIC_API_KEY", "test-semantic-key")
    monkeypatch.setenv("OKX_API_KEY", "test-paywall-key")

    async def fail_if_called(_self, _content):
        pytest.fail("the deterministic benchmark must not call the semantic endpoint")

    monkeypatch.setattr(HttpSemanticAnalyzer, "classify", fail_if_called)

    measured = await evaluate_benchmark(ATTACKS, BENIGN)

    assert measured == json.loads(PUBLISHED.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_published_result_discloses_both_depths_including_the_thorough_false_positive():
    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))

    assert published["depth_is_caller_controlled"] is True
    per_depth = published["per_depth"]
    assert set(per_depth) == {"fast", "thorough"}
    for measured in per_depth.values():
        interval = measured["false_positive_rate_ci_percent"]
        assert interval["method"] == "wilson-score"
        assert interval["observations"] == measured["benign_cases"]
        assert interval["lower_percent"] <= measured["false_positive_rate_percent"]
        assert interval["upper_percent"] >= measured["false_positive_rate_percent"]
        assert len(measured["false_positive_ids"]) == measured["false_positives"]

    # The fast path alone would report a clean benign sheet; thorough does not.
    assert per_depth["fast"]["false_positive_ids"] == []
    assert per_depth["thorough"]["false_positive_ids"] == ["held-benign-enc-016"]

    readme = (ROOT / "benchmark" / "README.md").read_text(encoding="utf-8")
    assert "held-benign-enc-016" in readme
    assert "7.87%" in readme
    assert "11.57%" in readme


def test_layer3_threshold_is_derived_only_from_the_calibration_split():
    calibration = load_jsonl(ROOT / "benchmark" / "calibration_benign.jsonl")
    assert len(calibration) >= 40

    scanner = InjectionScanner()
    scores = [
        scanner._run_similarity_layer(str(entry["payload"]))["similarity"] for entry in calibration
    ]
    highest = max(scores)

    # The published rule: smallest two-decimal value strictly above the calibration maximum.
    assert SIMILARITY_THRESHOLD == pytest.approx(math.floor(highest * 100 + 1) / 100)
    assert SIMILARITY_THRESHOLD > highest
    assert all(score < SIMILARITY_THRESHOLD for score in scores)


def test_calibration_split_is_disjoint_from_the_held_out_and_training_data():
    calibration = {
        normalized_payload(entry["payload"])
        for entry in load_jsonl(ROOT / "benchmark" / "calibration_benign.jsonl")
    }
    held_out = {normalized_payload(entry["payload"]) for entry in load_jsonl(ATTACKS)} | {
        normalized_payload(entry["payload"]) for entry in load_jsonl(BENIGN)
    }
    training = {
        normalized_payload(entry["payload"])
        for entry in load_jsonl(ROOT / "corpus" / "attacks.jsonl")
    } | {normalized_payload(payload) for payload in KNOWN_INJECTIONS}

    assert calibration.isdisjoint(held_out)
    assert calibration.isdisjoint(training)


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
