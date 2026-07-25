"""Operator-facing calibration capture and selection CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts import capture_model_calibration, select_model_threshold
from warden.scanner.embedding import EmbeddingMatch
from warden.scanner.semantic import SemanticClassification, SemanticThreatCategory

SCHEMAS = Path(__file__).resolve().parents[1] / "spec" / "schemas"


class FixtureEmbeddingAnalyzer:
    async def match(self, content: str, references: tuple[str, ...]) -> EmbeddingMatch:
        scores = {"attack": 0.91, "clean": 0.21}
        return EmbeddingMatch(similarity=scores[content], reference=references[0])


class FixtureSemanticAnalyzer:
    async def classify(self, content: str) -> SemanticClassification:
        flagged = content == "attack"
        return SemanticClassification(
            flagged=flagged,
            confidence=0.9,
            reason="fixture",
            category=SemanticThreatCategory.PROMPT_INJECTION if flagged else None,
        )


def _dataset(tmp_path):
    path = tmp_path / "independent.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "id": "attack",
                        "label": "attack",
                        "payload": "attack",
                        "source": "review-v1",
                        "reviewed_by": "review-record-1",
                    }
                ),
                json.dumps(
                    {
                        "id": "clean",
                        "label": "benign",
                        "payload": "clean",
                        "source": "review-v1",
                        "reviewed_by": "review-record-2",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_capture_then_select_writes_payload_free_review_candidate(
    tmp_path,
    monkeypatch,
) -> None:
    dataset = _dataset(tmp_path)
    capture = tmp_path / "capture.json"
    candidate = tmp_path / "candidate.json"
    monkeypatch.setenv("WARDEN_SEMANTIC_MODEL", "fixture-v1")
    monkeypatch.setattr(
        capture_model_calibration,
        "build_semantic_analyzer_from_env",
        lambda: FixtureSemanticAnalyzer(),
    )

    capture_model_calibration.main(
        [
            "--tier",
            "semantic",
            "--dataset",
            str(dataset),
            "--dataset-id",
            "independent-calibration-v1",
            "--provider",
            "fixture",
            "--captured-at",
            "2026-07-24T12:00:00Z",
            "--output",
            str(capture),
        ]
    )
    select_model_threshold.main([str(capture), str(candidate)])

    captured = json.loads(capture.read_text(encoding="utf-8"))
    selected = json.loads(candidate.read_text(encoding="utf-8"))
    assert "payload" not in json.dumps(captured)
    assert captured["model"] == "fixture-v1"
    assert selected["selected_threshold"] == 0.9
    assert selected["production_change"] == "requires explicit review; not applied"


def test_capture_supports_the_embedding_tier_through_the_cli(tmp_path, monkeypatch) -> None:
    # The embedding branch of the capture CLI was previously exercised only at unit
    # level, so a break in its wiring would not have failed any test.
    dataset = _dataset(tmp_path)
    capture = tmp_path / "capture.json"
    candidate = tmp_path / "candidate.json"
    monkeypatch.setenv("WARDEN_EMBEDDING_MODEL", "fixture-embed-v1")
    monkeypatch.setattr(
        capture_model_calibration,
        "build_embedding_analyzer_from_env",
        lambda: FixtureEmbeddingAnalyzer(),
    )

    capture_model_calibration.main(
        [
            "--tier",
            "embedding",
            "--dataset",
            str(dataset),
            "--dataset-id",
            "independent-calibration-v1",
            "--provider",
            "fixture",
            "--captured-at",
            "2026-07-24T12:00:00Z",
            "--output",
            str(capture),
        ]
    )
    select_model_threshold.main([str(capture), str(candidate)])

    captured = json.loads(capture.read_text(encoding="utf-8"))
    selected = json.loads(candidate.read_text(encoding="utf-8"))
    assert captured["tier"] == "embedding"
    assert captured["model"] == "fixture-embed-v1"
    assert "payload" not in json.dumps(captured)
    assert selected["selected_threshold"] == 0.91
    assert selected["production_change"] == "requires explicit review; not applied"


def test_produced_calibration_artifacts_validate_against_the_published_schemas(
    tmp_path,
    monkeypatch,
) -> None:
    # The schemas were only checked for being valid Draft 2020-12 documents; nothing
    # validated a real produced artifact against them.
    dataset = _dataset(tmp_path)
    capture = tmp_path / "capture.json"
    candidate = tmp_path / "candidate.json"
    monkeypatch.setenv("WARDEN_SEMANTIC_MODEL", "fixture-v1")
    monkeypatch.setattr(
        capture_model_calibration,
        "build_semantic_analyzer_from_env",
        lambda: FixtureSemanticAnalyzer(),
    )

    capture_model_calibration.main(
        [
            "--tier",
            "semantic",
            "--dataset",
            str(dataset),
            "--dataset-id",
            "independent-calibration-v1",
            "--provider",
            "fixture",
            "--captured-at",
            "2026-07-24T12:00:00Z",
            "--output",
            str(capture),
        ]
    )
    select_model_threshold.main([str(capture), str(candidate)])

    for artifact, schema_name in (
        (capture, "model-calibration-capture-v1.schema.json"),
        (candidate, "model-threshold-candidate-v1.schema.json"),
    ):
        schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        instance = json.loads(artifact.read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema).iter_errors(instance),
            key=lambda error: list(error.path),
        )
        assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
