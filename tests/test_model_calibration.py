"""Independent labeled-data capture and offline threshold-selection tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warden.model_calibration import (
    CalibrationCase,
    build_capture,
    capture_embedding_scores,
    capture_semantic_scores,
    load_capture,
    load_calibration_cases,
    select_threshold,
    verify_capture,
    write_artifact,
)
from warden.scanner.embedding import EmbeddingMatch
from warden.scanner.semantic import SemanticClassification, SemanticThreatCategory


class FixtureEmbeddingAnalyzer:
    async def match(self, content: str, references: tuple[str, ...]) -> EmbeddingMatch:
        assert references == ("known injection",)
        scores = {"attack": 0.91, "clean": 0.21}
        return EmbeddingMatch(similarity=scores[content], reference=references[0])


class FixtureSemanticAnalyzer:
    async def classify(self, content: str) -> SemanticClassification:
        if content == "attack":
            return SemanticClassification(
                flagged=True,
                confidence=0.88,
                reason="fixture attack",
                category=SemanticThreatCategory.PROMPT_INJECTION,
            )
        return SemanticClassification(
            flagged=False,
            confidence=0.93,
            reason="fixture clean",
        )


def _cases() -> tuple[CalibrationCase, ...]:
    return (
        CalibrationCase(
            case_id="cal-attack",
            label="attack",
            payload="attack",
            source="independent-review-v1",
            reviewed_by="review-record-1",
        ),
        CalibrationCase(
            case_id="cal-clean",
            label="benign",
            payload="clean",
            source="independent-review-v1",
            reviewed_by="review-record-1",
        ),
    )


@pytest.mark.asyncio
async def test_capture_records_scores_and_provenance_without_payloads() -> None:
    semantic = await capture_semantic_scores(_cases(), FixtureSemanticAnalyzer())
    embedding = await capture_embedding_scores(
        _cases(),
        FixtureEmbeddingAnalyzer(),
        ("known injection",),
    )

    semantic_capture = build_capture(
        tier="semantic",
        dataset_id="independent-calibration-v1",
        dataset_sha256="a" * 64,
        provider="fixture",
        model="semantic-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=semantic,
    )
    embedding_capture = build_capture(
        tier="embedding",
        dataset_id="independent-calibration-v1",
        dataset_sha256="a" * 64,
        provider="fixture",
        model="embedding-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=embedding,
    )

    assert [row["score"] for row in semantic_capture["cases"]] == [0.88, 0.07]
    assert [row["score"] for row in embedding_capture["cases"]] == [0.91, 0.21]
    assert "payload" not in json.dumps(semantic_capture)
    assert verify_capture(semantic_capture) == semantic_capture
    assert verify_capture(embedding_capture) == embedding_capture


def test_selection_maximizes_recall_subject_to_zero_false_positives() -> None:
    capture = build_capture(
        tier="semantic",
        dataset_id="independent-calibration-v1",
        dataset_sha256="b" * 64,
        provider="fixture",
        model="semantic-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=(
            {
                "case_id": "attack-high",
                "label": "attack",
                "score": 0.9,
                "source": "review-v1",
                "reviewed_by": "review-record-1",
            },
            {
                "case_id": "attack-low",
                "label": "attack",
                "score": 0.8,
                "source": "review-v1",
                "reviewed_by": "review-record-1",
            },
            {
                "case_id": "benign-high",
                "label": "benign",
                "score": 0.6,
                "source": "review-v1",
                "reviewed_by": "review-record-2",
            },
            {
                "case_id": "benign-low",
                "label": "benign",
                "score": 0.4,
                "source": "review-v1",
                "reviewed_by": "review-record-2",
            },
        ),
    )

    result = select_threshold(capture)

    assert result["status"] == "candidate"
    assert result["selected_threshold"] == 0.8
    assert result["selected_metrics"] == {
        "true_positives": 2,
        "false_positives": 0,
        "true_negatives": 2,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
        "f1": 1.0,
    }
    assert result["policy"] == "maximize recall subject to zero false positives"
    assert len(result["artifact_sha256"]) == 64


def test_selection_refuses_to_propose_threshold_without_zero_fp_candidate() -> None:
    capture = build_capture(
        tier="semantic",
        dataset_id="independent-calibration-v1",
        dataset_sha256="c" * 64,
        provider="fixture",
        model="semantic-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=(
            {
                "case_id": "attack",
                "label": "attack",
                "score": 0.9,
                "source": "review-v1",
                "reviewed_by": "review-record-1",
            },
            {
                "case_id": "benign",
                "label": "benign",
                "score": 1.0,
                "source": "review-v1",
                "reviewed_by": "review-record-2",
            },
        ),
    )

    result = select_threshold(capture)

    assert result["status"] == "no_candidate"
    assert result["selected_threshold"] is None
    assert result["selected_metrics"] is None


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"dataset_id": "warden-held-out-v1"}, "independent"),
        ({"cases": []}, "attack and one benign"),
        ({"dataset_sha256": "not-a-hash"}, "dataset_sha256"),
    ],
)
def test_capture_validation_rejects_non_independent_or_incomplete_data(
    mutation: dict[str, object],
    message: str,
) -> None:
    capture = build_capture(
        tier="semantic",
        dataset_id="independent-calibration-v1",
        dataset_sha256="d" * 64,
        provider="fixture",
        model="semantic-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=(
            {
                "case_id": "attack",
                "label": "attack",
                "score": 0.9,
                "source": "review-v1",
                "reviewed_by": "review-record-1",
            },
            {
                "case_id": "benign",
                "label": "benign",
                "score": 0.1,
                "source": "review-v1",
                "reviewed_by": "review-record-2",
            },
        ),
    )
    capture.update(mutation)

    with pytest.raises(ValueError, match=message):
        verify_capture(capture)


def test_selection_artifact_is_deterministic_and_binds_capture() -> None:
    capture_path = Path("calibration.json")
    capture = build_capture(
        tier="embedding",
        dataset_id="independent-calibration-v1",
        dataset_sha256="e" * 64,
        provider="fixture",
        model="embedding-fixture-v1",
        captured_at="2026-07-24T12:00:00Z",
        scored_cases=(
            {
                "case_id": "attack",
                "label": "attack",
                "score": 0.8,
                "source": str(capture_path),
                "reviewed_by": "review-record-1",
            },
            {
                "case_id": "benign",
                "label": "benign",
                "score": 0.2,
                "source": str(capture_path),
                "reviewed_by": "review-record-2",
            },
        ),
    )

    assert select_threshold(capture) == select_threshold(json.loads(json.dumps(capture)))


def test_labeled_case_loader_requires_reviewed_independent_jsonl(tmp_path: Path) -> None:
    dataset = tmp_path / "independent.jsonl"
    dataset.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "id": "attack",
                        "label": "attack",
                        "payload": "untrusted attack",
                        "source": "independent-review-v1",
                        "reviewed_by": "review-record-1",
                    }
                ),
                json.dumps(
                    {
                        "id": "clean",
                        "label": "benign",
                        "payload": "ordinary request",
                        "source": "independent-review-v1",
                        "reviewed_by": "review-record-2",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    cases, digest = load_calibration_cases(dataset)

    assert cases == (
        CalibrationCase(
            case_id="attack",
            label="attack",
            payload="untrusted attack",
            source="independent-review-v1",
            reviewed_by="review-record-1",
        ),
        CalibrationCase(
            case_id="clean",
            label="benign",
            payload="ordinary request",
            source="independent-review-v1",
            reviewed_by="review-record-2",
        ),
    )
    assert len(digest) == 64


def test_labeled_case_loader_rejects_non_string_fields(tmp_path: Path) -> None:
    dataset = tmp_path / "independent.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "id": 7,
                "label": "attack",
                "payload": "untrusted attack",
                "source": "independent-review-v1",
                "reviewed_by": "review-record-1",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="id"):
        load_calibration_cases(dataset)


def test_artifact_writer_is_atomic_and_refuses_non_files(tmp_path: Path) -> None:
    output = tmp_path / "candidate.json"
    document = {"schema_version": 1, "status": "candidate"}

    write_artifact(output, document)

    assert json.loads(output.read_text(encoding="utf-8")) == document
    directory = tmp_path / "directory.json"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        write_artifact(directory, document)


def test_capture_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "capture.json"
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        load_capture(path)


@pytest.mark.parametrize("reserved_directory", ["benchmark", "corpus", "Corpus", "BENCHMARK"])
def test_load_rejects_datasets_living_under_training_or_held_out_paths(
    tmp_path: Path,
    reserved_directory: str,
) -> None:
    # The dataset_id name guard is not enough on its own: an operator can point
    # --dataset at a well-named file that physically sits inside the training or
    # held-out trees, which would calibrate thresholds on evaluation data.
    dataset = tmp_path / reserved_directory / "independent-review.jsonl"
    dataset.parent.mkdir(parents=True)
    dataset.write_text(
        json.dumps(
            {
                "id": "attack",
                "label": "attack",
                "payload": "untrusted attack",
                "source": "independent-review",
                "reviewed_by": "reviewer",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="independent of training and held-out data"):
        load_calibration_cases(dataset)
