"""Operator-facing calibration capture and selection CLI tests."""

from __future__ import annotations

import json

from scripts import capture_model_calibration, select_model_threshold
from warden.scanner.semantic import SemanticClassification, SemanticThreatCategory


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
