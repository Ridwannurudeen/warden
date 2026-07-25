"""Independent model-score capture and deterministic threshold selection."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from warden.scanner.embedding import EmbeddingAnalyzer
from warden.scanner.semantic import SemanticAnalyzer

SCHEMA_VERSION = 1
TIERS = frozenset({"embedding", "semantic"})
LABELS = frozenset({"attack", "benign"})
SELECTION_POLICY = "maximize recall subject to zero false positives"
_CAPTURE_FIELDS = {
    "schema_version",
    "tier",
    "dataset_id",
    "dataset_sha256",
    "provider",
    "model",
    "captured_at",
    "cases",
}
_CASE_FIELDS = {"case_id", "label", "score", "source", "reviewed_by"}


@dataclass(frozen=True)
class CalibrationCase:
    case_id: str
    label: str
    payload: str
    source: str
    reviewed_by: str


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("calibration data contains duplicate object keys")
        parsed[key] = value
    return parsed


def _reject_non_finite(_value: str) -> object:
    raise ValueError("calibration data contains a non-finite number")


def _strict_json(document: str) -> object:
    try:
        return json.loads(
            document,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("calibration data must contain valid JSON") from exc


def _text(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be non-empty text no longer than {maximum} characters")
    return value.strip()


def _exact_utc(value: object) -> str:
    text = _text(value, "captured_at", maximum=32)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("captured_at must be an exact UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond or not text.endswith("Z"):
        raise ValueError("captured_at must be an exact UTC timestamp")
    return text


def _independent_dataset_id(value: object) -> str:
    dataset_id = _text(value, "dataset_id")
    collapsed = dataset_id.casefold().replace("_", "-")
    if any(token in collapsed for token in ("held-out", "training", "corpus")):
        raise ValueError("calibration dataset must be independent of training and held-out data")
    return dataset_id


def _score(value: object, tier: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("calibration score must be a number")
    score = float(value)
    minimum = -1.0 if tier == "embedding" else 0.0
    if not math.isfinite(score) or not minimum <= score <= 1.0:
        raise ValueError(f"{tier} calibration score must be between {minimum:g} and 1")
    return score


def _case_record(value: object, tier: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _CASE_FIELDS:
        raise ValueError("calibration case must contain exactly the required fields")
    label = value.get("label")
    if label not in LABELS:
        raise ValueError("calibration case label must be attack or benign")
    return {
        "case_id": _text(value.get("case_id"), "case_id"),
        "label": label,
        "score": _score(value.get("score"), tier),
        "source": _text(value.get("source"), "source", maximum=512),
        "reviewed_by": _text(value.get("reviewed_by"), "reviewed_by"),
    }


def verify_capture(value: object) -> dict[str, object]:
    """Validate one payload-free provider-score capture."""
    if not isinstance(value, Mapping) or set(value) != _CAPTURE_FIELDS:
        raise ValueError("calibration capture must contain exactly the required fields")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported calibration capture schema_version")
    tier = value.get("tier")
    if tier not in TIERS:
        raise ValueError("calibration tier must be embedding or semantic")
    assert isinstance(tier, str)
    dataset_id = _independent_dataset_id(value.get("dataset_id"))
    dataset_sha256 = value.get("dataset_sha256")
    if (
        not isinstance(dataset_sha256, str)
        or len(dataset_sha256) != 64
        or any(character not in "0123456789abcdef" for character in dataset_sha256)
    ):
        raise ValueError("dataset_sha256 must be 64 lowercase hexadecimal characters")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("calibration cases must be an array")
    cases = [_case_record(case, tier) for case in raw_cases]
    case_ids = [str(case["case_id"]) for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("calibration case IDs must be unique")
    labels = {case["label"] for case in cases}
    if labels != LABELS:
        raise ValueError("calibration capture requires at least one attack and one benign case")
    return {
        "schema_version": SCHEMA_VERSION,
        "tier": tier,
        "dataset_id": dataset_id,
        "dataset_sha256": dataset_sha256,
        "provider": _text(value.get("provider"), "provider"),
        "model": _text(value.get("model"), "model"),
        "captured_at": _exact_utc(value.get("captured_at")),
        "cases": cases,
    }


def build_capture(
    *,
    tier: str,
    dataset_id: str,
    dataset_sha256: str,
    provider: str,
    model: str,
    captured_at: str,
    scored_cases: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Build a validated payload-free provider-score capture."""
    return verify_capture(
        {
            "schema_version": SCHEMA_VERSION,
            "tier": tier,
            "dataset_id": dataset_id,
            "dataset_sha256": dataset_sha256,
            "provider": provider,
            "model": model,
            "captured_at": captured_at,
            "cases": [dict(case) for case in scored_cases],
        }
    )


def _calibration_case(case: CalibrationCase) -> CalibrationCase:
    label = case.label
    if label not in LABELS:
        raise ValueError("calibration case label must be attack or benign")
    return CalibrationCase(
        case_id=_text(case.case_id, "case_id"),
        label=label,
        payload=_text(case.payload, "payload", maximum=100_000),
        source=_text(case.source, "source", maximum=512),
        reviewed_by=_text(case.reviewed_by, "reviewed_by"),
    )


def load_calibration_cases(path: Path) -> tuple[tuple[CalibrationCase, ...], str]:
    """Load an independently reviewed JSONL dataset and return its content hash."""
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("calibration dataset must be a regular file")
    normalized_parts = {part.casefold().replace("_", "-") for part in resolved.parts}
    if normalized_parts & {"benchmark", "corpus"}:
        raise ValueError("calibration dataset must be independent of training and held-out data")
    cases: list[CalibrationCase] = []
    for line_number, line in enumerate(resolved.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = _strict_json(line)
        if not isinstance(value, Mapping) or set(value) != {
            "id",
            "label",
            "payload",
            "source",
            "reviewed_by",
        }:
            raise ValueError(
                f"{resolved}:{line_number} must contain exactly the calibration case fields"
            )
        case_id = value["id"]
        label = value["label"]
        payload = value["payload"]
        source = value["source"]
        reviewed_by = value["reviewed_by"]
        if not all(
            isinstance(item, str)
            for item in (case_id, label, payload, source, reviewed_by)
        ):
            raise ValueError(
                f"{resolved}:{line_number} calibration case id, label, payload, source, "
                "and reviewed_by must be strings"
            )
        cases.append(
            _calibration_case(
                CalibrationCase(
                    case_id=case_id,
                    label=label,
                    payload=payload,
                    source=source,
                    reviewed_by=reviewed_by,
                )
            )
        )
    if {case.label for case in cases} != LABELS:
        raise ValueError("calibration dataset requires at least one attack and one benign case")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("calibration case IDs must be unique")
    content = resolved.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return tuple(cases), hashlib.sha256(content).hexdigest()


def load_capture(path: Path) -> dict[str, object]:
    """Load and validate one payload-free capture artifact."""
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("calibration capture must be a regular file")
    return verify_capture(_strict_json(resolved.read_text(encoding="utf-8")))


def write_artifact(path: Path, document: Mapping[str, object]) -> None:
    """Write one JSON artifact atomically without following symbolic links."""
    output = Path(os.path.abspath(path))
    if output.is_symlink():
        raise ValueError("calibration output must not be a symbolic link")
    for parent in (output.parent, *output.parent.parents):
        if parent.is_symlink():
            raise ValueError("calibration output parent must not be a symbolic link")
    if not output.parent.is_dir():
        raise ValueError("calibration output parent must be an existing directory")
    if output.exists() and not stat.S_ISREG(output.lstat().st_mode):
        raise ValueError("calibration output must be a regular file")
    serialized = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


async def capture_semantic_scores(
    cases: Sequence[CalibrationCase],
    analyzer: SemanticAnalyzer,
) -> tuple[dict[str, object], ...]:
    """Capture attack-oriented semantic scores without retaining payloads."""
    captured: list[dict[str, object]] = []
    for raw_case in cases:
        case = _calibration_case(raw_case)
        classification = await analyzer.classify(case.payload)
        confidence = _score(classification.confidence, "semantic")
        attack_score = confidence if classification.flagged else 1.0 - confidence
        captured.append(
            {
                "case_id": case.case_id,
                "label": case.label,
                "score": round(attack_score, 6),
                "source": case.source,
                "reviewed_by": case.reviewed_by,
            }
        )
    return tuple(captured)


async def capture_embedding_scores(
    cases: Sequence[CalibrationCase],
    analyzer: EmbeddingAnalyzer,
    references: tuple[str, ...],
) -> tuple[dict[str, object], ...]:
    """Capture embedding-similarity scores without retaining payloads."""
    if not references or any(not isinstance(item, str) or not item for item in references):
        raise ValueError("embedding calibration requires non-empty reference text")
    captured: list[dict[str, object]] = []
    for raw_case in cases:
        case = _calibration_case(raw_case)
        match = await analyzer.match(case.payload, references)
        captured.append(
            {
                "case_id": case.case_id,
                "label": case.label,
                "score": round(_score(match.similarity, "embedding"), 6),
                "source": case.source,
                "reviewed_by": case.reviewed_by,
            }
        )
    return tuple(captured)


def _metrics(cases: list[dict[str, object]], threshold: float) -> dict[str, object]:
    true_positives = false_positives = true_negatives = false_negatives = 0
    for case in cases:
        predicted_attack = float(case["score"]) >= threshold
        actual_attack = case["label"] == "attack"
        if predicted_attack and actual_attack:
            true_positives += 1
        elif predicted_attack:
            false_positives += 1
        elif actual_attack:
            false_negatives += 1
        else:
            true_negatives += 1
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    benign_count = false_positives + true_negatives
    precision = true_positives / precision_denominator if precision_denominator else 0.0
    recall = true_positives / recall_denominator if recall_denominator else 0.0
    false_positive_rate = false_positives / benign_count
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(false_positive_rate, 6),
        "f1": round(f1, 6),
    }


def select_threshold(capture: object) -> dict[str, object]:
    """Select a review candidate without mutating runtime thresholds."""
    verified = verify_capture(capture)
    cases = verified["cases"]
    assert isinstance(cases, list)
    candidates = [
        {
            "threshold": threshold,
            "metrics": _metrics(cases, threshold),
        }
        for threshold in sorted({float(case["score"]) for case in cases})
    ]
    eligible = [
        candidate
        for candidate in candidates
        if candidate["metrics"]["false_positives"] == 0
        and candidate["metrics"]["true_positives"] > 0
    ]
    selected = (
        max(
            eligible,
            key=lambda candidate: (
                candidate["metrics"]["recall"],
                candidate["metrics"]["f1"],
                candidate["metrics"]["precision"],
                -candidate["threshold"],
            ),
        )
        if eligible
        else None
    )
    capture_sha256 = hashlib.sha256(_canonical_json(verified).encode("utf-8")).hexdigest()
    artifact: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "tier": verified["tier"],
        "dataset_id": verified["dataset_id"],
        "dataset_sha256": verified["dataset_sha256"],
        "capture_sha256": capture_sha256,
        "provider": verified["provider"],
        "model": verified["model"],
        "captured_at": verified["captured_at"],
        "policy": SELECTION_POLICY,
        "status": "candidate" if selected is not None else "no_candidate",
        "selected_threshold": selected["threshold"] if selected is not None else None,
        "selected_metrics": selected["metrics"] if selected is not None else None,
        "sample_counts": {
            "attack": sum(case["label"] == "attack" for case in cases),
            "benign": sum(case["label"] == "benign" for case in cases),
        },
        "candidates": candidates,
        "production_change": "requires explicit review; not applied",
    }
    artifact["artifact_sha256"] = hashlib.sha256(
        _canonical_json(artifact).encode("utf-8")
    ).hexdigest()
    return artifact
