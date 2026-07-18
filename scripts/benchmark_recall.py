"""Measure Warden against the versioned held-out attack and benign sets."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.engine import WardenEngine  # noqa: E402
from warden.scanner.scanner import (  # noqa: E402
    EMBEDDING_SIMILARITY_THRESHOLD,
    SEMANTIC_CONFIDENCE_THRESHOLD,
)

DEFAULT_ATTACKS = ROOT / "benchmark" / "held_out_attacks.jsonl"
DEFAULT_BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"
PUBLISHED_RESULTS = ROOT / "benchmark" / "results.json"
DEFAULT_HISTORY = ROOT / "benchmark" / "history.jsonl"
DEFAULT_PUBLIC_RESULT = ROOT / "site" / "data" / "evaluation.json"
EXPECTED_ATTACKS_SHA256 = "09a650c06b60c1a9ba1d69b72c18801f6fe0c464c826c201a638d3237e894287"
EXPECTED_BENIGN_SHA256 = "3b0e0f5ee72718fbe7a26721ae4b0ed577a00e5aa7c5990278015816687f5891"
MIN_CANONICAL_ATTACK_CASES = 94
MIN_CANONICAL_BENIGN_CASES = 45
MODEL_TIER_MODES = ("deterministic", "embedding-only", "semantic-only", "combined")
_MODEL_TIER_CONFIGURATION = {
    "embedding-only": (True, False),
    "semantic-only": (False, True),
    "combined": (True, True),
}
_MODE_DESCRIPTIONS = {
    "deterministic": "deterministic fast path; thorough only where declared; semantic disabled",
    "embedding-only": ("paid thorough path; deterministic then embedding; semantic disabled"),
    "semantic-only": ("paid thorough path; deterministic then semantic; embedding disabled"),
    "combined": "paid thorough path; deterministic then embedding then semantic",
}


def load_jsonl(path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict) or not isinstance(entry.get("payload"), str):
                raise ValueError(f"{path}:{line_number} must contain an object with payload text")
            entries.append(entry)
    return entries


def normalized_payload(payload: object) -> str:
    return " ".join(str(payload).casefold().split())


def _canonical_content_sha256(path: Path) -> str:
    content = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(content).hexdigest()


def _validate_recording_sources(
    attacks_path: Path,
    benign_path: Path,
) -> tuple[int, int]:
    try:
        resolved_attacks = attacks_path.resolve(strict=True)
        resolved_benign = benign_path.resolve(strict=True)
        canonical_attacks = DEFAULT_ATTACKS.resolve(strict=True)
        canonical_benign = DEFAULT_BENIGN.resolve(strict=True)
    except OSError as exc:
        raise ValueError("recording sources must be readable canonical benchmark files") from exc

    if resolved_attacks != canonical_attacks or resolved_benign != canonical_benign:
        raise ValueError("--record requires the canonical held-out benchmark paths")
    if _canonical_content_sha256(resolved_attacks) != EXPECTED_ATTACKS_SHA256:
        raise ValueError(
            "canonical held-out attack content hash does not match the pinned snapshot"
        )
    if _canonical_content_sha256(resolved_benign) != EXPECTED_BENIGN_SHA256:
        raise ValueError(
            "canonical held-out benign content hash does not match the pinned snapshot"
        )

    attack_cases = len(load_jsonl(resolved_attacks))
    benign_cases = len(load_jsonl(resolved_benign))
    if attack_cases < MIN_CANONICAL_ATTACK_CASES:
        raise ValueError(
            f"canonical held-out attack set must contain at least {MIN_CANONICAL_ATTACK_CASES} cases"
        )
    if benign_cases < MIN_CANONICAL_BENIGN_CASES:
        raise ValueError(
            f"canonical held-out benign set must contain at least {MIN_CANONICAL_BENIGN_CASES} cases"
        )
    return attack_cases, benign_cases


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 2) if denominator else 0.0


def _detection_tier(
    detections: list[dict[str, object]],
    expected_class: str | None = None,
) -> str:
    relevant = [
        detection
        for detection in detections
        if expected_class is None or detection.get("class") == expected_class
    ]
    sources = {detection.get("source") for detection in relevant}
    if "layer_4" in sources:
        return "embedding"
    if "layer_5" in sources:
        return "semantic"
    return "deterministic"


def _validate_model_tier_configuration(mode: str, engine: WardenEngine) -> None:
    if mode == "deterministic":
        return
    expected_embedding, expected_semantic = _MODEL_TIER_CONFIGURATION[mode]
    if (
        engine.embedding_enabled == expected_embedding
        and engine.semantic_enabled == expected_semantic
    ):
        return
    expectation = (
        f"embedding={'enabled' if expected_embedding else 'disabled'}, "
        f"semantic={'enabled' if expected_semantic else 'disabled'}"
    )
    configured = (
        f"embedding={'enabled' if engine.embedding_enabled else 'disabled'}, "
        f"semantic={'enabled' if engine.semantic_enabled else 'disabled'}"
    )
    raise RuntimeError(f"{mode} benchmark requires {expectation}; configured {configured}")


def _model_tier_metadata(mode: str, *, harness_only: bool) -> dict[str, object]:
    embedding_enabled, semantic_enabled = _MODEL_TIER_CONFIGURATION[mode]
    execution_order = ["deterministic"]
    if embedding_enabled:
        execution_order.append("embedding")
    if semantic_enabled:
        execution_order.append("semantic")
    metadata: dict[str, object] = {
        "mode": mode,
        "deterministic_enabled": True,
        "embedding_enabled": embedding_enabled,
        "semantic_enabled": semantic_enabled,
        "execution_order": execution_order,
        "evidence_scope": (
            "harness-behavior-only" if harness_only else "configured-provider-held-out-evaluation"
        ),
        "interpretation": (
            "not performance or calibration evidence"
            if harness_only
            else "held-out evaluation only; not threshold calibration"
        ),
    }
    if embedding_enabled:
        metadata["embedding_threshold"] = {
            "value": EMBEDDING_SIMILARITY_THRESHOLD,
            "calibration_status": "uncalibrated",
            "calibration_data": "none",
        }
    if semantic_enabled:
        metadata["semantic_threshold"] = {
            "value": SEMANTIC_CONFIDENCE_THRESHOLD,
            "calibration_status": "uncalibrated",
            "calibration_data": "none",
        }
    return metadata


def record_benchmark(
    result: dict[str, object],
    *,
    measured_at: str | None = None,
    attacks_path: Path = DEFAULT_ATTACKS,
    benign_path: Path = DEFAULT_BENIGN,
    history_path: Path = DEFAULT_HISTORY,
    public_path: Path = DEFAULT_PUBLIC_RESULT,
) -> dict[str, object]:
    if "model_tier" in result:
        raise ValueError(
            "model-tier benchmark results cannot be recorded in deterministic public history"
        )
    attack_cases, benign_cases = _validate_recording_sources(attacks_path, benign_path)
    if (
        result.get("benchmark") != "warden-held-out-v1"
        or result.get("mode") != _MODE_DESCRIPTIONS["deterministic"]
    ):
        raise ValueError("only the canonical deterministic held-out result can be recorded")
    if result.get("attack_cases") != attack_cases or result.get("benign_cases") != benign_cases:
        raise ValueError(
            "benchmark result case counts do not match the canonical recording sources"
        )
    measured_at = measured_at or (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    try:
        parsed = datetime.fromisoformat(measured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("measured_at must be an exact UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond or not measured_at.endswith("Z"):
        raise ValueError("measured_at must be an exact UTC timestamp")

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    record = {
        "schema_version": 1,
        "measured_at": measured_at,
        "benchmark": result["benchmark"],
        "mode": result["mode"],
        "attack_cases": result["attack_cases"],
        "detected_attacks": result["detected_attacks"],
        "attack_recall_percent": result["attack_recall_percent"],
        "benign_cases": result["benign_cases"],
        "false_positives": result["false_positives"],
        "false_positive_rate_percent": result["false_positive_rate_percent"],
        "result_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    public_payload = {
        "schema_version": 1,
        "current": record,
        "methodology": {
            "attack_success": "non-ALLOW decision with the expected threat class",
            "benign_false_positive": "any non-ALLOW decision",
            "held_out": True,
            "semantic_enabled": False,
        },
    }
    public_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = public_path.with_suffix(public_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(public_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(public_path)
    return record


async def evaluate_benchmark(
    attacks_path: Path = DEFAULT_ATTACKS,
    benign_path: Path = DEFAULT_BENIGN,
    *,
    mode: str = "deterministic",
    engine: WardenEngine | None = None,
    harness_only: bool = False,
) -> dict[str, object]:
    if mode not in MODEL_TIER_MODES:
        raise ValueError(f"benchmark mode must be one of: {', '.join(MODEL_TIER_MODES)}")
    if mode != "deterministic" and engine is not None and not harness_only:
        raise ValueError(
            "explicit-engine model evaluation is harness-only; provider evidence must use "
            "runtime configuration"
        )
    if harness_only and engine is None:
        raise ValueError("harness-only model evaluation requires an explicit fixture engine")
    engine = engine or WardenEngine()
    _validate_model_tier_configuration(mode, engine)
    attacks = load_jsonl(attacks_path)
    benign = load_jsonl(benign_path)
    model_tier_enabled = mode != "deterministic"
    detected_attacks = 0
    attack_misses: list[str] = []
    category_totals: dict[str, int] = defaultdict(int)
    category_hits: dict[str, int] = defaultdict(int)
    attack_attribution = {"deterministic": 0, "embedding": 0, "semantic": 0}
    false_positive_attribution = {"deterministic": 0, "embedding": 0, "semantic": 0}

    for entry in attacks:
        entry_id = str(entry["id"])
        category = str(entry["category"])
        category_totals[category] += 1
        verdict = await engine.scan(
            str(entry["payload"]),
            depth="thorough" if model_tier_enabled else str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
            allow_paid_semantic=model_tier_enabled,
        )
        classes = {reason.value for reason in verdict.threat_classes}
        detected = verdict.verdict != "ALLOW" and category in classes
        if detected:
            detected_attacks += 1
            category_hits[category] += 1
            attack_attribution[_detection_tier(verdict.detections, category)] += 1
        else:
            attack_misses.append(entry_id)

    false_positive_ids: list[str] = []
    for entry in benign:
        verdict = await engine.scan(
            str(entry["payload"]),
            depth="thorough" if model_tier_enabled else str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
            allow_paid_semantic=model_tier_enabled,
        )
        if verdict.verdict != "ALLOW":
            false_positive_ids.append(str(entry["id"]))
            false_positive_attribution[_detection_tier(verdict.detections)] += 1

    per_category = {
        category: {
            "cases": category_totals[category],
            "detected": category_hits[category],
            "recall_percent": _percent(category_hits[category], category_totals[category]),
        }
        for category in sorted(category_totals)
    }
    result: dict[str, object] = {
        "schema_version": 1,
        "benchmark": ("warden-synthetic-harness-v1" if harness_only else "warden-held-out-v1"),
        "mode": (
            f"synthetic harness only; {_MODE_DESCRIPTIONS[mode]}"
            if harness_only
            else _MODE_DESCRIPTIONS[mode]
        ),
        "attack_cases": len(attacks),
        "detected_attacks": detected_attacks,
        "attack_recall_percent": _percent(detected_attacks, len(attacks)),
        "attack_misses": attack_misses,
        "benign_cases": len(benign),
        "false_positives": len(false_positive_ids),
        "false_positive_rate_percent": _percent(len(false_positive_ids), len(benign)),
        "false_positive_ids": false_positive_ids,
        "per_category": per_category,
    }
    if model_tier_enabled:
        result["model_tier"] = _model_tier_metadata(mode, harness_only=harness_only)
        result["model_attribution"] = {
            "detected_attacks": attack_attribution,
            "false_positives": false_positive_attribution,
        }
        if harness_only:
            result["model_tier_enablement_gate"] = {
                "mode": mode,
                "eligible": False,
                "passed": None,
                "reason": "synthetic fixture results are not performance evidence",
            }
        else:
            published = json.loads(PUBLISHED_RESULTS.read_text(encoding="utf-8"))
            baseline_recall = float(published["attack_recall_percent"])
            result["model_tier_enablement_gate"] = {
                "mode": mode,
                "baseline_recall_percent": baseline_recall,
                "requires_zero_false_positives": True,
                "passed": (
                    result["attack_recall_percent"] > baseline_recall
                    and result["false_positive_rate_percent"] == 0
                ),
            }
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Warden's held-out detection benchmark.")
    parser.add_argument("--attacks", type=Path, default=DEFAULT_ATTACKS)
    parser.add_argument("--benign", type=Path, default=DEFAULT_BENIGN)
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    parser.add_argument(
        "--mode",
        choices=MODEL_TIER_MODES,
        default="deterministic",
        help=(
            "Execution mode. Provider-backed modes require exactly the named network tiers "
            "to be configured."
        ),
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help=(
            "In deterministic mode, append a dated history record and refresh public "
            "evaluation data."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.record and args.mode != "deterministic":
        raise SystemExit(
            "--record is limited to deterministic mode; model-tier results are local "
            "evaluation evidence only"
        )
    if args.record:
        try:
            _validate_recording_sources(args.attacks, args.benign)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    try:
        result = asyncio.run(evaluate_benchmark(args.attacks, args.benign, mode=args.mode))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if args.record:
        record_benchmark(
            result,
            attacks_path=args.attacks,
            benign_path=args.benign,
        )
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return
    print(
        f"Held-out attack recall: {result['attack_recall_percent']:.2f}% "
        f"({result['detected_attacks']}/{result['attack_cases']})"
    )
    print(
        f"Held-out false-positive rate: {result['false_positive_rate_percent']:.2f}% "
        f"({result['false_positives']}/{result['benign_cases']})"
    )
    if result["attack_misses"]:
        print(f"Missed attack IDs: {', '.join(result['attack_misses'])}")
    model_tier = result.get("model_tier")
    if isinstance(model_tier, dict):
        print(f"Model-tier mode: {model_tier['mode']}")
        threshold = model_tier.get("embedding_threshold")
        if isinstance(threshold, dict):
            print(
                f"Embedding threshold: {threshold['value']:.2f} ({threshold['calibration_status']})"
            )
        threshold = model_tier.get("semantic_threshold")
        if isinstance(threshold, dict):
            print(
                f"Semantic threshold: {threshold['value']:.2f} ({threshold['calibration_status']})"
            )
    gate = result.get("model_tier_enablement_gate")
    if isinstance(gate, dict):
        print(
            "Model-tier enablement gate: "
            + ("PASS" if gate.get("passed") is True else "FAIL; keep disabled")
        )


if __name__ == "__main__":
    main()
