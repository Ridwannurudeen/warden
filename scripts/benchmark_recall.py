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

DEFAULT_ATTACKS = ROOT / "benchmark" / "held_out_attacks.jsonl"
DEFAULT_BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"
PUBLISHED_RESULTS = ROOT / "benchmark" / "results.json"
DEFAULT_HISTORY = ROOT / "benchmark" / "history.jsonl"
DEFAULT_PUBLIC_RESULT = ROOT / "site" / "data" / "evaluation.json"


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


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 2) if denominator else 0.0


def record_benchmark(
    result: dict[str, object],
    *,
    measured_at: str | None = None,
    history_path: Path = DEFAULT_HISTORY,
    public_path: Path = DEFAULT_PUBLIC_RESULT,
) -> dict[str, object]:
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
            "semantic_enabled": "semantic_enablement_gate" in result,
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
    semantic: bool = False,
    engine: WardenEngine | None = None,
) -> dict[str, object]:
    attacks = load_jsonl(attacks_path)
    benign = load_jsonl(benign_path)
    engine = engine or WardenEngine()
    if semantic and not engine.semantic_enabled:
        raise RuntimeError(
            "semantic benchmark requires a fully configured paid semantic runtime"
        )
    detected_attacks = 0
    attack_misses: list[str] = []
    category_totals: dict[str, int] = defaultdict(int)
    category_hits: dict[str, int] = defaultdict(int)

    for entry in attacks:
        entry_id = str(entry["id"])
        category = str(entry["category"])
        category_totals[category] += 1
        verdict = await engine.scan(
            str(entry["payload"]),
            depth="thorough" if semantic else str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
            allow_paid_semantic=semantic,
        )
        classes = {reason.value for reason in verdict.threat_classes}
        detected = verdict.verdict != "ALLOW" and category in classes
        if detected:
            detected_attacks += 1
            category_hits[category] += 1
        else:
            attack_misses.append(entry_id)

    false_positive_ids: list[str] = []
    for entry in benign:
        verdict = await engine.scan(
            str(entry["payload"]),
            depth="thorough" if semantic else str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
            allow_paid_semantic=semantic,
        )
        if verdict.verdict != "ALLOW":
            false_positive_ids.append(str(entry["id"]))

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
        "benchmark": "warden-held-out-v1",
        "mode": (
            "paid thorough path; semantic after deterministic layers"
            if semantic
            else "deterministic fast path; thorough only where declared; semantic disabled"
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
    if semantic:
        published = json.loads(PUBLISHED_RESULTS.read_text(encoding="utf-8"))
        baseline_recall = float(published["attack_recall_percent"])
        result["semantic_enablement_gate"] = {
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
        "--semantic",
        action="store_true",
        help="Evaluate the configured paid semantic model in thorough mode.",
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help="Append a dated history record and refresh the public evaluation data.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        result = asyncio.run(
            evaluate_benchmark(args.attacks, args.benign, semantic=args.semantic)
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if args.record:
        record_benchmark(result)
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
    gate = result.get("semantic_enablement_gate")
    if isinstance(gate, dict):
        print(
            "Semantic enablement gate: "
            + ("PASS" if gate.get("passed") is True else "FAIL; keep disabled")
        )


if __name__ == "__main__":
    main()
