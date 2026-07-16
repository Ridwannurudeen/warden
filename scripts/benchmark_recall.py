"""Measure Warden against the versioned held-out attack and benign sets."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.engine import WardenEngine  # noqa: E402

DEFAULT_ATTACKS = ROOT / "benchmark" / "held_out_attacks.jsonl"
DEFAULT_BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"


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


async def evaluate_benchmark(
    attacks_path: Path = DEFAULT_ATTACKS,
    benign_path: Path = DEFAULT_BENIGN,
) -> dict[str, object]:
    attacks = load_jsonl(attacks_path)
    benign = load_jsonl(benign_path)
    engine = WardenEngine()
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
            depth=str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
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
            depth=str(entry.get("depth", "fast")),
            context=entry.get("context") if isinstance(entry.get("context"), dict) else None,
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
    return {
        "schema_version": 1,
        "benchmark": "warden-held-out-v1",
        "mode": "deterministic fast path; thorough only where declared; semantic disabled",
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Warden's held-out detection benchmark.")
    parser.add_argument("--attacks", type=Path, default=DEFAULT_ATTACKS)
    parser.add_argument("--benign", type=Path, default=DEFAULT_BENIGN)
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    result = asyncio.run(evaluate_benchmark(args.attacks, args.benign))
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


if __name__ == "__main__":
    main()

