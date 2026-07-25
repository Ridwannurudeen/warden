"""Measure Warden's false-positive rate on the first-party benign operations corpus.

Recall is measured by `scripts/benchmark_recall.py`. This is the other half: how often the
engine flags text that is not an attack. It runs `corpus/benign_ops_v1.jsonl` at both scan
depths, attributes every flagged row to the layer and pattern that fired, and reports the
Wilson 95% upper bound on the true false-positive rate implied by the observed count.

    python scripts/measure_benign_fp.py
    python scripts/measure_benign_fp.py --json
"""

import argparse
import asyncio
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from warden.engine import WardenEngine  # noqa: E402
from warden.scanner.patterns import INJECTION_PATTERNS  # noqa: E402

CORPUS = ROOT / "corpus" / "benign_ops_v1.jsonl"
DEPTHS = ("fast", "thorough")


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def wilson_upper_bound(successes: int, trials: int, z: float = 1.6449) -> float:
    """One-sided upper bound of the Wilson score interval (default 95%)."""
    if trials == 0:
        return 1.0
    phat = successes / trials
    denominator = 1 + z * z / trials
    centre = phat + z * z / (2 * trials)
    margin = z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
    return min(1.0, (centre + margin) / denominator)


def matching_regexes(payload: str) -> list[tuple[str, str]]:
    """Every Layer 1 pattern that fires on this exact text, as (category, pattern)."""
    hits = []
    for category, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload):
                hits.append((category, pattern))
    return hits


def attribute(row: dict, verdict) -> list[dict]:
    """Describe every detection on a flagged row, naming the responsible pattern."""
    regexes = matching_regexes(row["payload"])
    causes = []
    for detection in verdict.detections:
        source = str(detection.get("source", ""))
        cause = {
            "source": source,
            "class": str(detection.get("class", "")),
            "match": str(detection.get("match", "")),
            "confidence": float(detection.get("confidence", 0.0)),
        }
        if source.endswith("layer_1") and regexes:
            category, pattern = regexes[0]
            cause["pattern_category"] = category
            cause["pattern"] = pattern
        causes.append(cause)
    if not causes:
        causes.append(
            {
                "source": "verdict_policy",
                "class": ",".join(reason.value for reason in verdict.threat_classes),
                "match": "",
                "confidence": 0.0,
            }
        )
    return causes


def cause_key(cause: dict) -> str:
    if "pattern" in cause:
        return f"{cause['source']} {cause['pattern_category']} {cause['pattern']}"
    return f"{cause['source']} {cause['class']} :: {cause['match'][:60]}"


async def measure(rows: list[dict]) -> dict:
    engine = WardenEngine()
    report = {"corpus": CORPUS.name, "total": len(rows), "depths": {}}
    for depth in DEPTHS:
        flagged = []
        for row in rows:
            verdict = await engine.scan(row["payload"], depth=depth)
            if verdict.verdict == "ALLOW":
                continue
            flagged.append(
                {
                    "id": row["id"],
                    "category": row["category"],
                    "verdict": verdict.verdict,
                    "risk_level": verdict.risk_level,
                    "payload": row["payload"],
                    "causes": attribute(row, verdict),
                }
            )
        count = len(flagged)
        report["depths"][depth] = {
            "false_positives": count,
            "rate": count / len(rows) if rows else 0.0,
            "wilson_95_upper": wilson_upper_bound(count, len(rows)),
            "by_category": dict(Counter(entry["category"] for entry in flagged)),
            "by_cause": dict(
                Counter(cause_key(cause) for entry in flagged for cause in entry["causes"])
            ),
            "rows": flagged,
        }
    return report


def render(report: dict) -> str:
    lines = [f"corpus: {report['corpus']}  rows: {report['total']}", ""]
    for depth, result in report["depths"].items():
        lines.append(
            f"depth={depth}: {result['false_positives']}/{report['total']} flagged "
            f"({result['rate'] * 100:.2f}%), Wilson 95% upper bound "
            f"{result['wilson_95_upper'] * 100:.2f}%"
        )
        for category, count in sorted(result["by_category"].items(), key=lambda kv: -kv[1]):
            lines.append(f"    category {category}: {count}")
        for cause, count in sorted(result["by_cause"].items(), key=lambda kv: -kv[1]):
            lines.append(f"    cause x{count}: {cause}")
        for entry in result["rows"]:
            lines.append(f"      {entry['id']} {entry['verdict']}/{entry['risk_level']}")
            for cause in entry["causes"]:
                lines.append(f"        {cause['source']} {cause['class']} <- {cause['match']!r}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit the full report as JSON.")
    args = parser.parse_args()

    report = asyncio.run(measure(load_jsonl(CORPUS)))
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
