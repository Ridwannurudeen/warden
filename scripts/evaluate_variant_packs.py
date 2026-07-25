"""Evaluate Warden's deterministic detector against the per-class adversarial variant packs.

This is a separate evaluation surface. It never reads, writes, or re-records the published
held-out benchmark, and it performs no network or model calls.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.adversarial_variants import INDEX_FILENAME, SCHEMA_VERSION  # noqa: E402
from warden.engine import WardenEngine  # noqa: E402


def _detection_percent(detected: int, variants: int) -> float | None:
    """Return ``None`` for an empty class rather than an unearned zero."""
    return round((detected / variants) * 100, 2) if variants else None


def load_packs(directory: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Load the pack index and every class pack, checking each file against the index digest."""
    index = json.loads((directory / INDEX_FILENAME).read_text(encoding="utf-8"))
    if index.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"variant pack index must use schema version {SCHEMA_VERSION}")
    packs: list[dict[str, object]] = []
    for entry in index["classes"]:
        path = directory / str(entry["file"])
        content = path.read_bytes()
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if digest != entry["sha256"]:
            raise ValueError(f"{path.name} does not match its index digest")
        pack = json.loads(content.decode("utf-8"))
        if pack["threat_class"] != entry["threat_class"]:
            raise ValueError(f"{path.name} does not declare its indexed threat class")
        packs.append(pack)
    return index, packs


async def evaluate_packs(directory: Path) -> dict[str, object]:
    index, packs = load_packs(directory)
    engine = WardenEngine()
    per_class: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    total = 0
    detected = 0

    for pack in packs:
        threat_class = str(pack["threat_class"])
        class_detected = 0
        variants = pack["variants"]
        for variant in variants:
            evaluation = variant["evaluation"]
            context = variant.get("context")
            verdict = await engine.scan(
                str(variant["payload"]),
                depth=str(variant.get("depth", "fast")),
                context=context if isinstance(context, dict) else None,
                allow_paid_semantic=False,
            )
            observed_classes = sorted(reason.value for reason in verdict.threat_classes)
            required = set(evaluation["required_classes"])
            fired = verdict.verdict != evaluation["observed_verdict_must_not_equal"]
            if fired and required.issubset(observed_classes):
                class_detected += 1
            else:
                failures.append(
                    {
                        "threat_class": threat_class,
                        "source_case_id": variant["source_case_id"],
                        "transform_chain": variant["transform_chain"],
                        "observed_verdict": verdict.verdict,
                        "observed_classes": observed_classes,
                    }
                )
        total += len(variants)
        detected += class_detected
        per_class.append(
            {
                "threat_class": threat_class,
                "variants": len(variants),
                "detected": class_detected,
                "detection_percent": _detection_percent(class_detected, len(variants)),
            }
        )

    return {
        "evaluation": "warden-adversarial-variants-v1",
        "generator": index["generator"],
        "corpus_fingerprint": index["corpus_fingerprint"],
        "mode": "deterministic fast path; thorough only where the training source declares it",
        "evidence_scope": (
            "training-derived variants only; not held-out evidence and not the published benchmark"
        ),
        "variants": total,
        "detected": detected,
        "detection_percent": _detection_percent(detected, total),
        "per_class": per_class,
        "failures": failures,
    }


def _format_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}%"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the deterministic detector against per-class adversarial variant packs "
            "built from the training corpus. Reports results only; it does not gate CI and "
            "never touches the published held-out benchmark."
        )
    )
    parser.add_argument("pack_directory", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = asyncio.run(evaluate_packs(args.pack_directory))
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return 0
    print(
        f"Variant detection: {_format_percent(result['detection_percent'])} "
        f"({result['detected']}/{result['variants']})"
    )
    for entry in result["per_class"]:
        print(
            f"  {entry['threat_class']:<20} {entry['detected']:>4}/{entry['variants']:<4} "
            f"{_format_percent(entry['detection_percent'])}"
        )
    print(f"Evidence scope: {result['evidence_scope']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
