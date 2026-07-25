"""CI gate: regenerate the per-class variant packs and verify determinism and separation."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.adversarial_variants import (  # noqa: E402
    HELD_OUT_ATTACKS_PATH,
    HELD_OUT_BENIGN_PATH,
    INDEX_FILENAME,
    SOURCE_DATASET,
    THREAT_CLASSES,
    TRAINING_ATTACKS_PATH,
    TRAINING_BENIGN_PATH,
    build_variant_packs,
    load_dataset_rows,
    scanner_equivalence,
    write_variant_packs,
)
from warden.dataset_promotion import canonical_dataset_payload  # noqa: E402


def _build_into(directory: Path) -> dict[str, object]:
    packs = build_variant_packs(
        training_attacks_path=TRAINING_ATTACKS_PATH,
        training_benign_path=TRAINING_BENIGN_PATH,
        held_out_attacks_path=HELD_OUT_ATTACKS_PATH,
        held_out_benign_path=HELD_OUT_BENIGN_PATH,
    )
    return write_variant_packs(directory, packs)


def _pack_filenames() -> list[str]:
    return [INDEX_FILENAME, *(f"{threat_class}.json" for threat_class in THREAT_CLASSES)]


def verify_determinism(first: Path, second: Path) -> list[str]:
    failures: list[str] = []
    for name in _pack_filenames():
        left = first / name
        right = second / name
        if not left.is_file() or not right.is_file():
            failures.append(f"{name}: pack file was not written")
            continue
        if left.read_bytes() != right.read_bytes():
            failures.append(f"{name}: regeneration is not byte-identical")
    return failures


def verify_index(directory: Path, index: dict[str, object]) -> list[str]:
    failures: list[str] = []
    entries = index["classes"]
    if [str(entry["threat_class"]) for entry in entries] != list(THREAT_CLASSES):
        failures.append("index.json does not cover every Warden threat class in order")
    for entry in entries:
        path = directory / str(entry["file"])
        digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        if digest != entry["sha256"]:
            failures.append(f"{entry['file']}: index digest does not match the written pack")
        pack = json.loads(path.read_text(encoding="utf-8"))
        if pack["threat_class"] != entry["threat_class"]:
            failures.append(f"{entry['file']}: pack threat class does not match the index")
        if len(pack["variants"]) != entry["variants"]:
            failures.append(f"{entry['file']}: index variant count does not match the pack")
        for variant in pack["variants"]:
            if variant["threat_class"] != entry["threat_class"]:
                failures.append(f"{entry['file']}: contains a variant of another threat class")
                break
    return failures


def verify_separation(directory: Path) -> list[str]:
    """Re-derive I3 separation from the written packs, independent of the generator."""
    failures: list[str] = []
    training = load_dataset_rows(TRAINING_ATTACKS_PATH, label="training attacks")
    held_out = [
        *load_dataset_rows(HELD_OUT_ATTACKS_PATH, label="held-out attacks"),
        *load_dataset_rows(HELD_OUT_BENIGN_PATH, label="held-out benign"),
    ]
    training_payloads = {str(row["id"]): str(row["payload"]) for row in training}
    held_out_ids = {str(row["id"]) for row in held_out}
    held_out_canonicals = {canonical_dataset_payload(row["payload"]) for row in held_out}
    held_out_equivalence = set().union(
        *(scanner_equivalence(str(row["payload"])) for row in held_out)
    )

    for threat_class in THREAT_CLASSES:
        path = directory / f"{threat_class}.json"
        text = path.read_text(encoding="utf-8")
        leaked_ids = sorted(case_id for case_id in held_out_ids if case_id in text)
        if leaked_ids:
            failures.append(f"{path.name}: contains held-out case ids {', '.join(leaked_ids)}")
        for variant in json.loads(text)["variants"]:
            case_id = str(variant["source_case_id"])
            label = f"{path.name}:{case_id}:{'+'.join(variant['transform_chain'])}"
            if variant["source_dataset"] != SOURCE_DATASET:
                failures.append(f"{label}: variant is not sourced from the training corpus")
                continue
            if case_id not in training_payloads:
                failures.append(f"{label}: source case id is not a training attack")
                continue
            payload = str(variant["payload"])
            if canonical_dataset_payload(payload) in held_out_canonicals:
                failures.append(f"{label}: variant payload matches a held-out row")
            equivalence = scanner_equivalence(payload)
            if equivalence & held_out_equivalence:
                failures.append(f"{label}: variant is scanner-equivalent to a held-out row")
            if canonical_dataset_payload(training_payloads[case_id]) not in equivalence:
                failures.append(f"{label}: variant does not decode back to its training source")
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if variant["payload_sha256"] != f"sha256:{digest}":
                failures.append(f"{label}: payload digest does not match the payload")
    return failures


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate the per-class adversarial variant packs twice and verify byte-level "
            "determinism, index integrity, and training/held-out separation. Writes only to a "
            "temporary directory and performs no network or model calls."
        )
    )
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    with tempfile.TemporaryDirectory() as workspace:
        first = Path(workspace) / "first"
        second = Path(workspace) / "second"
        index = _build_into(first)
        _build_into(second)
        failures = [
            *verify_determinism(first, second),
            *verify_index(first, index),
            *verify_separation(first),
        ]
    result = {
        "check": "warden-variant-packs-v1",
        "classes": len(THREAT_CLASSES),
        "total_variants": index["total_variants"],
        "corpus_fingerprint": index["corpus_fingerprint"],
        "failures": failures,
        "passed": not failures,
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"Variant packs: {result['total_variants']} variants across "
            f"{result['classes']} threat classes"
        )
        print(f"Corpus fingerprint: {result['corpus_fingerprint']}")
        for failure in failures:
            print(f"FAIL {failure}")
        print("Determinism and separation: " + ("PASS" if result["passed"] else "FAIL"))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
