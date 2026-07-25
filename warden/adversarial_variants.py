"""Deterministic adversarial variants derived from training attacks only."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote_from_bytes
from uuid import uuid4

from warden import feedback_store
from warden.core.verdict import ReasonCode
from warden.dataset_promotion import canonical_dataset_payload
from warden.scanner.normalize import derive_candidates
from warden.scanner.patterns import KNOWN_INJECTIONS

ROOT = Path(__file__).resolve().parents[1]
TRAINING_ATTACKS_PATH = ROOT / "corpus" / "attacks.jsonl"
TRAINING_BENIGN_PATH = ROOT / "corpus" / "benign.jsonl"
HELD_OUT_ATTACKS_PATH = ROOT / "benchmark" / "held_out_attacks.jsonl"
HELD_OUT_BENIGN_PATH = ROOT / "benchmark" / "held_out_benign.jsonl"
MAX_DATASET_BYTES = 10_000_000
MAX_DATASET_ROWS = 10_000
MAX_SOURCE_PAYLOAD_LENGTH = 4_000
SOURCE_DATASET = "corpus/attacks.jsonl"
GENERATOR_ID = "warden-adversarial-variants/3"
SCHEMA_VERSION = 3
INDEX_FILENAME = "index.json"
THREAT_CLASSES = tuple(reason.value for reason in ReasonCode)

_EXTERNAL_PROVENANCE_FIELDS = (
    "source_id",
    "source_revision",
    "source_path",
    "source_record_id",
    "source_url",
    "source_file_sha256",
    "license_spdx",
    "license_url",
)
_HOMOGLYPHS = str.maketrans(
    {
        "A": "А",
        "B": "Β",
        "E": "Е",
        "H": "Н",
        "I": "І",
        "K": "Κ",
        "M": "М",
        "N": "Ν",
        "O": "О",
        "P": "Р",
        "S": "Ѕ",
        "T": "Т",
        "X": "Х",
        "a": "а",
        "c": "с",
        "e": "е",
        "i": "і",
        "j": "ј",
        "o": "о",
        "p": "р",
        "s": "ѕ",
        "x": "х",
        "y": "у",
    }
)


def load_dataset_rows(path: Path, *, label: str) -> list[dict[str, object]]:
    if path.is_symlink():
        raise ValueError(f"{label} dataset must not be a symlink")
    if not path.is_file():
        raise ValueError(f"{label} dataset does not exist")
    if path.stat().st_size > MAX_DATASET_BYTES:
        raise ValueError(f"{label} dataset exceeds the size limit")

    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(rows) >= MAX_DATASET_ROWS:
                raise ValueError(f"{label} dataset exceeds the row limit")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number} must contain a JSON object")
            case_id = row.get("id")
            payload = row.get("payload")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"{path}:{line_number} must contain a non-empty id")
            if not isinstance(payload, str) or not payload.strip():
                raise ValueError(f"{path}:{line_number} must contain non-empty payload text")
            if len(payload) > MAX_SOURCE_PAYLOAD_LENGTH:
                raise ValueError(f"{path}:{line_number} payload exceeds the length limit")
            try:
                payload.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    f"{path}:{line_number} payload must contain Unicode scalar text"
                ) from exc
            rows.append(row)
    return rows


def _validate_training_rows(
    attacks: list[dict[str, object]],
    benign: list[dict[str, object]],
) -> None:
    seen_ids: set[str] = set()
    seen_equivalence_sets: set[frozenset[str]] = set()
    for label, rows in (("training attacks", attacks), ("training benign", benign)):
        for row in rows:
            case_id = str(row["id"])
            equivalence = scanner_equivalence(str(row["payload"]))
            if case_id in seen_ids:
                raise ValueError(f"{label} contains a duplicate case id")
            if equivalence in seen_equivalence_sets:
                raise ValueError("training datasets contain scanner-equivalent payloads")
            seen_ids.add(case_id)
            seen_equivalence_sets.add(equivalence)

    for row in attacks:
        if row.get("expected_verdict") not in {"SANITIZE", "BLOCK"}:
            raise ValueError("training attack expected_verdict must be SANITIZE or BLOCK")
        category = row.get("category")
        expected_classes = row.get("expected_classes")
        if (
            not isinstance(category, str)
            or not category
            or not isinstance(expected_classes, list)
            or not expected_classes
            or not all(isinstance(item, str) and item for item in expected_classes)
        ):
            raise ValueError("training attack must contain category and expected_classes")
        if category not in THREAT_CLASSES:
            raise ValueError("training attack category must be a known Warden threat class")


def scanner_equivalence(payload: str) -> frozenset[str]:
    derived = {
        canonical_dataset_payload(candidate) for candidate, _transform in derive_candidates(payload)
    }
    return frozenset(derived or {canonical_dataset_payload(payload)})


def _validate_dataset_separation(
    training: list[dict[str, object]],
    held_out: list[dict[str, object]],
) -> None:
    training_equivalence = set().union(
        *(scanner_equivalence(str(row["payload"])) for row in training)
    )
    held_out_equivalence = set().union(
        *(scanner_equivalence(str(row["payload"])) for row in held_out)
    )
    if training_equivalence & held_out_equivalence:
        raise ValueError("training and held-out datasets contain scanner-equivalent payloads")


def _validate_canonical_sources(
    *,
    training_attacks_path: Path,
    training_benign_path: Path,
    held_out_attacks_path: Path,
    held_out_benign_path: Path,
) -> None:
    supplied = (
        training_attacks_path,
        training_benign_path,
        held_out_attacks_path,
        held_out_benign_path,
    )
    canonical = (
        TRAINING_ATTACKS_PATH,
        TRAINING_BENIGN_PATH,
        HELD_OUT_ATTACKS_PATH,
        HELD_OUT_BENIGN_PATH,
    )
    try:
        supplied_resolved = tuple(path.resolve(strict=True) for path in supplied)
        canonical_resolved = tuple(path.resolve(strict=True) for path in canonical)
    except OSError as exc:
        raise ValueError("variant sources must be readable canonical dataset files") from exc
    if supplied_resolved != canonical_resolved:
        raise ValueError("variant generation requires the canonical Warden dataset paths")


def _base64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _percent(value: str) -> str:
    return quote_from_bytes(value.encode("utf-8"), safe="")


def _html_entities(value: str) -> str:
    return "".join(f"&#{ord(character)};" for character in value)


def _x_escape(value: str) -> str:
    return "".join(f"\\x{byte:02x}" for byte in value.encode("utf-8"))


def _expanded_whitespace(value: str) -> str:
    return value.replace(" ", " \t ")


def _homoglyph(value: str) -> str:
    transformed = value.translate(_HOMOGLYPHS)
    if transformed == value:
        raise ValueError("training attack cannot produce a supported homoglyph variant")
    return transformed


def _nested_json(value: str) -> str:
    inner = json.dumps(
        {"encoding": "base64", "payload": _base64(value)},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return json.dumps(
        {"encoding": "base64", "payload": _base64(inner)},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _transforms() -> tuple[tuple[tuple[str, ...], Callable[[str], str]], ...]:
    return (
        (("encoding:base64",), _base64),
        (("encoding:hex",), lambda value: value.encode("utf-8").hex()),
        (("encoding:percent",), _percent),
        (("encoding:html-entities",), _html_entities),
        (("encoding:x-escape",), _x_escape),
        (("case:swap", "encoding:base64"), lambda value: _base64(value.swapcase())),
        (
            ("whitespace:expand", "encoding:base64"),
            lambda value: _base64(_expanded_whitespace(value)),
        ),
        (
            ("unicode:homoglyph", "encoding:base64"),
            lambda value: _base64(_homoglyph(value)),
        ),
        (
            (
                "nesting:json",
                "encoding:base64",
                "nesting:json",
                "encoding:base64",
            ),
            _nested_json,
        ),
    )


def _source_metadata(row: dict[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {
        "case_id": row["id"],
        "dataset": SOURCE_DATASET,
        "license_spdx": row.get("license_spdx", ["Apache-2.0"]),
    }
    note = row.get("note")
    if isinstance(note, str) and note:
        metadata["provenance"] = note
    if "source_id" in row:
        missing = [field for field in _EXTERNAL_PROVENANCE_FIELDS if field not in row]
        if missing:
            raise ValueError("external training row has incomplete provenance")
        metadata.update({field: row[field] for field in _EXTERNAL_PROVENANCE_FIELDS})
    licenses = metadata["license_spdx"]
    if (
        not isinstance(licenses, list)
        or not licenses
        or not all(isinstance(value, str) and value for value in licenses)
    ):
        raise ValueError("training attack license_spdx must contain SPDX identifiers")
    return metadata


def _build_variants(
    *,
    training_attacks_path: Path,
    training_benign_path: Path,
    held_out_attacks_path: Path,
    held_out_benign_path: Path,
) -> list[dict[str, object]]:
    _validate_canonical_sources(
        training_attacks_path=training_attacks_path,
        training_benign_path=training_benign_path,
        held_out_attacks_path=held_out_attacks_path,
        held_out_benign_path=held_out_benign_path,
    )
    training_attacks = load_dataset_rows(training_attacks_path, label="training attacks")
    training_benign = load_dataset_rows(training_benign_path, label="training benign")
    held_out_attacks = load_dataset_rows(held_out_attacks_path, label="held-out attacks")
    held_out_benign = load_dataset_rows(held_out_benign_path, label="held-out benign")
    _validate_training_rows(training_attacks, training_benign)
    _validate_dataset_separation(
        [*training_attacks, *training_benign],
        [*held_out_attacks, *held_out_benign],
    )

    occupied_canonicals = {
        canonical_dataset_payload(row["payload"])
        for row in (
            *training_attacks,
            *training_benign,
            *held_out_attacks,
            *held_out_benign,
        )
    }
    occupied_canonicals.update(canonical_dataset_payload(payload) for payload in KNOWN_INJECTIONS)
    held_out_equivalence = set().union(
        *(scanner_equivalence(str(row["payload"])) for row in (*held_out_attacks, *held_out_benign))
    )
    known_injection_equivalence = set().union(
        *(scanner_equivalence(payload) for payload in KNOWN_INJECTIONS)
    )

    variants: list[dict[str, object]] = []
    for row in sorted(training_attacks, key=lambda item: str(item["id"])):
        payload = str(row["payload"])
        source = _source_metadata(row)
        source_normalized = canonical_dataset_payload(payload)
        for transform_chain, transform in _transforms():
            variant_payload = transform(payload)
            normalized = canonical_dataset_payload(variant_payload)
            if normalized in occupied_canonicals:
                continue
            equivalence = scanner_equivalence(variant_payload)
            if source_normalized not in equivalence:
                continue
            if equivalence & held_out_equivalence:
                continue
            if equivalence & known_injection_equivalence:
                continue
            occupied_canonicals.add(normalized)
            variant: dict[str, object] = {
                "threat_class": row["category"],
                "source_case_id": row["id"],
                "source_dataset": SOURCE_DATASET,
                "transform_chain": list(transform_chain),
                "payload": variant_payload,
                "payload_sha256": (
                    f"sha256:{hashlib.sha256(variant_payload.encode('utf-8')).hexdigest()}"
                ),
                "evaluation": {
                    "observed_verdict_must_not_equal": "ALLOW",
                    "required_classes": row["expected_classes"],
                },
                "source": source,
            }
            for field in ("context", "depth"):
                if field in row:
                    variant[field] = row[field]
            variants.append(variant)

    return variants


def _pack_header() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR_ID,
        "source": "training-only",
        "corpus_fingerprint": feedback_store.corpus_fingerprint(),
    }


def build_variant_packs(
    *,
    training_attacks_path: Path,
    training_benign_path: Path,
    held_out_attacks_path: Path,
    held_out_benign_path: Path,
) -> dict[str, dict[str, object]]:
    """Build one stable pack per threat class without copying held-out rows."""
    variants = _build_variants(
        training_attacks_path=training_attacks_path,
        training_benign_path=training_benign_path,
        held_out_attacks_path=held_out_attacks_path,
        held_out_benign_path=held_out_benign_path,
    )
    header = _pack_header()
    return {
        threat_class: {
            **header,
            "threat_class": threat_class,
            "variants": [row for row in variants if row["threat_class"] == threat_class],
        }
        for threat_class in THREAT_CLASSES
    }


def _serialize_pack(pack: dict[str, object]) -> str:
    return json.dumps(pack, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _write_atomic(path: Path, content: str) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("variant pack output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_variant_packs(
    directory: Path,
    packs: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Atomically write one deterministic pack per threat class plus an index."""
    classes: list[dict[str, object]] = []
    total = 0
    for threat_class in THREAT_CLASSES:
        pack = packs[threat_class]
        serialized = _serialize_pack(pack)
        _write_atomic(directory / f"{threat_class}.json", serialized)
        rows = pack["variants"]
        total += len(rows)
        classes.append(
            {
                "threat_class": threat_class,
                "file": f"{threat_class}.json",
                "variants": len(rows),
                "source_case_ids": sorted({str(row["source_case_id"]) for row in rows}),
                "sha256": f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}",
            }
        )
    index = {**_pack_header(), "classes": classes, "total_variants": total}
    _write_atomic(directory / INDEX_FILENAME, _serialize_pack(index))
    return index
