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

from warden.dataset_promotion import canonical_dataset_payload
from warden.scanner.normalize import derive_candidates
from warden.scanner.patterns import KNOWN_INJECTIONS

MAX_DATASET_BYTES = 10_000_000
MAX_DATASET_ROWS = 10_000
MAX_SOURCE_PAYLOAD_LENGTH = 4_000
SOURCE_DATASET = "corpus/attacks.jsonl"
GENERATOR_ID = "warden-adversarial-variants/1"

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


def _load_jsonl(path: Path, *, label: str) -> list[dict[str, object]]:
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
    seen_payloads: set[str] = set()
    for label, rows in (("training attacks", attacks), ("training benign", benign)):
        for row in rows:
            case_id = str(row["id"])
            normalized = canonical_dataset_payload(row["payload"])
            if case_id in seen_ids:
                raise ValueError(f"{label} contains a duplicate case id")
            if normalized in seen_payloads:
                raise ValueError("training datasets contain a duplicate payload")
            seen_ids.add(case_id)
            seen_payloads.add(normalized)

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


def _validate_dataset_separation(
    training: list[dict[str, object]],
    held_out: list[dict[str, object]],
) -> None:
    training_payloads = {canonical_dataset_payload(row["payload"]) for row in training}
    held_out_payloads = {canonical_dataset_payload(row["payload"]) for row in held_out}
    if training_payloads & held_out_payloads:
        raise ValueError("training and held-out datasets overlap")


def _corpus_fingerprint(
    attacks: list[dict[str, object]],
    benign: list[dict[str, object]],
) -> str:
    document = {
        "attacks": sorted(attacks, key=lambda row: str(row["id"])),
        "benign": sorted(benign, key=lambda row: str(row["id"])),
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


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


def build_variant_pack(
    *,
    training_attacks_path: Path,
    training_benign_path: Path,
    held_out_attacks_path: Path,
    held_out_benign_path: Path,
) -> dict[str, object]:
    """Build a stable pack without transforming or copying held-out rows."""
    training_attacks = _load_jsonl(training_attacks_path, label="training attacks")
    training_benign = _load_jsonl(training_benign_path, label="training benign")
    held_out_attacks = _load_jsonl(held_out_attacks_path, label="held-out attacks")
    held_out_benign = _load_jsonl(held_out_benign_path, label="held-out benign")
    _validate_training_rows(training_attacks, training_benign)
    _validate_dataset_separation(
        [*training_attacks, *training_benign],
        [*held_out_attacks, *held_out_benign],
    )

    occupied = {
        canonical_dataset_payload(row["payload"])
        for row in (
            *training_attacks,
            *training_benign,
            *held_out_attacks,
            *held_out_benign,
        )
    }
    occupied.update(canonical_dataset_payload(payload) for payload in KNOWN_INJECTIONS)

    generated: set[str] = set()
    variants: list[dict[str, object]] = []
    for row in sorted(training_attacks, key=lambda item: str(item["id"])):
        payload = str(row["payload"])
        source = _source_metadata(row)
        source_normalized = canonical_dataset_payload(payload)
        for transform_chain, transform in _transforms():
            variant_payload = transform(payload)
            normalized = canonical_dataset_payload(variant_payload)
            if normalized in occupied or normalized in generated:
                continue
            decoded = {
                canonical_dataset_payload(candidate)
                for candidate, _transform in derive_candidates(variant_payload)
            }
            if source_normalized not in decoded:
                continue
            generated.add(normalized)
            variants.append(
                {
                    "source_case_id": row["id"],
                    "source_dataset": SOURCE_DATASET,
                    "transform_chain": list(transform_chain),
                    "payload": variant_payload,
                    "payload_sha256": (
                        f"sha256:{hashlib.sha256(variant_payload.encode('utf-8')).hexdigest()}"
                    ),
                    "expected_verdict": row["expected_verdict"],
                    "expected_classes": row["expected_classes"],
                    "source": source,
                }
            )

    return {
        "schema_version": 1,
        "generator": GENERATOR_ID,
        "source": "training-only",
        "corpus_fingerprint": _corpus_fingerprint(training_attacks, training_benign),
        "variants": variants,
    }


def write_variant_pack(path: Path, pack: dict[str, object]) -> None:
    """Atomically write one deterministic JSON pack."""
    if path.exists() and path.is_symlink():
        raise ValueError("variant pack output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(pack, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
