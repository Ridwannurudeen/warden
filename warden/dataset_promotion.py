"""Shared guards for human-reviewed training and benchmark promotion."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Literal
from uuid import uuid4

from warden.scanner.normalize import fold_unicode

_LOCK = Lock()
TrainingDataset = Literal["attacks", "benign"]


def canonical_dataset_payload(value: object) -> str:
    return " ".join(fold_unicode(str(value)).casefold().split())


@contextmanager
def exclusive_dataset_lock(held_out_attacks_path: Path) -> Iterator[None]:
    lock_path = held_out_attacks_path.parent / ".warden-dataset-promotion.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if lock_path.exists() and lock_path.is_symlink():
        raise ValueError("dataset promotion lock must not be a symlink")
    with _LOCK, lock_path.open("a+b") as handle:
        if os.name != "nt":
            os.chmod(lock_path, 0o600)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    entries: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is invalid JSON") from exc
            if not isinstance(entry, dict) or not isinstance(entry.get("payload"), str):
                raise ValueError(f"{path}:{line_number} must contain payload text")
            entries.append(entry)
    return entries


def _atomic_write_jsonl(path: Path, entries: list[dict[str, object]]) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("dataset promotion target must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def promote_reviewed_training_batch(
    entries: list[dict[str, object]],
    *,
    dataset: TrainingDataset,
    reviewer_approved: bool,
    training_attacks_path: Path,
    training_benign_path: Path,
    held_out_attacks_path: Path,
    held_out_benign_path: Path,
) -> int:
    """Atomically append one reviewed batch to exactly one training dataset."""
    if reviewer_approved is not True:
        raise ValueError("explicit human reviewer approval is required")
    if dataset not in {"attacks", "benign"}:
        raise ValueError("training dataset must be attacks or benign")
    if not entries:
        raise ValueError("reviewed training batch must not be empty")

    paths = {
        "training-attacks": training_attacks_path,
        "training-benign": training_benign_path,
        "held-out-attacks": held_out_attacks_path,
        "held-out-benign": held_out_benign_path,
    }
    target_name = f"training-{dataset}"
    target_path = paths[target_name]

    with exclusive_dataset_lock(held_out_attacks_path):
        entries_by_dataset = {name: _load_jsonl(path) for name, path in paths.items()}
        from warden.scanner.patterns import KNOWN_INJECTIONS

        occupied_payloads = {
            canonical_dataset_payload(payload): "built-in injection list"
            for payload in KNOWN_INJECTIONS
        }
        occupied_ids: dict[str, tuple[str, dict[str, object]]] = {}
        for dataset_name, existing_entries in entries_by_dataset.items():
            for existing in existing_entries:
                existing_id = existing.get("id")
                if isinstance(existing_id, str):
                    occupied_ids[existing_id] = (dataset_name, existing)
                occupied_payloads.setdefault(
                    canonical_dataset_payload(existing["payload"]),
                    dataset_name,
                )

        reviewed_ids: set[str] = set()
        reviewed_payloads: set[str] = set()
        additions: list[dict[str, object]] = []
        for entry in entries:
            case_id = entry.get("id")
            payload = entry.get("payload")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError("reviewed training entry must have a non-empty id")
            if not isinstance(payload, str) or not payload.strip():
                raise ValueError("reviewed training entry must have non-empty payload text")
            normalized = canonical_dataset_payload(payload)
            if case_id in reviewed_ids:
                raise ValueError("reviewed training batch contains a duplicate case id")
            if normalized in reviewed_payloads:
                raise ValueError("reviewed training batch contains a duplicate payload")
            reviewed_ids.add(case_id)
            reviewed_payloads.add(normalized)

            existing_id = occupied_ids.get(case_id)
            if existing_id is not None:
                existing_dataset, existing_entry = existing_id
                if existing_dataset == target_name and existing_entry == entry:
                    continue
                raise ValueError("reviewed case id conflicts with an existing dataset entry")

            existing_payload_dataset = occupied_payloads.get(normalized)
            if existing_payload_dataset is not None:
                raise ValueError(
                    "reviewed payload overlaps existing training, held-out, "
                    f"or built-in material ({existing_payload_dataset})"
                )
            occupied_ids[case_id] = (target_name, entry)
            occupied_payloads[normalized] = target_name
            additions.append(entry)

        if additions:
            _atomic_write_jsonl(
                target_path,
                [*entries_by_dataset[target_name], *additions],
            )
        return len(additions)
