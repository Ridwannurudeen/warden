"""Persistent queue for public Gauntlet attempts and candidate bypasses."""

from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from collections.abc import Iterator
from pathlib import Path
from threading import Lock
from uuid import uuid4

from warden.core.verdict import ReasonCode
from warden.models import ClaimStatus, GauntletRequest, ScanResponse


_STORE_PATH = Path(__file__).resolve().parents[1] / "gauntlet" / "attempts.jsonl"
_LOCK = Lock()
# Cap on-disk growth from the unauthenticated public demo route.
_MAX_RECORDS = 5000
_MAX_PENDING_RECORDS = 500
_DEFAULT_BENCHMARK_PATH = Path(__file__).resolve().parents[1] / "benchmark" / "held_out_attacks.jsonl"
_CLAIM_ID_RE = re.compile(r"[0-9a-f]{64}")


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def _exclusive_store_lock() -> Iterator[None]:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_path = _STORE_PATH.with_name(f".{_STORE_PATH.name}.lock")
    with _LOCK, lock_path.open("a+b") as handle:
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


def _read_records_locked() -> list[dict[str, object]]:
    if not _STORE_PATH.exists():
        return []
    records: list[dict[str, object]] = []
    with _STORE_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A single truncated/corrupt line (e.g. a crash mid-append) must not
                # break every subsequent read of the store.
                continue
    return records


def _prune_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    pending = [
        index for index, record in enumerate(records) if record.get("status") == "pending"
    ]
    retained = set(pending[-_MAX_PENDING_RECORDS:]) if _MAX_PENDING_RECORDS > 0 else set()
    retained.update(
        index for index, record in enumerate(records) if record.get("status") == "confirmed"
    )
    routine = [
        index
        for index, record in enumerate(records)
        if record.get("status") not in {"pending", "confirmed"}
    ]
    budget = max(0, _MAX_RECORDS - len(retained))
    if budget:
        retained.update(routine[-budget:])
    return [record for index, record in enumerate(records) if index in retained]


def _claim_id(request: GauntletRequest) -> str:
    expected_addresses = {
        address.lower() if address.lower().startswith("0x") else address
        for address in request.context.expected_addresses
    }
    claim = {
        "context": {"expected_addresses": sorted(expected_addresses)},
        "intent": request.intent,
        "payload": request.payload,
    }
    canonical = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_attempt(
    request: GauntletRequest,
    response: ScanResponse,
) -> tuple[ClaimStatus, str | None]:
    attempt_id = uuid4().hex[:16]
    payload_hash = hashlib.sha256(request.payload.encode("utf-8")).hexdigest()
    claim_id = _claim_id(request)
    intent_hash = hashlib.sha256(request.intent.encode("utf-8")).hexdigest()
    record: dict[str, object] = {
        "schema_version": 1,
        "attempt_id": attempt_id,
        "submitted_at": _timestamp(),
        "payload_hash": payload_hash,
        "intent_hash": intent_hash,
        "verdict": response.verdict,
        "risk_level": response.risk_level,
        "threat_classes": response.threat_classes,
    }

    with _exclusive_store_lock():
        records = _read_records_locked()
        if response.verdict == "ALLOW":
            existing = next(
                (
                    item
                    for item in records
                    if item.get("claim_id") == claim_id
                    and item.get("status") in {"pending", "confirmed"}
                ),
                None,
            )
            if existing is None:
                status: ClaimStatus = "pending"
                record["claim_id"] = claim_id
                record["payload"] = request.payload
                record["intent"] = request.intent
                record["context"] = request.context.model_dump(mode="json")
                if request.finder:
                    record["finder"] = request.finder
            else:
                status = "duplicate"
                claim_id = str(existing["claim_id"])
                record["claim_id"] = claim_id
                record["duplicate_of"] = existing["attempt_id"]
        else:
            status = "not_candidate"
            claim_id = None
        record["status"] = status

        updated = [*records, record]
        pruned = _prune_records(updated)
        if len(pruned) != len(updated):
            tmp = _STORE_PATH.with_suffix(".jsonl.tmp")
            with tmp.open("w", encoding="utf-8") as handle:
                for item in pruned:
                    handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            tmp.replace(_STORE_PATH)
        else:
            serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
            with _STORE_PATH.open("a", encoding="utf-8") as handle:
                handle.write(serialized + "\n")
    return status, claim_id


def get_stats(corpus_size: int) -> dict[str, int]:
    with _exclusive_store_lock():
        records = _read_records_locked()
    return {
        "attempts": len(records),
        "pending_claims": sum(record.get("status") == "pending" for record in records),
        "confirmed_bypasses": sum(record.get("status") == "confirmed" for record in records),
        "corpus_size": corpus_size,
    }


def confirm_bypass(
    claim_id: str,
    category: ReasonCode,
    *,
    benchmark_path: Path = _DEFAULT_BENCHMARK_PATH,
    confirmed_at: str | None = None,
) -> dict[str, object]:
    """Promote one explicitly reviewed pending claim into the held-out benchmark."""
    if _CLAIM_ID_RE.fullmatch(claim_id) is None:
        raise ValueError("claim_id must be 64 lowercase hex characters")
    confirmed_at = confirmed_at or _timestamp()
    try:
        parsed_at = datetime.fromisoformat(confirmed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("confirmed_at must be an exact UTC timestamp") from exc
    if parsed_at.tzinfo != timezone.utc or parsed_at.microsecond or not confirmed_at.endswith("Z"):
        raise ValueError("confirmed_at must be an exact UTC timestamp")

    with _exclusive_store_lock():
        records = _read_records_locked()
        claim = next(
            (
                record
                for record in records
                if record.get("claim_id") == claim_id
                and record.get("status") in {"pending", "confirmed"}
            ),
            None,
        )
        if claim is None:
            raise ValueError("no pending Gauntlet claim matches claim_id")

        case_id = f"gauntlet-{claim_id[:16]}"
        case: dict[str, object] = {
            "id": case_id,
            "category": category.value,
            "payload": str(claim["payload"]),
            "source": "human-reviewed-gauntlet",
        }
        context = claim.get("context")
        if isinstance(context, dict) and (
            context.get("expected_addresses") or context.get("source")
        ):
            case["context"] = context

        benchmark_cases = []
        if benchmark_path.exists():
            if benchmark_path.is_symlink():
                raise ValueError("held-out benchmark path must not be a symlink")
            with benchmark_path.open(encoding="utf-8") as handle:
                benchmark_cases = [json.loads(line) for line in handle if line.strip()]
        existing = next(
            (entry for entry in benchmark_cases if entry.get("id") == case_id),
            None,
        )
        if existing is not None and existing != case:
            raise ValueError("held-out benchmark case id conflicts with reviewed claim")
        if claim.get("status") == "confirmed":
            if existing is None or claim.get("benchmark_case_id") != case_id:
                raise ValueError("confirmed Gauntlet claim is missing its held-out case")
            return case

        normalized = " ".join(str(case["payload"]).casefold().split())
        root = Path(__file__).resolve().parents[1]
        with (root / "corpus" / "attacks.jsonl").open(encoding="utf-8") as handle:
            training_payloads = {
                " ".join(str(json.loads(line)["payload"]).casefold().split())
                for line in handle
                if line.strip()
            }
        from warden.scanner.patterns import KNOWN_INJECTIONS

        training_payloads.update(
            " ".join(payload.casefold().split()) for payload in KNOWN_INJECTIONS
        )
        if normalized in training_payloads:
            raise ValueError("reviewed claim overlaps the training corpus")
        if any(
            " ".join(str(entry.get("payload", "")).casefold().split()) == normalized
            and entry.get("id") != case_id
            for entry in benchmark_cases
        ):
            raise ValueError("reviewed claim duplicates an existing held-out payload")

        if existing is None:
            benchmark_path.parent.mkdir(parents=True, exist_ok=True)
            benchmark_temporary = benchmark_path.with_suffix(".jsonl.tmp")
            with benchmark_temporary.open("w", encoding="utf-8") as handle:
                for entry in [*benchmark_cases, case]:
                    handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            benchmark_temporary.replace(benchmark_path)

        claim["status"] = "confirmed"
        claim["confirmed_at"] = confirmed_at
        claim["benchmark_case_id"] = case_id
        store_temporary = _STORE_PATH.with_suffix(".jsonl.tmp")
        with store_temporary.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        store_temporary.replace(_STORE_PATH)
        return case
