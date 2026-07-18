"""Bounded private queue for explicitly consented, redacted scan feedback."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Literal
from uuid import uuid4

from warden.core.verdict import ReasonCode
from warden.dataset_promotion import (
    canonical_dataset_payload,
    exclusive_dataset_lock,
)
from warden.models import FeedbackRequest

ROOT = Path(__file__).resolve().parents[1]


def _configured_store_path() -> Path:
    configured = os.getenv("WARDEN_FEEDBACK_STORE", "").strip()
    return Path(configured) if configured else ROOT / "data" / "feedback" / "pending.jsonl"


_STORE_PATH = _configured_store_path()
_MAX_RECORDS = 5_000
_RETENTION_DAYS = 90
_LOCK = Lock()
_FEEDBACK_ID_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CORPUS_FINGERPRINT_RE = re.compile(r"sha256:[0-9a-f]{64}")
_PACKAGED_CORPUS_FINGERPRINT_PATH = Path(__file__).with_name("corpus_fingerprint.txt")
_OUTCOMES = {"missed_attack", "false_positive", "correct_detection"}
_VERDICTS = {"ALLOW", "SANITIZE", "BLOCK"}
_THREAT_CLASSES = {reason.value for reason in ReasonCode}

_TRAINING_ATTACKS_PATH = ROOT / "corpus" / "attacks.jsonl"
_TRAINING_BENIGN_PATH = ROOT / "corpus" / "benign.jsonl"
_HELD_OUT_ATTACKS_PATH = ROOT / "benchmark" / "held_out_attacks.jsonl"
_HELD_OUT_BENIGN_PATH = ROOT / "benchmark" / "held_out_benign.jsonl"

FeedbackDestination = Literal["training", "held-out"]
ExpectedAttackVerdict = Literal["SANITIZE", "BLOCK"]
_RECORD_KEYS = {
    "schema_version",
    "feedback_id",
    "dedupe_key",
    "submitted_at",
    "expires_at",
    "status",
    "outcome",
    "observed_verdict",
    "threat_class",
    "redacted_reproducer",
    "reproducer_sha256",
    "consent_to_retain",
    "redaction_confirmed",
    "scanner_version",
    "corpus_fingerprint",
}
_PROMOTION_KEYS = {
    "destination",
    "dataset",
    "case_id",
    "category",
    "expected_verdict",
    "reviewed_at",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _normalized_time(value: datetime | None) -> datetime:
    result = value or _utc_now()
    if result.tzinfo != timezone.utc:
        raise ValueError("feedback timestamps must use UTC")
    return result.replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        return None
    return parsed


def corpus_fingerprint() -> str:
    corpus_paths = (_TRAINING_ATTACKS_PATH, _TRAINING_BENIGN_PATH)
    existing = [path.exists() for path in corpus_paths]
    if all(existing):
        payload = b"".join(path.read_bytes() for path in corpus_paths)
        payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"
    if any(existing):
        raise RuntimeError("training corpus installation is incomplete")
    fingerprint = _PACKAGED_CORPUS_FINGERPRINT_PATH.read_text(encoding="ascii").strip()
    if _SHA256_RE.fullmatch(fingerprint) is None:
        raise RuntimeError("packaged corpus fingerprint is invalid")
    return f"sha256:{fingerprint}"


def reproducer_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _feedback_dedupe_key_values(
    *,
    outcome: str,
    observed_verdict: str,
    threat_class: str,
    redacted_reproducer: str,
) -> str:
    canonical = json.dumps(
        {
            "observed_verdict": observed_verdict,
            "outcome": outcome,
            "redacted_reproducer": canonical_dataset_payload(redacted_reproducer),
            "threat_class": threat_class,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def feedback_dedupe_key(request: FeedbackRequest) -> str:
    return _feedback_dedupe_key_values(
        outcome=request.outcome,
        observed_verdict=request.observed_verdict,
        threat_class=request.threat_class.value,
        redacted_reproducer=request.redacted_reproducer,
    )


def feedback_id_for_dedupe_key(dedupe_key: str) -> str:
    if _SHA256_RE.fullmatch(dedupe_key) is None:
        raise ValueError("feedback dedupe key must be 64 lowercase hex characters")
    return hashlib.sha256(f"warden-feedback:{dedupe_key}".encode("utf-8")).hexdigest()[:32]


def _valid_promotion(
    promotion: object,
    *,
    feedback_id: str,
    outcome: str,
    submitted_at: datetime,
    checked_at: datetime,
) -> bool:
    if not isinstance(promotion, dict) or set(promotion) != _PROMOTION_KEYS:
        return False
    destination = promotion.get("destination")
    category = promotion.get("category")
    expected_verdict = promotion.get("expected_verdict")
    reviewed_at = promotion.get("reviewed_at")
    if (
        destination not in {"training", "held-out"}
        or category not in _THREAT_CLASSES
        or promotion.get("case_id") != f"feedback-{feedback_id[:16]}"
        or not isinstance(reviewed_at, str)
    ):
        return False
    suffix = "benign" if outcome == "false_positive" else "attacks"
    if promotion.get("dataset") != f"{destination}-{suffix}":
        return False
    if outcome == "false_positive":
        if expected_verdict is not None:
            return False
    elif destination == "training":
        if expected_verdict not in {"SANITIZE", "BLOCK"}:
            return False
    elif expected_verdict is not None:
        return False
    parsed_reviewed_at = _parse_timestamp(reviewed_at)
    return parsed_reviewed_at is not None and submitted_at <= parsed_reviewed_at <= checked_at


def validate_feedback_record(
    record: dict[str, object],
    *,
    checked_at: datetime,
) -> dict[str, object] | None:
    status = record.get("status")
    expected_keys = _RECORD_KEYS | ({"promotion"} if status == "promoted" else set())
    if (
        set(record) != expected_keys
        or record.get("schema_version") != 1
        or status not in {"pending", "promoted"}
        or record.get("outcome") not in _OUTCOMES
        or record.get("observed_verdict") not in _VERDICTS
        or record.get("threat_class") not in _THREAT_CLASSES
        or record.get("consent_to_retain") is not True
        or record.get("redaction_confirmed") is not True
        or not isinstance(record.get("submitted_at"), str)
        or not isinstance(record.get("expires_at"), str)
        or not isinstance(record.get("feedback_id"), str)
        or _FEEDBACK_ID_RE.fullmatch(str(record["feedback_id"])) is None
        or not isinstance(record.get("dedupe_key"), str)
        or _SHA256_RE.fullmatch(str(record["dedupe_key"])) is None
        or not isinstance(record.get("redacted_reproducer"), str)
        or not str(record["redacted_reproducer"]).strip()
        or len(str(record["redacted_reproducer"])) > 4_000
        or not isinstance(record.get("reproducer_sha256"), str)
        or _SHA256_RE.fullmatch(str(record["reproducer_sha256"])) is None
        or not isinstance(record.get("scanner_version"), str)
        or not str(record["scanner_version"])
        or str(record["scanner_version"]).strip() != record["scanner_version"]
        or not isinstance(record.get("corpus_fingerprint"), str)
        or _CORPUS_FINGERPRINT_RE.fullmatch(str(record["corpus_fingerprint"])) is None
    ):
        return None
    try:
        str(record["scanner_version"]).encode("utf-8")
    except UnicodeEncodeError:
        return None
    submitted_at = _parse_timestamp(record["submitted_at"])
    expires_at = _parse_timestamp(record["expires_at"])
    if (
        submitted_at is None
        or expires_at is None
        or submitted_at > checked_at
        or expires_at != submitted_at + timedelta(days=_RETENTION_DAYS)
        or expires_at <= checked_at
    ):
        return None
    reproducer = str(record["redacted_reproducer"])
    try:
        if record["reproducer_sha256"] != reproducer_sha256(reproducer):
            return None
    except UnicodeEncodeError:
        return None
    try:
        request = FeedbackRequest.model_validate(
            {
                "outcome": record["outcome"],
                "observed_verdict": record["observed_verdict"],
                "threat_class": record["threat_class"],
                "redacted_reproducer": reproducer,
                "consent_to_retain": record["consent_to_retain"],
                "redaction_confirmed": record["redaction_confirmed"],
            }
        )
    except ValueError:
        return None
    dedupe_key = feedback_dedupe_key(request)
    feedback_id = feedback_id_for_dedupe_key(dedupe_key)
    if record["dedupe_key"] != dedupe_key or record["feedback_id"] != feedback_id:
        return None
    if status == "promoted" and not _valid_promotion(
        record.get("promotion"),
        feedback_id=feedback_id,
        outcome=request.outcome,
        submitted_at=submitted_at,
        checked_at=checked_at,
    ):
        return None
    return dict(record)


def _ensure_store_directory() -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(_STORE_PATH.parent, 0o700)


@contextmanager
def _exclusive_store_lock() -> Iterator[None]:
    _ensure_store_directory()
    lock_path = _STORE_PATH.with_name(f".{_STORE_PATH.name}.lock")
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


def _read_records_locked() -> list[dict[str, object]]:
    if not _STORE_PATH.exists():
        return []
    records: list[dict[str, object]] = []
    with _STORE_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def _prune_records(
    records: list[dict[str, object]],
    now: datetime,
) -> list[dict[str, object]]:
    retained = [
        validated
        for record in records
        if (validated := validate_feedback_record(record, checked_at=now)) is not None
    ]
    if _MAX_RECORDS <= 0:
        return []
    return retained[-_MAX_RECORDS:]


def _write_records(records: list[dict[str, object]]) -> None:
    _ensure_store_directory()
    temporary = _STORE_PATH.with_name(f".{_STORE_PATH.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, _STORE_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def _submission_result(record: dict[str, object], status: str) -> dict[str, object]:
    return {
        "feedback_id": record["feedback_id"],
        "status": status,
        "retained_until": record["expires_at"],
    }


def record_feedback(
    request: FeedbackRequest,
    *,
    scanner_version: str,
    corpus_fingerprint: str,
    now: datetime | None = None,
) -> dict[str, object]:
    if not scanner_version or scanner_version.strip() != scanner_version:
        raise ValueError("scanner_version must be a non-empty trimmed string")
    try:
        scanner_version.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("scanner_version must contain valid unicode scalar text") from exc
    if _CORPUS_FINGERPRINT_RE.fullmatch(corpus_fingerprint) is None:
        raise ValueError("corpus_fingerprint must be canonical sha256")
    submitted_at = _normalized_time(now)
    dedupe_key = feedback_dedupe_key(request)
    feedback_id = feedback_id_for_dedupe_key(dedupe_key)

    with _exclusive_store_lock():
        records = _prune_records(_read_records_locked(), submitted_at)
        existing = next(
            (
                record
                for record in records
                if record.get("dedupe_key") == dedupe_key
                and record.get("status") in {"pending", "promoted"}
            ),
            None,
        )
        if existing is not None:
            _write_records(records)
            return _submission_result(existing, "duplicate")

        expires_at = submitted_at + timedelta(days=_RETENTION_DAYS)
        reproducer = request.redacted_reproducer
        record: dict[str, object] = {
            "schema_version": 1,
            "feedback_id": feedback_id,
            "dedupe_key": dedupe_key,
            "submitted_at": _timestamp(submitted_at),
            "expires_at": _timestamp(expires_at),
            "status": "pending",
            "outcome": request.outcome,
            "observed_verdict": request.observed_verdict,
            "threat_class": request.threat_class.value,
            "redacted_reproducer": reproducer,
            "reproducer_sha256": reproducer_sha256(reproducer),
            "consent_to_retain": request.consent_to_retain,
            "redaction_confirmed": request.redaction_confirmed,
            "scanner_version": scanner_version,
            "corpus_fingerprint": corpus_fingerprint,
        }
        records = _prune_records([*records, record], submitted_at)
        _write_records(records)
        return _submission_result(record, "pending")


def list_feedback(
    *,
    now: datetime | None = None,
    compact: bool = True,
) -> list[dict[str, object]]:
    checked_at = _normalized_time(now)
    with _exclusive_store_lock():
        records = _read_records_locked()
        retained = _prune_records(records, checked_at)
        if compact and retained != records:
            _write_records(retained)
    return [dict(record) for record in retained]


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


def _append_jsonl_entry(path: Path, entry: dict[str, object]) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("feedback promotion target must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_bytes() if path.exists() else b""
    separator = b"" if not original or original.endswith(b"\n") else b"\n"
    serialized = json.dumps(entry, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(original)
            handle.write(separator)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _promotion_entry(
    record: dict[str, object],
    *,
    destination: FeedbackDestination,
    category: ReasonCode,
    expected_verdict: ExpectedAttackVerdict | None,
) -> tuple[str, dict[str, object]]:
    case_id = f"feedback-{str(record['feedback_id'])[:16]}"
    payload = str(record["redacted_reproducer"])
    if record.get("outcome") == "false_positive":
        if expected_verdict is not None:
            raise ValueError("false-positive promotion must not set an attack verdict")
        dataset = f"{destination}-benign"
        if destination == "training":
            return dataset, {
                "id": case_id,
                "payload": payload,
                "expected_verdict": "ALLOW",
                "expected_classes": [],
                "note": "human-reviewed-opt-in-feedback",
            }
        return dataset, {
            "id": case_id,
            "payload": payload,
            "source": "human-reviewed-opt-in-feedback",
        }

    dataset = f"{destination}-attacks"
    if destination == "training":
        if expected_verdict not in {"SANITIZE", "BLOCK"}:
            raise ValueError(
                "training attack promotion requires expected_verdict SANITIZE or BLOCK"
            )
        return dataset, {
            "id": case_id,
            "category": category.value,
            "payload": payload,
            "expected_verdict": expected_verdict,
            "expected_classes": [category.value],
            "note": "human-reviewed-opt-in-feedback",
        }
    if expected_verdict is not None:
        raise ValueError("held-out promotion must not set an expected verdict")
    return dataset, {
        "id": case_id,
        "category": category.value,
        "payload": payload,
        "source": "human-reviewed-opt-in-feedback",
    }


def promote_feedback(
    feedback_id: str,
    *,
    destination: FeedbackDestination,
    category: ReasonCode,
    reviewer_approved: bool,
    expected_verdict: ExpectedAttackVerdict | None = None,
    reviewed_at: datetime | None = None,
    training_attacks_path: Path = _TRAINING_ATTACKS_PATH,
    training_benign_path: Path = _TRAINING_BENIGN_PATH,
    held_out_attacks_path: Path = _HELD_OUT_ATTACKS_PATH,
    held_out_benign_path: Path = _HELD_OUT_BENIGN_PATH,
) -> dict[str, object]:
    if reviewer_approved is not True:
        raise ValueError("explicit human reviewer approval is required")
    if _FEEDBACK_ID_RE.fullmatch(feedback_id) is None:
        raise ValueError("feedback_id must be 32 lowercase hex characters")
    if destination not in {"training", "held-out"}:
        raise ValueError("destination must be training or held-out")
    review_time = _normalized_time(reviewed_at)
    paths = {
        "training-attacks": training_attacks_path,
        "training-benign": training_benign_path,
        "held-out-attacks": held_out_attacks_path,
        "held-out-benign": held_out_benign_path,
    }

    with _exclusive_store_lock():
        records = _prune_records(_read_records_locked(), review_time)
        record = next(
            (item for item in records if item.get("feedback_id") == feedback_id),
            None,
        )
        if record is None:
            raise ValueError("pending feedback record was not found or has expired")
        existing_promotion = record.get("promotion")
        if record.get("status") == "promoted":
            if (
                isinstance(existing_promotion, dict)
                and existing_promotion.get("destination") == destination
                and existing_promotion.get("category") == category.value
                and existing_promotion.get("expected_verdict") == expected_verdict
            ):
                return dict(existing_promotion)
            raise ValueError("feedback was already promoted to another destination")
        if record.get("status") != "pending":
            raise ValueError("feedback record is not pending review")
        if (
            record.get("consent_to_retain") is not True
            or record.get("redaction_confirmed") is not True
            or not isinstance(record.get("redacted_reproducer"), str)
            or not str(record["redacted_reproducer"]).strip()
        ):
            raise ValueError("feedback lacks consented redacted review material")

        dataset, entry = _promotion_entry(
            record,
            destination=destination,
            category=category,
            expected_verdict=expected_verdict,
        )
        target_path = paths[dataset]
        with exclusive_dataset_lock(held_out_attacks_path):
            entries_by_dataset = {name: _load_jsonl(path) for name, path in paths.items()}
            normalized = canonical_dataset_payload(entry["payload"])

            from warden.scanner.patterns import KNOWN_INJECTIONS

            if normalized in {canonical_dataset_payload(payload) for payload in KNOWN_INJECTIONS}:
                raise ValueError(
                    "reviewed reproducer overlaps existing training or held-out material"
                )

            existing_target: dict[str, object] | None = None
            for dataset_name, entries in entries_by_dataset.items():
                for existing in entries:
                    if existing.get("id") == entry["id"] and existing != entry:
                        raise ValueError(
                            "feedback case ID conflicts with an existing dataset entry"
                        )
                    if canonical_dataset_payload(existing.get("payload")) != normalized:
                        continue
                    if dataset_name == dataset and existing == entry:
                        existing_target = existing
                        continue
                    raise ValueError(
                        "reviewed reproducer overlaps existing training or held-out material"
                    )

            if existing_target is None:
                _append_jsonl_entry(target_path, entry)

        promotion: dict[str, object] = {
            "destination": destination,
            "dataset": dataset,
            "case_id": entry["id"],
            "category": category.value,
            "expected_verdict": expected_verdict,
            "reviewed_at": _timestamp(review_time),
        }
        record["status"] = "promoted"
        record["promotion"] = promotion
        _write_records(records)
        return dict(promotion)
