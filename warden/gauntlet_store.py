"""Persistent queue for public Gauntlet attempts and candidate bypasses."""

from __future__ import annotations

import asyncio
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

from warden import protection, protection_store
from warden.core.verdict import ReasonCode
from warden.engine import WardenEngine
from warden.models import (
    ClaimStatus,
    GauntletRequest,
    ScanResponse,
    finder_handle_is_visible,
    normalize_finder_handle,
)


_STORE_PATH = Path(__file__).resolve().parents[1] / "gauntlet" / "attempts.jsonl"
_LOCK = Lock()
# Cap on-disk growth from the unauthenticated public demo route.
_MAX_RECORDS = 5000
_MAX_PENDING_RECORDS = 500
_DEFAULT_BENCHMARK_PATH = Path(__file__).resolve().parents[1] / "benchmark" / "held_out_attacks.jsonl"
_DEFAULT_BENIGN_BENCHMARK_PATH = (
    Path(__file__).resolve().parents[1] / "benchmark" / "held_out_benign.jsonl"
)
_CLAIM_ID_RE = re.compile(r"[0-9a-f]{64}")
_CERTIFICATE_ID_RE = re.compile(r"[0-9a-f]{32}")
_MAX_CONFIRMATION_CLOCK_SKEW_SECONDS = 300


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
                record = json.loads(line)
            except json.JSONDecodeError:
                # A single truncated/corrupt line (e.g. a crash mid-append) must not
                # break every subsequent read of the store.
                continue
            if isinstance(record, dict):
                records.append(record)
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


def _credit_hash(request: GauntletRequest) -> str:
    canonical = json.dumps(
        {
            "finder": request.finder,
            "public_credit_consent": request.public_credit_consent,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
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
                record["credit_hash"] = _credit_hash(request)
                record["public_credit_consent"] = request.public_credit_consent
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


def get_confirmed_breaker_ids(limit: int = 50) -> list[str]:
    if not 1 <= limit <= 50:
        raise ValueError("breaker certificate limit must be between 1 and 50")
    with _exclusive_store_lock():
        records = _read_records_locked()
    confirmed = [
        record
        for record in records
        if record.get("status") == "confirmed"
        and isinstance(record.get("certificate_id"), str)
        and _CERTIFICATE_ID_RE.fullmatch(str(record["certificate_id"]))
        and type(record.get("log_seq")) is int
        and int(record["log_seq"]) > 0
    ]
    confirmed.sort(key=lambda record: int(record["log_seq"]), reverse=True)
    return [str(record["certificate_id"]) for record in confirmed[:limit]]


def is_confirmed_breaker(certificate_id: str) -> bool:
    if _CERTIFICATE_ID_RE.fullmatch(certificate_id) is None:
        return False
    with _exclusive_store_lock():
        records = _read_records_locked()
    return any(
        record.get("status") == "confirmed"
        and record.get("certificate_id") == certificate_id
        for record in records
    )


def _parse_confirmed_at(value: str) -> tuple[str, int]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("confirmed_at must be an exact UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond or not value.endswith("Z"):
        raise ValueError("confirmed_at must be an exact UTC timestamp")
    timestamp = int(parsed.timestamp())
    if not 0 <= timestamp <= protection.MAX_SAFE_UNIX_SECONDS:
        raise ValueError("confirmed_at must be a non-negative safe Unix timestamp")
    if (
        timestamp
        > int(datetime.now(timezone.utc).timestamp())
        + _MAX_CONFIRMATION_CLOCK_SKEW_SECONDS
    ):
        raise ValueError("confirmed_at must not be in the future")
    return value, timestamp


def _timestamp_from_unix(value: int) -> str:
    return (
        datetime.fromtimestamp(value, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    entries: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError(f"{path} must contain only JSON objects")
            entries.append(entry)
    return entries


def _append_benchmark_case(path: Path, case: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_bytes() if path.exists() else b""
    separator = b"" if not original or original.endswith(b"\n") else b"\n"
    serialized = (
        json.dumps(case, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    )
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


def _write_records(records: list[dict[str, object]]) -> None:
    temporary = _STORE_PATH.with_name(f".{_STORE_PATH.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, _STORE_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def _validated_pending_request(
    claim: dict[str, object],
    claim_id: str,
) -> GauntletRequest:
    try:
        request = GauntletRequest.model_validate(
            {
                "intent": claim["intent"],
                "payload": claim["payload"],
                "context": claim["context"],
                "finder": claim.get("finder"),
                "public_credit_consent": claim.get("public_credit_consent", False),
            }
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("pending Gauntlet claim is incomplete or invalid") from exc
    if (
        _claim_id(request) != claim_id
        or claim.get("payload_hash")
        != hashlib.sha256(request.payload.encode("utf-8")).hexdigest()
        or claim.get("intent_hash")
        != hashlib.sha256(request.intent.encode("utf-8")).hexdigest()
        or claim.get("credit_hash") != _credit_hash(request)
    ):
        raise ValueError("pending Gauntlet claim failed its stored digest checks")
    return request


def _certificate_matches_review(
    certificate: dict[str, object],
    *,
    certificate_id: str,
    case: dict[str, object],
    category: ReasonCode,
    payload_sha256: str,
    finder: str | None,
) -> bool:
    return (
        protection.verify_breaker_certificate(certificate)
        and certificate.get("certificate_id") == certificate_id
        and certificate.get("benchmark_case_id") == case["id"]
        and certificate.get("threat_class") == category.value
        and certificate.get("payload_sha256") == payload_sha256
        and certificate.get("finder") == finder
    )


def confirm_bypass(
    claim_id: str,
    category: ReasonCode,
    *,
    reviewed_payload: str,
    finder: str | None,
    reviewer_approved: bool,
    reviewed_context: dict[str, object] | None = None,
    benchmark_path: Path = _DEFAULT_BENCHMARK_PATH,
    benign_benchmark_path: Path = _DEFAULT_BENIGN_BENCHMARK_PATH,
    confirmed_at: str | None = None,
) -> dict[str, object]:
    """Promote one reviewed reproducer and issue its signed BREAKER certificate."""
    if reviewer_approved is not True:
        raise ValueError("explicit human reviewer approval is required")
    if _CLAIM_ID_RE.fullmatch(claim_id) is None:
        raise ValueError("claim_id must be 64 lowercase hex characters")
    if not isinstance(reviewed_payload, str) or not reviewed_payload.strip():
        raise ValueError("reviewed_payload must not be blank")
    if len(reviewed_payload) > 4_000:
        raise ValueError("reviewed_payload must not exceed 4000 characters")
    raw_finder = finder
    finder = normalize_finder_handle(raw_finder)
    if finder is None and raw_finder is not None and raw_finder.strip(" \t\r\n"):
        raise ValueError("finder must contain only visible characters")
    if finder is not None and (
        len(finder) > 128
        or not finder_handle_is_visible(finder)
        or any(ord(character) < 32 or ord(character) == 127 for character in finder)
    ):
        raise ValueError("finder must be a printable handle of at most 128 characters")
    requested_at, requested_at_unix = _parse_confirmed_at(
        confirmed_at or _timestamp()
    )

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
        submitted_request = _validated_pending_request(claim, claim_id)
        if finder is not None and (
            not submitted_request.public_credit_consent
            or submitted_request.finder != finder
        ):
            raise ValueError(
                "public finder consent must match the submitted finder handle"
            )

        case_id = f"gauntlet-{claim_id[:16]}"
        case: dict[str, object] = {
            "id": case_id,
            "category": category.value,
            "payload": reviewed_payload,
            "source": "human-reviewed-gauntlet",
        }
        reviewed_request = GauntletRequest(
            intent=str(claim["intent"]),
            payload=reviewed_payload,
            context=reviewed_context or {},
        )
        reviewed_scan_context = reviewed_request.context.model_dump(mode="json")
        if reviewed_scan_context.get("expected_addresses"):
            case["context"] = {
                "expected_addresses": reviewed_scan_context["expected_addresses"]
            }

        if benchmark_path.exists() and benchmark_path.is_symlink():
            raise ValueError("held-out benchmark path must not be a symlink")
        benchmark_cases = _load_jsonl(benchmark_path)
        existing = next(
            (entry for entry in benchmark_cases if entry.get("id") == case_id),
            None,
        )
        if existing is not None and existing != case:
            raise ValueError("held-out benchmark case id conflicts with reviewed claim")

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

        benign_cases = _load_jsonl(benign_benchmark_path)
        if any(
            " ".join(str(entry.get("payload", "")).casefold().split()) == normalized
            for entry in benign_cases
        ):
            raise ValueError("reviewed claim overlaps the held-out benign benchmark")

        payload_sha256 = hashlib.sha256(reviewed_payload.encode("utf-8")).hexdigest()
        certificate_id = hashlib.sha256(
            f"warden-breaker:{claim_id}".encode("utf-8")
        ).hexdigest()[:32]
        certificate = protection_store.get_breaker_certificate(certificate_id)

        if claim.get("status") == "confirmed":
            if (
                existing is None
                or claim.get("benchmark_case_id") != case_id
                or claim.get("certificate_id") != certificate_id
                or certificate is None
                or not _certificate_matches_review(
                    certificate,
                    certificate_id=certificate_id,
                    case=case,
                    category=category,
                    payload_sha256=payload_sha256,
                    finder=finder,
                )
            ):
                raise ValueError("confirmed Gauntlet claim is missing its signed evidence")
            return {"held_out_case": case, "certificate": certificate}

        if certificate is None:
            verdict = asyncio.run(
                WardenEngine().scan(
                    reviewed_payload,
                    depth="fast",
                    context=reviewed_scan_context,
                )
            )
            if verdict.verdict != "ALLOW":
                raise ValueError(
                    "reviewed reproducer is now detected by the current scanner "
                    "and is no longer a confirmable bypass"
                )

        if existing is None:
            _append_benchmark_case(benchmark_path, case)

        certificate = protection_store.commit_breaker_certificate(
            claim_id=claim_id,
            record_factory=lambda log_seq: protection.issue_breaker_certificate(
                certificate_id=certificate_id,
                benchmark_case_id=case_id,
                threat_class=category,
                payload_sha256=payload_sha256,
                finder=finder,
                confirmed_at=requested_at_unix,
                log_seq=log_seq,
            ),
            record_validator=protection.verify_breaker_certificate,
        )
        if not _certificate_matches_review(
            certificate,
            certificate_id=certificate_id,
            case=case,
            category=category,
            payload_sha256=payload_sha256,
            finder=finder,
        ):
            raise ValueError("stored breaker certificate conflicts with reviewed claim")

        claim["status"] = "confirmed"
        certificate_confirmed_at = certificate["confirmed_at"]
        if type(certificate_confirmed_at) is not int:
            raise ValueError("stored breaker certificate has an invalid timestamp")
        claim["confirmed_at"] = (
            requested_at
            if certificate_confirmed_at == requested_at_unix
            else _timestamp_from_unix(certificate_confirmed_at)
        )
        claim["benchmark_case_id"] = case_id
        claim["certificate_id"] = certificate_id
        claim["log_seq"] = certificate["log_seq"]
        _write_records(records)
        return {"held_out_case": case, "certificate": certificate}
