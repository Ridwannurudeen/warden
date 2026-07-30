"""Signed, payload-free evidence for one OKX task safety decision."""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping

from pydantic import ValidationError

from warden import protection
from warden.badges import _canonical_json, ed25519_sign_record, ed25519_verify_record
from warden.models import (
    TaskSafetyOutcome,
    TaskSafetyReceiptRecord,
    TaskSafetyReceiptStatus,
    VerdictLabel,
)

SPEC_VERSION = "warden-task-safety-receipt/1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/task-safety-receipt/v1"
PROVIDER = "okx"
RECEIPT_TTL_SECONDS = 30 * 24 * 60 * 60
LIMITATIONS = (
    "Hash-only record of one Warden task safety decision and result; not proof of "
    "execution, delivery, settlement, or authorization, and not certification or "
    "proof of future safety."
)
RECEIPT_FIELDS = frozenset(TaskSafetyReceiptRecord.model_fields)


def _json_value_is_safe(value: object) -> bool:
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return -protection.MAX_SAFE_UNIX_SECONDS <= value <= protection.MAX_SAFE_UNIX_SECONDS
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError:
            return False
        return True
    if isinstance(value, list):
        return all(_json_value_is_safe(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str)
            and _json_value_is_safe(key)
            and _json_value_is_safe(item)
            for key, item in value.items()
        )
    return False


def canonical_sha256(value: Mapping[str, object]) -> str:
    """Hash finite JSON metadata without retaining its potentially private values."""
    if not isinstance(value, Mapping):
        raise ValueError("value must be finite canonical JSON metadata")
    material = dict(value)
    if not _json_value_is_safe(material):
        raise ValueError("value must be finite canonical JSON metadata")
    try:
        canonical = _canonical_json(material)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("value must be finite canonical JSON metadata") from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _receipt_id(record: Mapping[str, object]) -> str:
    core = {
        key: value
        for key, value in record.items()
        if key not in {"receipt_id", "issuer_sig"}
    }
    return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()


def _task_id_sha256(task_id: str) -> str:
    if (
        not isinstance(task_id, str)
        or not task_id
        or task_id != task_id.strip()
        or len(task_id) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in task_id)
    ):
        raise ValueError("task_id must be a non-empty trimmed identifier")
    try:
        encoded = task_id.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("task_id must contain valid Unicode scalar text") from exc
    return hashlib.sha256(encoded).hexdigest()


def issue_task_safety_receipt(
    *,
    task_id: str,
    agent_id: str,
    service_id: str,
    service_revision_sha256: str,
    request_sha256: str,
    result_sha256: str,
    decision_sha256: str,
    verdict: VerdictLabel,
    outcome: TaskSafetyOutcome,
    issued_at: int | None = None,
) -> dict[str, object]:
    """Issue one task-bound receipt containing hashes and public identifiers only."""
    current = int(time.time()) if issued_at is None else issued_at
    if type(current) is not int or not (
        0 <= current <= protection.MAX_SAFE_UNIX_SECONDS - RECEIPT_TTL_SECONDS
    ):
        raise ValueError("receipt issued_at must be safe Unix seconds")
    expected_outcomes = {
        "ALLOW": "result-produced",
        "SANITIZE": "result-sanitized",
        "BLOCK": "result-withheld",
    }
    if expected_outcomes.get(verdict) != outcome:
        raise ValueError("outcome must match the safety verdict")
    record: dict[str, object] = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "issuer": protection.ISSUER_NAME,
        "provider": PROVIDER,
        "agent_id": agent_id,
        "service_id": service_id,
        "service_revision_sha256": service_revision_sha256,
        "task_id_sha256": _task_id_sha256(task_id),
        "request_sha256": request_sha256,
        "result_sha256": result_sha256,
        "decision_sha256": decision_sha256,
        "verdict": verdict,
        "outcome": outcome,
        "issued_at": current,
        "expires_at": current + RECEIPT_TTL_SECONDS,
        "limitations": LIMITATIONS,
    }
    try:
        TaskSafetyReceiptRecord.model_validate(
            {**record, "receipt_id": "0" * 64, "issuer_sig": "sig:placeholder"},
            strict=True,
        )
    except ValidationError as exc:
        raise ValueError("task safety receipt fields are invalid") from exc
    record["receipt_id"] = _receipt_id(record)
    signed = ed25519_sign_record(
        record,
        protection.issuer_private_key(),
        "issuer_sig",
    )
    if not verify_task_safety_receipt(signed):
        raise ValueError("task safety receipt fields are invalid")
    return json.loads(_canonical_json(signed))


def verify_task_safety_receipt(record: dict[str, object]) -> bool:
    """Verify the strict schema, derived ID, fixed lifetime, and issuer signature."""
    if (
        not isinstance(record, dict)
        or set(record) != RECEIPT_FIELDS
        or not protection._signed_json_values_are_safe(record)
    ):
        return False
    try:
        receipt = TaskSafetyReceiptRecord.model_validate(record, strict=True)
    except ValidationError:
        return False
    serialized = receipt.model_dump()
    if (
        serialized != record
        or receipt.spec_version != SPEC_VERSION
        or receipt.predicate_type != PREDICATE_TYPE
        or receipt.issuer != protection.ISSUER_NAME
        or receipt.provider != PROVIDER
        or receipt.limitations != LIMITATIONS
        or receipt.expires_at != receipt.issued_at + RECEIPT_TTL_SECONDS
        or receipt.receipt_id != _receipt_id(serialized)
    ):
        return False
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        receipt.issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def effective_status(
    record: dict[str, object],
    *,
    revoked: bool = False,
    now: int | None = None,
) -> TaskSafetyReceiptStatus:
    """Return active, stale, revoked, or invalid from the current lifecycle facts."""
    if not verify_task_safety_receipt(record) or type(revoked) is not bool:
        return "invalid"
    current = int(time.time()) if now is None else now
    if type(current) is not int or not 0 <= current <= protection.MAX_SAFE_UNIX_SECONDS:
        return "invalid"
    if revoked:
        return "revoked"
    return "stale" if current > int(record["expires_at"]) else "active"
