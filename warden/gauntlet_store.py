"""Persistent queue for public Gauntlet attempts and candidate bypasses."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from uuid import uuid4

from warden.models import ClaimStatus, GauntletRequest, ScanResponse


_STORE_PATH = Path(__file__).resolve().parents[1] / "gauntlet" / "attempts.jsonl"
_LOCK = Lock()


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_records_locked() -> list[dict[str, object]]:
    if not _STORE_PATH.exists():
        return []
    with _STORE_PATH.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


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

    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
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

        serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with _STORE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
    return status, claim_id


def get_stats(corpus_size: int) -> dict[str, int]:
    with _LOCK:
        records = _read_records_locked()
    return {
        "attempts": len(records),
        "pending_claims": sum(record.get("status") == "pending" for record in records),
        "confirmed_bypasses": sum(record.get("status") == "confirmed" for record in records),
        "corpus_size": corpus_size,
    }
