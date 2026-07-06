"""Badge issuance and verification helpers for Warden audits."""

from __future__ import annotations

import hashlib
import hmac
import json
import os


def _badge_secret() -> str:
    return os.getenv("WARDEN_BADGE_SECRET", "warden-dev-key")


def _canonical_json(record: dict[str, object]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def issue_badge(
    target_host: str,
    score: float,
    grade: str,
    blocked: int,
    total: int,
    issued_at: str,
) -> dict[str, object]:
    """
    Issue a signed badge record for a completed audit.

    The audit id is stable for the same target host, score, and issued date.
    """
    short_hash_input = f"{target_host}|{issued_at}|{score}"
    audit_id = hashlib.sha256(short_hash_input.encode("utf-8")).hexdigest()[:16]

    payload = {
        "audit_id": audit_id,
        "target_host": target_host,
        "grade": grade,
        "score": score,
        "blocked": blocked,
        "total": total,
        "issued_at": issued_at,
    }
    canonical_payload = dict(payload)
    canonical_json = _canonical_json(canonical_payload)
    payload["signature"] = hmac.new(
        _badge_secret().encode("utf-8"), canonical_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return payload


def verify_badge(badge: dict[str, object]) -> bool:
    """
    Verify a badge record's integrity.
    """
    signature = badge.get("signature")
    if not isinstance(signature, str):
        return False

    expected = dict(badge)
    expected.pop("signature", None)
    canonical_json = _canonical_json(expected)
    expected_signature = hmac.new(
        _badge_secret().encode("utf-8"), canonical_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
