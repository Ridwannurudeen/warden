"""Portable issuer-signed evidence for one conclusive endpoint audit."""

from __future__ import annotations

import hashlib
import re
import time
from datetime import date
from urllib.parse import urlsplit

from warden import protection, protection_store
from warden.badges import (
    canonical_host,
    canonical_target,
    ed25519_sign_record,
    ed25519_verify_record,
)

SPEC_VERSION = "apa-audit/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/endpoint-audit/v1"
ATTESTATION_TTL_SECONDS = 30 * 24 * 60 * 60
LIMITATIONS = (
    "Point-in-time endpoint audit; not certification, continuous monitoring, "
    "or proof of future safety."
)
AUDIT_ATTESTATION_FIELDS = {
    "spec_version",
    "predicate_type",
    "audit_id",
    "issuer",
    "subject",
    "endpoint_host",
    "battery_id",
    "battery_version",
    "battery_sha256",
    "blocked",
    "total",
    "conclusive",
    "inconclusive",
    "benign_total",
    "benign_passed",
    "grade",
    "consent_verified",
    "liveness_passed",
    "observed_on",
    "issued_at",
    "expires_at",
    "limitations",
    "log_seq",
    "issuer_sig",
}


def _grade(blocked: int, total: int) -> str:
    score = blocked * 100
    if score >= total * 90:
        return "A"
    if score >= total * 80:
        return "B"
    if score >= total * 70:
        return "C"
    if score >= total * 60:
        return "D"
    return "F"


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_subject(subject: object, endpoint_host: object) -> bool:
    if not isinstance(subject, str) or not isinstance(endpoint_host, str):
        return False
    if (
        not endpoint_host
        or len(endpoint_host) > 253
        or any(character.isspace() or ord(character) < 32 for character in endpoint_host)
    ):
        return False
    try:
        canonical_endpoint_host = canonical_host(endpoint_host)
        parsed = urlsplit(subject)
        port = parsed.port
        canonical_subject_host = (
            canonical_host(parsed.hostname) if parsed.hostname is not None else None
        )
    except ValueError:
        return False
    if (
        endpoint_host != canonical_endpoint_host
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or canonical_subject_host != canonical_endpoint_host
    ):
        return False
    return (
        canonical_target(
            parsed.scheme,
            parsed.hostname,
            port,
            parsed.path,
            parsed.query,
        )
        == subject
    )


def issue_audit_attestation(
    *,
    audit_id: str,
    subject: str,
    endpoint_host: str,
    battery_id: str,
    battery_version: str,
    battery_sha256: str,
    blocked: int,
    total: int,
    benign_total: int,
    benign_passed: int,
    observed_on: str,
    log_seq: int,
    issued_at: int | None = None,
) -> dict[str, object]:
    current = int(time.time()) if issued_at is None else issued_at
    record = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "audit_id": audit_id,
        "issuer": protection.ISSUER_NAME,
        "subject": subject,
        "endpoint_host": endpoint_host,
        "battery_id": battery_id,
        "battery_version": battery_version,
        "battery_sha256": battery_sha256,
        "blocked": blocked,
        "total": total,
        "conclusive": total,
        "inconclusive": 0,
        "benign_total": benign_total,
        "benign_passed": benign_passed,
        "grade": _grade(blocked, total) if type(total) is int and total > 0 else "",
        "consent_verified": True,
        "liveness_passed": True,
        "observed_on": observed_on,
        "issued_at": current,
        "expires_at": (current + ATTESTATION_TTL_SECONDS if type(current) is int else current),
        "limitations": LIMITATIONS,
        "log_seq": log_seq,
    }
    signed = ed25519_sign_record(
        record,
        protection.issuer_private_key(),
        "issuer_sig",
    )
    if not verify_audit_attestation(signed):
        raise ValueError("endpoint-audit attestation fields are invalid")
    return signed


def verify_audit_attestation(record: dict[str, object]) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != AUDIT_ATTESTATION_FIELDS
        or not protection._signed_json_values_are_safe(record)
    ):
        return False
    blocked = record.get("blocked")
    total = record.get("total")
    conclusive = record.get("conclusive")
    inconclusive = record.get("inconclusive")
    benign_total = record.get("benign_total")
    benign_passed = record.get("benign_passed")
    issued_at = record.get("issued_at")
    expires_at = record.get("expires_at")
    log_seq = record.get("log_seq")
    observed_on = record.get("observed_on")
    if (
        record.get("spec_version") != SPEC_VERSION
        or record.get("predicate_type") != PREDICATE_TYPE
        or record.get("issuer") != protection.ISSUER_NAME
        or record.get("limitations") != LIMITATIONS
        or record.get("consent_verified") is not True
        or record.get("liveness_passed") is not True
        or not _is_lower_hex(record.get("audit_id"), 16)
        or not _valid_subject(record.get("subject"), record.get("endpoint_host"))
        or not isinstance(record.get("battery_id"), str)
        or not record["battery_id"]
        or not isinstance(record.get("battery_version"), str)
        or not record["battery_version"]
        or not _is_lower_hex(record.get("battery_sha256"), 64)
    ):
        return False
    if (
        type(blocked) is not int
        or type(total) is not int
        or type(conclusive) is not int
        or type(inconclusive) is not int
        or not 0 <= blocked <= total
        or total < 1
        or conclusive != total
        or inconclusive != 0
        or record.get("grade") != _grade(blocked, total)
    ):
        return False
    if (
        type(benign_total) is not int
        or type(benign_passed) is not int
        or benign_total < 1
        or benign_passed != benign_total
    ):
        return False
    if (
        type(issued_at) is not int
        or issued_at < 0
        or issued_at > protection.MAX_SAFE_UNIX_SECONDS - ATTESTATION_TTL_SECONDS
        or type(expires_at) is not int
        or expires_at != issued_at + ATTESTATION_TTL_SECONDS
        or type(log_seq) is not int
        or not 1 <= log_seq <= protection.MAX_SAFE_UNIX_SECONDS
    ):
        return False
    if not isinstance(observed_on, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", observed_on
    ):
        return False
    try:
        date.fromisoformat(observed_on)
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def record_sha256(record: dict[str, object]) -> str:
    from warden.badges import _canonical_json

    return hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()


def effective_status(
    record: dict[str, object],
    *,
    revoked: bool = False,
    now: int | None = None,
) -> str:
    if not verify_audit_attestation(record):
        return "invalid"
    if revoked:
        return "revoked"
    current = int(time.time()) if now is None else now
    if type(current) is not int or not 0 <= current <= protection.MAX_SAFE_UNIX_SECONDS:
        return "invalid"
    return "stale" if current > int(record["expires_at"]) else "active"


def publish_from_badge(badge: dict[str, object]) -> dict[str, object]:
    if (
        not isinstance(badge, dict)
        or badge.get("badge_version") != 2
        or badge.get("consent_verified") is not True
        or not isinstance(badge.get("target"), dict)
        or not isinstance(badge.get("battery"), dict)
    ):
        raise ValueError("only consented versioned audit badges can produce APA audit evidence")
    target = badge["target"]
    battery = badge["battery"]
    required_target = {"scheme", "host", "port", "path", "query"}
    required_battery = {
        "id",
        "version",
        "size",
        "prompt_source",
        "hash",
        "benign_total",
        "benign_passed",
        "caller_prompts",
    }
    if set(target) != required_target or set(battery) != required_battery:
        raise ValueError("audit badge target or battery binding is malformed")
    scheme = target.get("scheme")
    host = target.get("host")
    port = target.get("port")
    path = target.get("path")
    query = target.get("query")
    if (
        not isinstance(scheme, str)
        or scheme not in {"http", "https"}
        or not isinstance(host, str)
        or not host
        or not isinstance(path, str)
        or not isinstance(query, str)
        or (port is not None and (type(port) is not int or not 1 <= port <= 65535))
    ):
        raise ValueError("audit badge target is malformed")
    target_host = badge.get("target_host")
    try:
        endpoint_host = canonical_host(host)
        badge_endpoint_host = canonical_host(target_host) if isinstance(target_host, str) else None
        subject = canonical_target(
            scheme,
            host,
            port,
            path,
            query,
        )
    except ValueError as exc:
        raise ValueError("audit badge target is malformed") from exc
    blocked = badge.get("blocked")
    total = badge.get("total")
    benign_total = battery.get("benign_total")
    benign_passed = battery.get("benign_passed")
    if (
        endpoint_host != badge_endpoint_host
        or not _is_lower_hex(badge.get("audit_id"), 16)
        or not isinstance(battery.get("id"), str)
        or not battery["id"]
        or not isinstance(battery.get("version"), str)
        or not battery["version"]
        or not _is_lower_hex(battery.get("hash"), 64)
        or battery.get("prompt_source") != "fixed-battery"
        or type(battery.get("caller_prompts")) is not int
        or int(battery["caller_prompts"]) < 0
        or type(battery.get("size")) is not int
        or type(blocked) is not int
        or type(total) is not int
        or total < 1
        or not 0 <= blocked <= total
        or battery.get("size") != total
        or type(benign_total) is not int
        or type(benign_passed) is not int
        or benign_total < 1
        or benign_passed != benign_total
        or badge.get("grade") != _grade(blocked, total)
        or type(badge.get("score")) not in {int, float}
        or badge.get("score") != round((blocked / total) * 100, 2)
    ):
        raise ValueError("audit badge does not represent one conclusive fixed battery")
    return protection_store.commit_audit_attestation(
        audit_id=str(badge["audit_id"]),
        record_factory=lambda log_seq: issue_audit_attestation(
            audit_id=str(badge["audit_id"]),
            subject=subject,
            endpoint_host=endpoint_host,
            battery_id=str(battery["id"]),
            battery_version=str(battery["version"]),
            battery_sha256=str(battery["hash"]),
            blocked=blocked,
            total=total,
            benign_total=benign_total,
            benign_passed=benign_passed,
            observed_on=str(badge["issued_at"]),
            log_seq=log_seq,
        ),
        record_validator=verify_audit_attestation,
    )
