"""Owner-enrolled recurring endpoint audits with signed evidence lineage."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from warden import audit_attestations, badge_store, protection_store
from warden.auditor import AgentAuditor
from warden.badges import canonical_target, verify_badge

SCHEMA_VERSION = 1
MAX_TARGETS = 32
MAX_EVENTS = 1_000
MAX_CONFIG_BYTES = 128_000
MAX_STATE_BYTES = 2_000_000
MIN_INTERVAL_HOURS = 24
RENEWAL_SAFETY_MARGIN_SECONDS = 2 * 24 * 60 * 60
MAX_INTERVAL_HOURS = (
    audit_attestations.ATTESTATION_TTL_SECONDS - RENEWAL_SAFETY_MARGIN_SECONDS
) // (60 * 60)
INCONCLUSIVE_RETRY_SECONDS = 24 * 60 * 60
_STATE_LOCK = Lock()

_TARGET_FIELDS = {
    "target_id",
    "owner_id",
    "owner_enrolled",
    "enrollment_revision",
    "target_url",
    "interval_hours",
    "battery",
}
_BATTERY_FIELDS = {"id", "version", "sha256"}
_STATE_FIELDS = {"schema_version", "targets", "events"}
_TARGET_STATE_FIELDS = {
    "target_id",
    "enrollment_revision",
    "enrollment_sha256",
    "next_due_at",
    "last_attempt_at",
    "last_conclusive_at",
    "comparison",
    "reason",
    "baseline",
}
_BASELINE_FIELDS = {
    "audit_id",
    "battery_id",
    "battery_version",
    "battery_sha256",
    "blocked",
    "total",
    "score",
    "observed_on",
    "issued_at",
    "expires_at",
}
_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "target_id",
    "comparison",
    "reason",
    "occurred_at",
    "previous_evidence",
    "observed_evidence",
    "action",
    "notification",
}
_COMPARISONS = {"initial", "unchanged", "improved", "regressed", "inconclusive"}
_NOTIFICATION_STATES = {
    "not_applicable",
    "not_configured",
    "pending",
    "delivered",
    "failed",
}


class Auditor(Protocol):
    async def audit(self, target_url: str) -> object: ...


class ShieldNotifier(Protocol):
    async def notify(self, event: Mapping[str, object]) -> None: ...


@dataclass(frozen=True)
class ShieldTarget:
    target_id: str
    owner_id: str
    enrollment_revision: int
    target_url: str
    interval_hours: int
    battery_id: str
    battery_version: str
    battery_sha256: str
    enrollment_sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("Shield JSON contains duplicate object keys")
        parsed[key] = value
    return parsed


def _reject_non_finite_number(_value: str) -> object:
    raise ValueError("Shield JSON contains a non-finite number")


def _load_strict_json(raw: bytes) -> object:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Shield file must contain valid UTF-8 JSON") from exc


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_existing_file(path: Path, *, label: str, max_bytes: int) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label} must be a regular file")
    if candidate.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds its size limit")
    return candidate


def _canonical_enrolled_url(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ValueError("Shield target_url must be a bounded canonical HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        subject = canonical_target(
            parsed.scheme,
            parsed.hostname or "",
            port,
            parsed.path,
            parsed.query,
        )
    except ValueError as exc:
        raise ValueError("Shield target_url must be a bounded canonical HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or subject != value
    ):
        raise ValueError(
            "Shield target_url must be canonical HTTPS without credentials, query, or fragment"
        )
    return subject


def _bounded_identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or value.strip() != value
        or not value[0].isalnum()
        or any(
            not character.isascii() or not (character.isalnum() or character in {"-", "_"})
            for character in value
        )
    ):
        raise ValueError(f"{label} must be a 1-64 character identifier")
    return value


def _battery(value: object) -> tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != _BATTERY_FIELDS:
        raise ValueError("Shield battery binding is malformed")
    battery_id = _bounded_identifier(value.get("id"), label="battery id")
    version = value.get("version")
    sha256 = value.get("sha256")
    if (
        not isinstance(version, str)
        or not 1 <= len(version) <= 64
        or version.strip() != version
        or any(
            not character.isascii() or not (character.isalnum() or character in {"-", "_", "."})
            for character in version
        )
        or not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise ValueError("Shield battery binding is malformed")
    return battery_id, version, sha256


def load_shield_config(path: Path) -> tuple[ShieldTarget, ...]:
    """Load strict, explicitly owner-enrolled recurring audit targets."""
    config_path = _safe_existing_file(path, label="Shield config", max_bytes=MAX_CONFIG_BYTES)
    document = _load_strict_json(config_path.read_bytes())
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "targets"}
        or document.get("schema_version") != SCHEMA_VERSION
        or not isinstance(document.get("targets"), list)
        or not 0 <= len(document["targets"]) <= MAX_TARGETS
    ):
        raise ValueError("Shield config is malformed or has an invalid target count")

    targets: list[ShieldTarget] = []
    target_ids: set[str] = set()
    target_urls: set[str] = set()
    for raw_target in document["targets"]:
        if not isinstance(raw_target, dict) or set(raw_target) != _TARGET_FIELDS:
            raise ValueError("Shield target enrollment is malformed")
        if raw_target.get("owner_enrolled") is not True:
            raise ValueError("Shield target requires explicit owner enrollment")
        target_id = _bounded_identifier(raw_target.get("target_id"), label="target_id")
        owner_id = _bounded_identifier(raw_target.get("owner_id"), label="owner_id")
        revision = raw_target.get("enrollment_revision")
        interval_hours = raw_target.get("interval_hours")
        if type(revision) is not int or not 1 <= revision <= 2_147_483_647:
            raise ValueError("Shield enrollment_revision must be a positive integer")
        if (
            type(interval_hours) is not int
            or not MIN_INTERVAL_HOURS <= interval_hours <= MAX_INTERVAL_HOURS
        ):
            raise ValueError(
                f"Shield interval_hours must be between {MIN_INTERVAL_HOURS} "
                f"and {MAX_INTERVAL_HOURS}"
            )
        target_url = _canonical_enrolled_url(raw_target.get("target_url"))
        battery_id, battery_version, battery_sha256 = _battery(raw_target.get("battery"))
        if target_id in target_ids or target_url in target_urls:
            raise ValueError("Shield target IDs and URLs must be unique")
        target_ids.add(target_id)
        target_urls.add(target_url)
        enrollment = {
            "target_id": target_id,
            "owner_id": owner_id,
            "owner_enrolled": True,
            "enrollment_revision": revision,
            "target_url": target_url,
            "interval_hours": interval_hours,
            "battery": {
                "id": battery_id,
                "version": battery_version,
                "sha256": battery_sha256,
            },
        }
        targets.append(
            ShieldTarget(
                target_id=target_id,
                owner_id=owner_id,
                enrollment_revision=revision,
                target_url=target_url,
                interval_hours=interval_hours,
                battery_id=battery_id,
                battery_version=battery_version,
                battery_sha256=battery_sha256,
                enrollment_sha256=hashlib.sha256(_canonical_json(enrollment)).hexdigest(),
            )
        )
    return tuple(sorted(targets, key=lambda target: target.target_id))


@contextmanager
def _exclusive_state_lock(state_path: Path) -> Iterator[None]:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_name(f".{state_path.name}.lock")
    if lock_path.is_symlink():
        raise ValueError("Shield state lock must not be a symbolic link")
    with _STATE_LOCK, lock_path.open("a+b") as handle:
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


def _empty_state() -> dict[str, object]:
    return {"schema_version": SCHEMA_VERSION, "targets": {}, "events": []}


def _valid_baseline(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _BASELINE_FIELDS:
        return False
    return (
        isinstance(value.get("audit_id"), str)
        and len(value["audit_id"]) == 16
        and all(character in "0123456789abcdef" for character in value["audit_id"])
        and isinstance(value.get("battery_id"), str)
        and bool(value["battery_id"])
        and isinstance(value.get("battery_version"), str)
        and bool(value["battery_version"])
        and isinstance(value.get("battery_sha256"), str)
        and len(value["battery_sha256"]) == 64
        and all(character in "0123456789abcdef" for character in value["battery_sha256"])
        and type(value.get("blocked")) is int
        and type(value.get("total")) is int
        and 0 <= value["blocked"] <= value["total"]
        and value["total"] >= 1
        and type(value.get("score")) in {int, float}
        and value["score"] == round((value["blocked"] / value["total"]) * 100, 2)
        and isinstance(value.get("observed_on"), str)
        and type(value.get("issued_at")) is int
        and type(value.get("expires_at")) is int
        and value["issued_at"] >= 0
        and value["expires_at"] > value["issued_at"]
    )


def _valid_event(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _EVENT_FIELDS:
        return False
    return (
        value.get("schema_version") == SCHEMA_VERSION
        and isinstance(value.get("event_id"), str)
        and len(value["event_id"]) == 32
        and all(character in "0123456789abcdef" for character in value["event_id"])
        and isinstance(value.get("target_id"), str)
        and 1 <= len(value["target_id"]) <= 64
        and value.get("comparison") in _COMPARISONS
        and isinstance(value.get("reason"), str)
        and 1 <= len(value["reason"]) <= 64
        and type(value.get("occurred_at")) is int
        and value["occurred_at"] >= 0
        and (value.get("previous_evidence") is None or _valid_baseline(value["previous_evidence"]))
        and (value.get("observed_evidence") is None or _valid_baseline(value["observed_evidence"]))
        and isinstance(value.get("action"), str)
        and 1 <= len(value["action"]) <= 256
        and value.get("notification") in _NOTIFICATION_STATES
    )


def _validate_state(document: object) -> dict[str, object]:
    if (
        not isinstance(document, dict)
        or set(document) != _STATE_FIELDS
        or document.get("schema_version") != SCHEMA_VERSION
        or not isinstance(document.get("targets"), dict)
        or not isinstance(document.get("events"), list)
        or len(document["targets"]) > MAX_TARGETS
        or len(document["events"]) > MAX_EVENTS
        or not all(_valid_event(event) for event in document["events"])
    ):
        raise ValueError("Shield lifecycle state is malformed")
    for target_id, target_state in document["targets"].items():
        if (
            not isinstance(target_id, str)
            or not isinstance(target_state, dict)
            or set(target_state) != _TARGET_STATE_FIELDS
            or target_state.get("target_id") != target_id
            or type(target_state.get("enrollment_revision")) is not int
            or target_state["enrollment_revision"] < 1
            or not isinstance(target_state.get("enrollment_sha256"), str)
            or len(target_state["enrollment_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in target_state["enrollment_sha256"]
            )
            or type(target_state.get("next_due_at")) is not int
            or target_state["next_due_at"] < 0
            or (
                target_state.get("last_attempt_at") is not None
                and (
                    type(target_state["last_attempt_at"]) is not int
                    or target_state["last_attempt_at"] < 0
                )
            )
            or (
                target_state.get("last_conclusive_at") is not None
                and (
                    type(target_state["last_conclusive_at"]) is not int
                    or target_state["last_conclusive_at"] < 0
                )
            )
            or target_state.get("comparison") not in _COMPARISONS
            or not isinstance(target_state.get("reason"), str)
            or not 1 <= len(target_state["reason"]) <= 64
            or (
                target_state.get("baseline") is not None
                and not _valid_baseline(target_state["baseline"])
            )
        ):
            raise ValueError("Shield lifecycle state is malformed")
    return document


def _read_state(path: Path) -> dict[str, object]:
    if not path.exists():
        return _empty_state()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("Shield lifecycle state is not a bounded regular file")
    return _validate_state(_load_strict_json(path.read_bytes()))


def _write_state(path: Path, document: dict[str, object]) -> None:
    _validate_state(document)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Shield lifecycle state must be a regular file")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8"))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _audit_id(response: object) -> str | None:
    if getattr(response, "grade", None) == "INCONCLUSIVE":
        return None
    badge = getattr(response, "badge_record", None)
    audit_id = (
        badge.get("audit_id") if isinstance(badge, dict) else getattr(badge, "audit_id", None)
    )
    if (
        not isinstance(audit_id, str)
        or len(audit_id) != 16
        or any(character not in "0123456789abcdef" for character in audit_id)
    ):
        return None
    return audit_id


def _resolve_published_evidence(audit_id: str) -> dict[str, object]:
    badge = badge_store.get_badge(audit_id)
    if not isinstance(badge, dict) or badge.get("badge_version") != 2 or not verify_badge(badge):
        raise ValueError("Shield audit has no valid versioned badge")
    portable = audit_attestations.publish_from_badge(badge)
    evidence = protection_store.get_audit_attestation_with_evidence(
        audit_id,
        record_validator=audit_attestations.verify_audit_attestation,
    )
    if (
        not isinstance(evidence, dict)
        or evidence.get("attestation") != portable
        or evidence.get("status") not in {"active", "revoked"}
    ):
        raise ValueError("Shield audit has no intact portable evidence")
    return evidence


def _baseline_from_evidence(
    evidence: object,
    *,
    target: ShieldTarget,
    audit_id: str,
    now: int,
) -> tuple[dict[str, object] | None, str | None]:
    if not isinstance(evidence, dict):
        return None, "evidence_unavailable"
    record = evidence.get("attestation")
    if not isinstance(record, dict) or not audit_attestations.verify_audit_attestation(record):
        return None, "evidence_invalid"
    if evidence.get("status") != "active":
        return None, "evidence_revoked"
    if audit_attestations.effective_status(record, now=now) != "active":
        return None, "evidence_stale"
    if record.get("audit_id") != audit_id or record.get("subject") != target.target_url:
        return None, "evidence_subject_mismatch"
    baseline = {
        "audit_id": audit_id,
        "battery_id": record.get("battery_id"),
        "battery_version": record.get("battery_version"),
        "battery_sha256": record.get("battery_sha256"),
        "blocked": record.get("blocked"),
        "total": record.get("total"),
        "score": round((int(record["blocked"]) / int(record["total"])) * 100, 2),
        "observed_on": record.get("observed_on"),
        "issued_at": record.get("issued_at"),
        "expires_at": record.get("expires_at"),
    }
    if not _valid_baseline(baseline):
        return None, "evidence_invalid"
    expected_battery = (
        target.battery_id,
        target.battery_version,
        target.battery_sha256,
    )
    observed_battery = (
        baseline["battery_id"],
        baseline["battery_version"],
        baseline["battery_sha256"],
    )
    if observed_battery != expected_battery:
        return baseline, "battery_changed"
    return baseline, None


def _comparison(
    previous: dict[str, object] | None,
    observed: dict[str, object],
) -> tuple[str, str]:
    if previous is None:
        return "initial", "first_conclusive_audit"
    previous_battery = (
        previous["battery_id"],
        previous["battery_version"],
        previous["battery_sha256"],
    )
    observed_battery = (
        observed["battery_id"],
        observed["battery_version"],
        observed["battery_sha256"],
    )
    if previous_battery != observed_battery:
        return "inconclusive", "battery_changed"
    if observed["score"] == previous["score"]:
        return "unchanged", "same_battery_same_score"
    if float(observed["score"]) > float(previous["score"]):
        return "improved", "same_battery_score_increased"
    return "regressed", "same_battery_score_decreased"


def _action(comparison: str, reason: str) -> str:
    if comparison == "initial":
        return "Review the first signed audit as this enrollment's baseline."
    if comparison == "unchanged":
        return "No drift action is required; inspect the renewed signed audit if needed."
    if comparison == "improved":
        return "Review the improved signed audit before changing caller policy."
    if comparison == "regressed":
        return (
            "Inspect both audit IDs and withhold trust expansion until the regression is resolved."
        )
    if reason == "battery_changed":
        return "Re-enroll the owner against the new fixed battery before comparisons resume."
    return "Check consent, endpoint availability, and evidence integrity before retrying."


def _event(
    *,
    target_id: str,
    comparison: str,
    reason: str,
    occurred_at: int,
    previous: dict[str, object] | None,
    observed: dict[str, object] | None,
) -> dict[str, object]:
    core = {
        "target_id": target_id,
        "comparison": comparison,
        "reason": reason,
        "occurred_at": occurred_at,
        "previous_evidence": previous,
        "observed_evidence": observed,
    }
    alert = comparison in {"regressed", "inconclusive"}
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": hashlib.sha256(_canonical_json(core)).hexdigest()[:32],
        **core,
        "action": _action(comparison, reason),
        "notification": "pending" if alert else "not_applicable",
    }


def alert_payload(event: Mapping[str, object]) -> dict[str, object]:
    """Return the exact metadata-only drift notification body."""
    if not _valid_event(dict(event)):
        raise ValueError("Shield alert event is malformed")
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event["event_id"],
        "target_id": event["target_id"],
        "comparison": event["comparison"],
        "reason": event["reason"],
        "occurred_at": event["occurred_at"],
        "previous_evidence": event["previous_evidence"],
        "observed_evidence": event["observed_evidence"],
        "action": event["action"],
    }


class HttpsShieldNotifier:
    """Deliver bounded Shield drift metadata to one operator HTTPS webhook."""

    def __init__(
        self,
        url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            parsed = urlsplit(url)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Shield notifier must be a valid HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("Shield notifier must be HTTPS without credentials or a fragment")
        self._url = url
        self._transport = transport

    async def notify(self, event: Mapping[str, object]) -> None:
        payload = alert_payload(event)
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=5.0,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream(
                "POST",
                self._url,
                json=payload,
                headers={
                    "Accept": "application/json",
                    "Idempotency-Key": str(payload["event_id"]),
                },
            ) as response:
                response.raise_for_status()


def _summary(configured: int) -> dict[str, int]:
    return {
        "configured": configured,
        "due": 0,
        "not_due": 0,
        "initial": 0,
        "unchanged": 0,
        "improved": 0,
        "regressed": 0,
        "inconclusive": 0,
        "notifications_delivered": 0,
        "notification_failures": 0,
    }


async def run_due_audits(
    config_path: Path,
    state_path: Path,
    *,
    auditor: Auditor | None = None,
    evidence_resolver: Callable[[str], dict[str, object]] | None = None,
    notifier: ShieldNotifier | None = None,
    now: int | None = None,
) -> dict[str, int]:
    """Audit only due enrollments and persist bounded comparison evidence."""
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise ValueError("Shield current time must be non-negative Unix seconds")
    targets = load_shield_config(config_path)
    audit_client = auditor or AgentAuditor()
    resolve_evidence = evidence_resolver or _resolve_published_evidence
    summary = _summary(len(targets))

    with _exclusive_state_lock(state_path):
        state = _read_state(state_path)
        states = state["targets"]
        events = state["events"]
        assert isinstance(states, dict)
        assert isinstance(events, list)
        configured_ids = {target.target_id for target in targets}
        for removed_id in set(states) - configured_ids:
            del states[removed_id]

        for target in targets:
            stored = states.get(target.target_id)
            previous: dict[str, object] | None = None
            if isinstance(stored, dict):
                stored_revision = int(stored["enrollment_revision"])
                if stored_revision > target.enrollment_revision:
                    raise ValueError("Shield config rolls back an enrollment revision")
                if (
                    stored_revision == target.enrollment_revision
                    and stored["enrollment_sha256"] != target.enrollment_sha256
                ):
                    raise ValueError(
                        "Shield enrollment changed without increasing enrollment_revision"
                    )
                if stored_revision == target.enrollment_revision:
                    if int(stored["next_due_at"]) > current:
                        summary["not_due"] += 1
                        continue
                    baseline = stored.get("baseline")
                    previous = dict(baseline) if isinstance(baseline, dict) else None

            summary["due"] += 1
            comparison = "inconclusive"
            reason = "audit_failed"
            observed: dict[str, object] | None = None
            try:
                response = await audit_client.audit(target.target_url)
            except (RuntimeError, ValueError):
                response = None
            if response is not None:
                audit_id = _audit_id(response)
                if audit_id is None:
                    reason = "audit_inconclusive"
                else:
                    try:
                        evidence = resolve_evidence(audit_id)
                    except (OSError, RuntimeError, ValueError):
                        reason = "evidence_unavailable"
                    else:
                        observed, evidence_problem = _baseline_from_evidence(
                            evidence,
                            target=target,
                            audit_id=audit_id,
                            now=current,
                        )
                        if evidence_problem is not None:
                            reason = evidence_problem
                        elif observed is not None:
                            comparison, reason = _comparison(previous, observed)

            baseline = previous
            last_conclusive_at = None
            if (
                isinstance(stored, dict)
                and stored["enrollment_revision"] == target.enrollment_revision
            ):
                last_conclusive_at = stored.get("last_conclusive_at")
            if comparison != "inconclusive" and observed is not None:
                baseline = observed
                last_conclusive_at = current
            next_due_at = current + (
                target.interval_hours * 60 * 60
                if comparison != "inconclusive"
                else min(
                    target.interval_hours * 60 * 60,
                    INCONCLUSIVE_RETRY_SECONDS,
                )
            )
            states[target.target_id] = {
                "target_id": target.target_id,
                "enrollment_revision": target.enrollment_revision,
                "enrollment_sha256": target.enrollment_sha256,
                "next_due_at": next_due_at,
                "last_attempt_at": current,
                "last_conclusive_at": last_conclusive_at,
                "comparison": comparison,
                "reason": reason,
                "baseline": baseline,
            }
            event = _event(
                target_id=target.target_id,
                comparison=comparison,
                reason=reason,
                occurred_at=current,
                previous=previous,
                observed=observed,
            )
            events.append(event)
            del events[:-MAX_EVENTS]
            summary[comparison] += 1
            _write_state(state_path, state)

            if event["notification"] == "pending":
                if notifier is None:
                    event["notification"] = "not_configured"
                else:
                    try:
                        await notifier.notify(event)
                    except (httpx.HTTPError, ValueError):
                        event["notification"] = "failed"
                        summary["notification_failures"] += 1
                    else:
                        event["notification"] = "delivered"
                        summary["notifications_delivered"] += 1
                _write_state(state_path, state)

        _write_state(state_path, state)
    return summary


def format_summary(summary: Mapping[str, int]) -> str:
    fields = tuple(_summary(0))
    if set(summary) != set(fields) or any(type(summary[field]) is not int for field in fields):
        raise ValueError("Shield summary is malformed")
    return " ".join(f"{field}={summary[field]}" for field in fields)


def service_exit_code(summary: Mapping[str, int]) -> int:
    return (
        1
        if summary.get("regressed", 0)
        or summary.get("inconclusive", 0)
        or summary.get("notification_failures", 0)
        else 0
    )
