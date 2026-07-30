"""Signed, hash-only security evidence passports for marketplace services."""

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
    AgentServiceBinding,
    SecurityPassportRecord,
    SecurityPassportStatus,
)

SPEC_VERSION = "warden-security-passport/1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/security-passport/v1"
PASSPORT_TTL_SECONDS = protection.ATTESTATION_TTL_SECONDS
LIMITATIONS = (
    "Signed references to point-in-time Warden evidence; not certification, continuous "
    "monitoring, or proof that the service or referenced evidence remains safe or active."
)
PASSPORT_FIELDS = frozenset(SecurityPassportRecord.model_fields)
_HASH_FIELDS = (
    "audit_evidence_sha256",
    "hardening_evidence_sha256",
    "protection_evidence_sha256",
    "shield_evidence_sha256",
)


def _snapshot_value_is_safe(value: object) -> bool:
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
        return all(_snapshot_value_is_safe(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _snapshot_value_is_safe(key) and _snapshot_value_is_safe(item)
            for key, item in value.items()
        )
    return False


def _canonical_snapshot(snapshot: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(snapshot, Mapping):
        raise ValueError("marketplace snapshot must be non-empty finite canonical JSON")
    material = dict(snapshot)
    if not material or not _snapshot_value_is_safe(material):
        raise ValueError("marketplace snapshot must be non-empty finite canonical JSON")
    try:
        json.dumps(
            material,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("marketplace snapshot must be non-empty finite canonical JSON") from exc
    return material


def _matching_snapshot_service(
    snapshot: Mapping[str, object],
    *,
    agent_id: str,
    service_id: str,
) -> Mapping[str, object]:
    agent = snapshot.get("agent", snapshot)
    if not isinstance(agent, Mapping) or agent.get("agentId") != agent_id:
        raise ValueError("marketplace snapshot does not match agent_id")
    services = agent.get("services")
    if not isinstance(services, list):
        raise ValueError("marketplace snapshot has no service list")
    matches = [
        service
        for service in services
        if isinstance(service, Mapping)
        and service.get("serviceId", service.get("id")) == service_id
    ]
    if len(matches) != 1:
        raise ValueError("marketplace snapshot must contain exactly one matching service")
    return matches[0]


def _snapshot_sha256(snapshot: Mapping[str, object]) -> str:
    material = _canonical_snapshot(snapshot)
    return hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


def _revision_from_snapshot_hash(
    *,
    agent_id: str,
    service_id: str,
    chain_id: str,
    endpoint: str,
    marketplace_snapshot_sha256: str,
) -> str:
    candidate = AgentServiceBinding(
        agent_id=agent_id,
        service_id=service_id,
        chain_id=chain_id,
        endpoint=endpoint,
        observed_at=0,
        marketplace_snapshot_sha256=marketplace_snapshot_sha256,
        service_revision_sha256="0" * 64,
    )
    revision_material = {
        "agent_id": candidate.agent_id,
        "service_id": candidate.service_id,
        "chain_id": candidate.chain_id,
        "endpoint": candidate.endpoint,
        "marketplace_snapshot_sha256": candidate.marketplace_snapshot_sha256,
    }
    return hashlib.sha256(_canonical_json(revision_material).encode("utf-8")).hexdigest()


def service_revision_hash(
    *,
    agent_id: str,
    service_id: str,
    chain_id: str,
    endpoint: str,
    marketplace_snapshot: Mapping[str, object],
) -> str:
    """Hash one canonical marketplace observation into a service revision."""
    material = _canonical_snapshot(marketplace_snapshot)
    service = _matching_snapshot_service(
        material,
        agent_id=agent_id,
        service_id=service_id,
    )
    if service.get("endpoint") != endpoint:
        raise ValueError("marketplace snapshot endpoint does not match endpoint")
    return _revision_from_snapshot_hash(
        agent_id=agent_id,
        service_id=service_id,
        chain_id=chain_id,
        endpoint=endpoint,
        marketplace_snapshot_sha256=_snapshot_sha256(material),
    )


def build_agent_service_binding(
    *,
    agent_id: str,
    service_id: str,
    chain_id: str,
    endpoint: str,
    observed_at: int,
    marketplace_snapshot: Mapping[str, object],
) -> AgentServiceBinding:
    """Validate and bind a service identity to its exact observed public snapshot."""
    snapshot_hash = _snapshot_sha256(marketplace_snapshot)
    revision_hash = service_revision_hash(
        agent_id=agent_id,
        service_id=service_id,
        chain_id=chain_id,
        endpoint=endpoint,
        marketplace_snapshot=marketplace_snapshot,
    )
    return AgentServiceBinding(
        agent_id=agent_id,
        service_id=service_id,
        chain_id=chain_id,
        endpoint=endpoint,
        observed_at=observed_at,
        marketplace_snapshot_sha256=snapshot_hash,
        service_revision_sha256=revision_hash,
    )


def _passport_id(record: Mapping[str, object]) -> str:
    core = {key: value for key, value in record.items() if key not in {"passport_id", "issuer_sig"}}
    return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()


def issue_security_passport(
    *,
    binding: AgentServiceBinding | Mapping[str, object],
    audit_evidence_sha256: str,
    hardening_evidence_sha256: str,
    protection_evidence_sha256: str,
    shield_evidence_sha256: str,
    issued_at: int | None = None,
) -> dict[str, object]:
    """Issue a signed composite containing evidence hashes, never evidence bodies."""
    service_binding = AgentServiceBinding.model_validate(binding)
    current = int(time.time()) if issued_at is None else issued_at
    if type(current) is not int or not (
        0 <= current <= protection.MAX_SAFE_UNIX_SECONDS - PASSPORT_TTL_SECONDS
    ):
        raise ValueError("passport issued_at must be safe Unix seconds")
    if current < service_binding.observed_at:
        raise ValueError("passport cannot be issued before the service observation")
    record: dict[str, object] = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "issuer": protection.ISSUER_NAME,
        "binding": service_binding.model_dump(),
        "audit_evidence_sha256": audit_evidence_sha256,
        "hardening_evidence_sha256": hardening_evidence_sha256,
        "protection_evidence_sha256": protection_evidence_sha256,
        "shield_evidence_sha256": shield_evidence_sha256,
        "issued_at": current,
        "expires_at": current + PASSPORT_TTL_SECONDS,
        "limitations": LIMITATIONS,
    }
    record["passport_id"] = _passport_id(record)
    signed = ed25519_sign_record(
        record,
        protection.issuer_private_key(),
        "issuer_sig",
    )
    if not verify_security_passport(signed):
        raise ValueError("security passport fields are invalid")
    return json.loads(_canonical_json(signed))


def verify_security_passport(record: dict[str, object]) -> bool:
    """Verify the strict schema, derived hashes, time bounds, and issuer signature."""
    if (
        not isinstance(record, dict)
        or set(record) != PASSPORT_FIELDS
        or not protection._signed_json_values_are_safe(record)
    ):
        return False
    try:
        passport = SecurityPassportRecord.model_validate(record)
    except ValidationError:
        return False
    serialized = passport.model_dump()
    binding = passport.binding
    if (
        passport.spec_version != SPEC_VERSION
        or passport.predicate_type != PREDICATE_TYPE
        or passport.issuer != protection.ISSUER_NAME
        or passport.limitations != LIMITATIONS
        or passport.expires_at != passport.issued_at + PASSPORT_TTL_SECONDS
        or binding.service_revision_sha256
        != _revision_from_snapshot_hash(
            agent_id=binding.agent_id,
            service_id=binding.service_id,
            chain_id=binding.chain_id,
            endpoint=binding.endpoint,
            marketplace_snapshot_sha256=binding.marketplace_snapshot_sha256,
        )
        or passport.passport_id != _passport_id(serialized)
        or any(not serialized[field] for field in _HASH_FIELDS)
    ):
        return False
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        passport.issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def effective_status(
    record: dict[str, object],
    *,
    revoked: bool = False,
    current_service_revision_sha256: str | None = None,
    now: int | None = None,
) -> SecurityPassportStatus:
    """Return the passport's fail-closed status against current lifecycle facts."""
    if not verify_security_passport(record) or type(revoked) is not bool:
        return "invalid"
    current = int(time.time()) if now is None else now
    if type(current) is not int or not 0 <= current <= protection.MAX_SAFE_UNIX_SECONDS:
        return "invalid"
    if current_service_revision_sha256 is not None and (
        not isinstance(current_service_revision_sha256, str)
        or len(current_service_revision_sha256) != 64
        or any(character not in "0123456789abcdef" for character in current_service_revision_sha256)
    ):
        return "invalid"
    if revoked:
        return "revoked"
    if (
        current_service_revision_sha256 is not None
        and current_service_revision_sha256 != record["binding"]["service_revision_sha256"]
    ):
        return "superseded"
    return "stale" if current > int(record["expires_at"]) else "active"
