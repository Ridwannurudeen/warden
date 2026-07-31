"""Policies registered before the fact, so a receipt can cite one rather than assert it.

An inline policy travels with the request, which means a decision receipt records
the policy a caller *asserted at call time*. Submitting the same intent under a
laxer policy yields a different, equally valid signature, so an adjudicator
learns nothing from the receipt alone about which rules were actually in force.

Registering closes that. A policy is signed, stored, and anchored in the
transparency log at a sequence number; the decision receipt then cites the
`policy_id` and that `log_seq`. Because the log is hash-chained, an adjudicator
can establish the policy existed *before* the action it authorized.

Registration also carries an optional Ed25519 caller key. When a guard request is
signed by that key, the receipt records that the caller proved control of the
registration, which is what makes the `agent_id` in a receipt worth anything.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from warden import protection
from warden.badges import (
    _canonical_json,
    b64u_decode,
    b64u_encode,
    ed25519_sign_record,
    ed25519_verify_record,
)
from warden.models import ActionPolicy

SPEC_VERSION = "warden-action-policy/1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/action-policy/v1"
LIMITATIONS = (
    "Registered policy record; proves the policy existed at the anchored log sequence and "
    "nothing about whether any agent was obliged to use it."
)
RECORD_FIELDS = frozenset(
    {
        "spec_version",
        "predicate_type",
        "policy_id",
        "issuer",
        "policy",
        "caller_key",
        "issued_at",
        "limitations",
        "issuer_sig",
    }
)
RECORD_CONTENT_FIELDS = RECORD_FIELDS - {"issuer_sig"}


def canonical_policy(policy: ActionPolicy) -> dict[str, object]:
    """The policy exactly as it is committed to, hashed, and stored.

    Destinations are normalized here for the same reason they are normalized when
    compared: one logical address must not produce two different policy ids.
    """
    from warden.action_guard import _normalize_destination

    return {
        "allowed_actions": sorted(policy.allowed_actions),
        "allowed_tools": sorted(policy.allowed_tools),
        "allowed_destinations": sorted(
            _normalize_destination(entry) for entry in policy.allowed_destinations
        ),
        "allowed_selectors": sorted(policy.allowed_selectors),
        "max_amount_atomic_by_asset": dict(sorted(policy.max_amount_atomic_by_asset.items())),
    }


def policy_id_for(policy: ActionPolicy, caller_key: str | None = None) -> str:
    """Content address of a registration: the rules *and* the key bound to them.

    The key has to be part of the identity. With the policy alone as the address,
    a second party registering identical rules under its own key would collide
    with the first registration, silently inherit its (possibly absent) key, and
    be handed a receipt whose `caller_verified` could never become true. Two
    parties may hold the same rules; they are separate registrations.
    """
    return hashlib.sha256(
        _canonical_json({"policy": canonical_policy(policy), "caller_key": caller_key}).encode(
            "utf-8"
        )
    ).hexdigest()


def _is_ed25519_public_key(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        return False
    try:
        return len(b64u_decode(value)) == 32
    except (ValueError, TypeError):
        return False


def build_policy_record(
    policy: ActionPolicy,
    *,
    caller_key: str | None = None,
    issued_at: int | None = None,
) -> dict[str, object]:
    if caller_key is not None and not _is_ed25519_public_key(caller_key):
        raise ValueError("caller_key must be an ed25519: public key")
    content = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "policy_id": policy_id_for(policy, caller_key),
        "issuer": protection.ISSUER_NAME,
        "policy": canonical_policy(policy),
        "caller_key": caller_key,
        "issued_at": int(time.time()) if issued_at is None else issued_at,
        "limitations": LIMITATIONS,
    }
    signed = ed25519_sign_record(content, protection.issuer_private_key(), "issuer_sig")
    if not verify_policy_record(signed):
        raise ValueError("policy record fields are invalid")
    return signed


def verify_policy_record(
    record: Mapping[str, object],
    *,
    issuer_public_key: str | None = None,
) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != RECORD_FIELDS
        or not protection._signed_json_values_are_safe(record)
        or record.get("spec_version") != SPEC_VERSION
        or record.get("predicate_type") != PREDICATE_TYPE
        or record.get("issuer") != protection.ISSUER_NAME
        or record.get("limitations") != LIMITATIONS
    ):
        return False
    policy = record.get("policy")
    if not isinstance(policy, dict):
        return False
    try:
        rebuilt = ActionPolicy.model_validate(policy)
    except ValueError:
        return False
    caller_key = record.get("caller_key")
    if caller_key is not None and not _is_ed25519_public_key(caller_key):
        return False
    if policy_id_for(rebuilt, caller_key) != record.get("policy_id"):
        return False
    issued_at = record.get("issued_at")
    if type(issued_at) is not int or issued_at < 0:
        return False
    if issuer_public_key is not None:
        return ed25519_verify_record(dict(record), issuer_public_key, "issuer_sig")
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        issued_at <= int(key["not_after"])
        and ed25519_verify_record(dict(record), str(key["pub"]), "issuer_sig")
        for key in keys
    )


def policy_from_record(record: Mapping[str, object]) -> ActionPolicy:
    policy = record.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("policy record has no policy")
    return ActionPolicy.model_validate(policy)


def caller_binding_payload(policy_id: str, action_context_sha256: str) -> bytes:
    """Exactly what a caller signs to prove control of a registration.

    Binding the action context as well as the policy id stops a captured signature
    being replayed against a different action under the same policy.
    """
    return _canonical_json(
        {
            "spec_version": SPEC_VERSION,
            "policy_id": policy_id,
            "action_context_sha256": action_context_sha256,
        }
    ).encode("utf-8")


def caller_signature_valid(
    *,
    caller_key: str | None,
    signature: str | None,
    policy_id: str,
    action_context_sha256: str,
) -> bool:
    """True only when the registration named a key and this request proves control of it.

    The signature is verified over `caller_binding_payload` exactly as published.
    An earlier version verified it over an internal wrapper,
    `{"payload_sha256": sha256(payload)}`, which no caller following the spec
    could produce: `caller_verified` was unreachable from outside, and a wrong
    signature was indistinguishable from an unchecked one. Verifying the
    documented bytes is the whole point of publishing them.
    """
    if caller_key is None or signature is None:
        return False
    if not isinstance(signature, str) or not signature.startswith("sig:"):
        return False
    if not _is_ed25519_public_key(caller_key):
        return False
    try:
        public_key = b64u_decode(caller_key)
        signature_bytes = b64u_decode(signature)
    except (ValueError, TypeError):
        return False
    if (
        len(public_key) != 32
        or len(signature_bytes) != 64
        or b64u_encode(signature_bytes, "sig") != signature
    ):
        return False
    payload = caller_binding_payload(policy_id, action_context_sha256)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, payload)
    except InvalidSignature:
        return False
    return True


def register_policy(
    policy: ActionPolicy,
    *,
    caller_key: str | None = None,
) -> dict[str, object]:
    """Register a policy and anchor it in the transparency log.

    Policies are content-addressed, so registering identical rules twice returns
    the original record with its original anchor. That is deliberate: the first
    registration is the one that establishes the policy predates an action, and a
    later re-registration must not be able to move that evidence forward in time.
    """
    from warden import evidence_store

    policy_id = policy_id_for(policy, caller_key)
    existing = evidence_store.get_action_policy(policy_id, validator=verify_policy_record)
    if existing is not None:
        return existing
    record = build_policy_record(policy, caller_key=caller_key)
    return evidence_store.store_action_policy(record, validator=verify_policy_record)


def load_registered_policy(policy_id: str) -> dict[str, object] | None:
    from warden import evidence_store

    return evidence_store.get_action_policy(policy_id, validator=verify_policy_record)
