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
registration — control of that key and nothing else. The key is bound to itself,
so on its own it says nothing about the `agent_id` a request happens to carry.

A registration may additionally name an ERC-8004 `agent_id`, which is only
accepted against a signature from the agent's on-chain owner (see
`warden.agent_identity`). That is what makes `agent_id` evidence rather than an
assertion, and it is recorded as `warden-action-policy/2`. Registrations without
one stay on `/1` byte for byte, so every policy already anchored in the live log
keeps its id, its record, and its sequence.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from web3 import Web3

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
AGENT_BOUND_SPEC_VERSION = "warden-action-policy/2"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/action-policy/v1"
LIMITATIONS = (
    "Registered policy record; proves the policy existed at the anchored log sequence and "
    "nothing about whether any agent was obliged to use it."
)
AGENT_BOUND_LIMITATIONS = (
    "Registered policy record bound to an ERC-8004 agent whose owner proved control at "
    "registration; proves the policy existed at the anchored log sequence, and nothing about "
    "whether the agent was obliged to use it or still has the same owner."
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
AGENT_BOUND_RECORD_FIELDS = RECORD_FIELDS | {"agent_id", "agent_owner"}
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


def policy_id_for(
    policy: ActionPolicy,
    caller_key: str | None = None,
    agent_id: str | None = None,
) -> str:
    """Content address of a registration: the rules, the key, and any agent bound to them.

    The key has to be part of the identity. With the policy alone as the address,
    a second party registering identical rules under its own key would collide
    with the first registration, silently inherit its (possibly absent) key, and
    be handed a receipt whose `caller_verified` could never become true. Two
    parties may hold the same rules; they are separate registrations. An agent
    binding partitions them further, for the same reason.

    An unbound registration hashes exactly the pair it always did, with no
    `agent_id` member at all. That is deliberate rather than tidy: production's
    hash-chained log already holds records addressed that way, and every read
    re-checks a stored record against its log entry, so a derivation that shifted
    those ids would invalidate evidence that is already anchored.
    """
    identity: dict[str, object] = {"policy": canonical_policy(policy), "caller_key": caller_key}
    if agent_id is not None:
        identity["agent_id"] = agent_id
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


def _is_ed25519_public_key(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        return False
    try:
        return len(b64u_decode(value)) == 32
    except (ValueError, TypeError):
        return False


def _is_agent_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9]{1,78}", value) is not None


def _is_checksummed_address(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        return False
    # Stored checksummed so one owner cannot appear as two different strings in
    # two records, the same reason destinations are normalized before hashing.
    return Web3.to_checksum_address(value) == value


def build_policy_record(
    policy: ActionPolicy,
    *,
    caller_key: str | None = None,
    agent_id: str | None = None,
    agent_owner: str | None = None,
    issued_at: int | None = None,
) -> dict[str, object]:
    if caller_key is not None and not _is_ed25519_public_key(caller_key):
        raise ValueError("caller_key must be an ed25519: public key")
    if (agent_id is None) != (agent_owner is None):
        raise ValueError("agent_id and agent_owner must be supplied together")
    content = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "policy_id": policy_id_for(policy, caller_key, agent_id),
        "issuer": protection.ISSUER_NAME,
        "policy": canonical_policy(policy),
        "caller_key": caller_key,
        "issued_at": int(time.time()) if issued_at is None else issued_at,
        "limitations": LIMITATIONS,
    }
    if agent_id is not None:
        if not _is_agent_id(agent_id):
            raise ValueError("agent_id must be a decimal ERC-8004 token id")
        if not _is_checksummed_address(agent_owner):
            raise ValueError("agent_owner must be a checksummed EVM address")
        content["spec_version"] = AGENT_BOUND_SPEC_VERSION
        content["limitations"] = AGENT_BOUND_LIMITATIONS
        content["agent_id"] = agent_id
        content["agent_owner"] = agent_owner
    signed = ed25519_sign_record(content, protection.issuer_private_key(), "issuer_sig")
    if not verify_policy_record(signed):
        raise ValueError("policy record fields are invalid")
    return signed


def verify_policy_record(
    record: Mapping[str, object],
    *,
    issuer_public_key: str | None = None,
) -> bool:
    if not isinstance(record, dict) or not protection._signed_json_values_are_safe(record):
        return False
    # Dispatch on the record's own version. A record anchored under /1 must keep
    # verifying forever: the log re-checks every stored record against its entry
    # on every read, so widening the /1 field set would retroactively invalidate
    # policies that are already evidence.
    bound = record.get("spec_version") == AGENT_BOUND_SPEC_VERSION
    expected_fields = AGENT_BOUND_RECORD_FIELDS if bound else RECORD_FIELDS
    expected_limitations = AGENT_BOUND_LIMITATIONS if bound else LIMITATIONS
    if (
        set(record) != expected_fields
        or record.get("spec_version") not in {SPEC_VERSION, AGENT_BOUND_SPEC_VERSION}
        or record.get("predicate_type") != PREDICATE_TYPE
        or record.get("issuer") != protection.ISSUER_NAME
        or record.get("limitations") != expected_limitations
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
    agent_id = record.get("agent_id") if bound else None
    if bound and (
        not _is_agent_id(agent_id) or not _is_checksummed_address(record.get("agent_owner"))
    ):
        return False
    if policy_id_for(rebuilt, caller_key, agent_id) != record.get("policy_id"):
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
    agent_id: str | None = None,
    agent_owner: str | None = None,
) -> dict[str, object]:
    """Register a policy and anchor it in the transparency log.

    Policies are content-addressed, so registering identical rules twice returns
    the original record with its original anchor. That is deliberate: the first
    registration is the one that establishes the policy predates an action, and a
    later re-registration must not be able to move that evidence forward in time.

    `agent_owner` is the address this caller has *already* been shown to control;
    proving that is the endpoint's job, because it needs the chain. Nothing here
    re-reads it, and no expiry is stored: the proof gates registration once, and
    what survives is the issuer-signed statement of who owned the agent then.
    """
    from warden import evidence_store

    policy_id = policy_id_for(policy, caller_key, agent_id)
    existing = evidence_store.get_action_policy(policy_id, validator=verify_policy_record)
    if existing is not None:
        return existing
    record = build_policy_record(
        policy, caller_key=caller_key, agent_id=agent_id, agent_owner=agent_owner
    )
    return evidence_store.store_action_policy(record, validator=verify_policy_record)


def load_registered_policy(policy_id: str) -> dict[str, object] | None:
    from warden import evidence_store

    return evidence_store.get_action_policy(policy_id, validator=verify_policy_record)
