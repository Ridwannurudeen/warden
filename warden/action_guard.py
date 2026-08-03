"""Deterministic authorization immediately before an OKX agent acts."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping, Sequence

from warden import protection
from warden.badges import _canonical_json, ed25519_sign_record, ed25519_verify_record
from warden.engine import WardenEngine
from warden.models import (
    ActionIntent,
    ActionPolicy,
    DecisionReceipt,
    OkxTaskContext,
    SafetyDecision,
    SafetyReasonCode,
)

CONTEXT_SPEC_VERSION = "warden-action-context/2"
RECEIPT_SPEC_VERSION = "warden-action-receipt/4"
RECEIPT_PREDICATE_TYPE = "https://warden.gudman.xyz/spec/action-decision/v1"
RECEIPT_LIMITATIONS = (
    "Task-bound record of one Warden payload and caller-policy decision; not proof of "
    "execution, delivery, settlement, authorization, certification, or future safety."
)
RECEIPT_FIELDS = frozenset(
    {
        "spec_version",
        "predicate_type",
        "receipt_id",
        "issuer",
        "network",
        "agent_id",
        "service_id",
        "service_revision_sha256",
        "task_id_sha256",
        "action_type",
        "action_context_sha256",
        "policy_sha256",
        "policy_binding",
        "policy_log_seq",
        "caller_verified",
        "agent_binding",
        "payload_sha256",
        "effective_payload_sha256",
        "decision",
        "reason_codes",
        "issued_at",
        "limitations",
        "issuer_sig",
    }
)
RECEIPT_CONTENT_FIELDS = RECEIPT_FIELDS - {"receipt_id", "issuer_sig"}
_REASON_ORDER: tuple[SafetyReasonCode, ...] = (
    "DRAIN_ADDRESS",
    "SECRET_EXFIL",
    "TOOL_HIJACK",
    "MALICIOUS_LINK",
    "WEB3_INJECTION",
    "PROMPT_INJECTION",
    "ROLE_OVERRIDE",
    "HIDDEN_UNICODE",
    "ENCODING_TRICK",
    "CORPUS_MATCH",
    "STATISTICAL_ANOMALY",
    "ACTION_NOT_ALLOWED",
    "TOOL_NOT_ALLOWED",
    "DESTINATION_NOT_ALLOWED",
    "ASSET_NOT_ALLOWED",
    "AMOUNT_LIMIT_EXCEEDED",
    "SELECTOR_NOT_ALLOWED",
    "PAYLOAD_BLOCKED",
    "PAYLOAD_SANITIZED",
)
_REASON_INDEX = {reason: index for index, reason in enumerate(_REASON_ORDER)}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_action_context(
    intent: ActionIntent,
    task: OkxTaskContext,
) -> dict[str, object]:
    """Return the metadata-only action context committed to by a receipt."""
    return {
        "spec_version": CONTEXT_SPEC_VERSION,
        "task": {
            "network": task.network,
            "agent_id": task.agent_id,
            "service_id": task.service_id,
            "service_revision_sha256": task.service_revision_sha256,
            "task_id_sha256": _sha256_text(task.task_id),
        },
        "action": {
            "action_type": intent.action_type,
            "tool": intent.tool,
            # Hash the normalized destination, so the same address committed to in
            # checksummed and lowercase form yields one context hash rather than two.
            "destination_sha256": (
                _sha256_text(_normalize_destination(intent.destination))
                if intent.destination is not None
                else None
            ),
            "asset": intent.asset,
            "amount_atomic": intent.amount_atomic,
            "selector": intent.selector,
            "payload_sha256": _sha256_text(intent.payload),
        },
    }


def canonicalize_action_context(
    intent: ActionIntent,
    task: OkxTaskContext,
) -> bytes:
    return _canonical_json(canonical_action_context(intent, task)).encode("utf-8")


def action_context_sha256(intent: ActionIntent, task: OkxTaskContext) -> str:
    return hashlib.sha256(canonicalize_action_context(intent, task)).hexdigest()


def policy_sha256(policy: ActionPolicy) -> str:
    canonical_policy = {
        "allowed_actions": sorted(policy.allowed_actions),
        "allowed_tools": sorted(policy.allowed_tools),
        # Normalized, so a policy allowlisting a checksummed address hashes the same
        # as the identical policy written in lowercase.
        "allowed_destinations": sorted(
            _normalize_destination(entry) for entry in policy.allowed_destinations
        ),
        "allowed_selectors": sorted(policy.allowed_selectors),
        "max_amount_atomic_by_asset": dict(sorted(policy.max_amount_atomic_by_asset.items())),
    }
    return hashlib.sha256(_canonical_json(canonical_policy).encode("utf-8")).hexdigest()


def receipt_id_for_content(content: Mapping[str, object]) -> str:
    if set(content) != RECEIPT_CONTENT_FIELDS:
        raise ValueError("decision receipt content fields are invalid")
    return hashlib.sha256(_canonical_json(dict(content)).encode("utf-8")).hexdigest()


def _ordered_reasons(reasons: Sequence[str]) -> list[SafetyReasonCode]:
    unique: set[str] = set(reasons)
    unknown = unique - set(_REASON_INDEX)
    if unknown:
        raise ValueError(f"unsupported safety reason codes: {sorted(unknown)}")
    return [reason for reason in _REASON_ORDER if reason in unique]


def _receipt_content(
    *,
    intent: ActionIntent,
    task: OkxTaskContext,
    decision: str,
    reason_codes: list[SafetyReasonCode],
    context_hash: str,
    policy_hash: str,
    input_hash: str,
    effective_hash: str | None,
    issued_at: int,
    policy_binding: str,
    policy_log_seq: int | None,
    caller_verified: bool,
    agent_binding: str,
) -> dict[str, object]:
    return {
        "spec_version": RECEIPT_SPEC_VERSION,
        "predicate_type": RECEIPT_PREDICATE_TYPE,
        "issuer": protection.ISSUER_NAME,
        "network": task.network,
        "agent_id": task.agent_id,
        "service_id": task.service_id,
        "service_revision_sha256": task.service_revision_sha256,
        "task_id_sha256": _sha256_text(task.task_id),
        "action_type": intent.action_type,
        "action_context_sha256": context_hash,
        "policy_sha256": policy_hash,
        "policy_binding": policy_binding,
        "policy_log_seq": policy_log_seq,
        "caller_verified": caller_verified,
        "agent_binding": agent_binding,
        "payload_sha256": input_hash,
        "effective_payload_sha256": effective_hash,
        "decision": decision,
        "reason_codes": reason_codes,
        "issued_at": issued_at,
        "limitations": RECEIPT_LIMITATIONS,
    }


def issue_decision_receipt(
    *,
    intent: ActionIntent,
    task: OkxTaskContext,
    decision: str,
    reason_codes: list[SafetyReasonCode],
    context_hash: str,
    policy_hash: str,
    input_hash: str,
    effective_hash: str | None,
    issued_at: int | None = None,
    policy_binding: str = "inline",
    policy_log_seq: int | None = None,
    caller_verified: bool = False,
    agent_binding: str = "unbound",
) -> DecisionReceipt:
    current = int(time.time()) if issued_at is None else issued_at
    content = _receipt_content(
        intent=intent,
        task=task,
        decision=decision,
        reason_codes=reason_codes,
        context_hash=context_hash,
        policy_hash=policy_hash,
        input_hash=input_hash,
        effective_hash=effective_hash,
        issued_at=current,
        policy_binding=policy_binding,
        policy_log_seq=policy_log_seq,
        caller_verified=caller_verified,
        agent_binding=agent_binding,
    )
    record = {**content, "receipt_id": receipt_id_for_content(content)}
    signed = ed25519_sign_record(record, protection.issuer_private_key(), "issuer_sig")
    if not verify_decision_receipt(signed):
        raise ValueError("decision receipt fields are invalid")
    return DecisionReceipt.model_validate(signed, strict=True)


def verify_decision_receipt(
    record: dict[str, object],
    *,
    issuer_public_key: str | None = None,
) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != RECEIPT_FIELDS
        or not protection._signed_json_values_are_safe(record)
    ):
        return False
    try:
        parsed = DecisionReceipt.model_validate(record, strict=True)
    except ValueError:
        return False
    if (
        parsed.model_dump(mode="json") != record
        or parsed.spec_version != RECEIPT_SPEC_VERSION
        or parsed.predicate_type != RECEIPT_PREDICATE_TYPE
        or parsed.issuer != protection.ISSUER_NAME
        or parsed.limitations != RECEIPT_LIMITATIONS
        or parsed.reason_codes != _ordered_reasons(parsed.reason_codes)
    ):
        return False
    content = {
        key: value for key, value in record.items() if key not in {"receipt_id", "issuer_sig"}
    }
    if parsed.receipt_id != receipt_id_for_content(content):
        return False
    if issuer_public_key is not None:
        return ed25519_verify_record(record, issuer_public_key, "issuer_sig")
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        parsed.issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def _normalize_destination(value: str) -> str:
    """Fold an EVM address to a single comparable form.

    Tooling disagrees on case: viem returns EIP-55 checksummed addresses while
    most RPC and OKX responses return lowercase. Comparing them literally meant a
    caller could allowlist the very address it was paying and still be refused.
    Only `0x` + 40 hex is folded; anything else compares unchanged, so non-EVM
    destinations keep their case.
    """
    if len(value) == 42 and value.startswith("0x"):
        body = value[2:]
        if all(character in "0123456789abcdefABCDEF" for character in body):
            return "0x" + body.lower()
    return value


def _destination_allowed(destination: str, allowed: Sequence[str]) -> bool:
    target = _normalize_destination(destination)
    return any(target == _normalize_destination(entry) for entry in allowed)


class ActionGuard:
    """Compose payload detection with an explicit caller-owned action policy."""

    def __init__(
        self,
        policy: ActionPolicy,
        *,
        engine: WardenEngine | None = None,
    ) -> None:
        self.policy = policy
        self.engine = engine if engine is not None else WardenEngine()

    async def evaluate(
        self,
        intent: ActionIntent,
        task: OkxTaskContext,
        *,
        issued_at: int | None = None,
        policy_binding: str = "inline",
        policy_log_seq: int | None = None,
        caller_verified: bool = False,
        agent_binding: str = "unbound",
    ) -> SafetyDecision:
        expected_addresses = [intent.destination] if intent.destination is not None else []
        verdict = await self.engine.scan(
            intent.payload,
            depth="thorough",
            context={"expected_addresses": expected_addresses},
            allow_paid_semantic=False,
        )
        policy_reasons = self._policy_reasons(intent)
        scan_verdict = verdict.verdict
        scan_reasons = [reason.value for reason in verdict.threat_classes]
        if scan_verdict not in {"ALLOW", "SANITIZE", "BLOCK"}:
            scan_verdict = "BLOCK"
            scan_reasons.append("PAYLOAD_BLOCKED")

        if policy_reasons or scan_verdict == "BLOCK":
            decision = "BLOCK"
            if scan_verdict == "BLOCK" and not scan_reasons:
                scan_reasons.append("PAYLOAD_BLOCKED")
            sanitized_payload = None
            effective_hash = None
        elif scan_verdict == "SANITIZE":
            if verdict.sanitized_payload == intent.payload:
                decision = "BLOCK"
                scan_reasons.append("PAYLOAD_BLOCKED")
                sanitized_payload = None
                effective_hash = None
            else:
                decision = "SANITIZE"
                if not scan_reasons:
                    scan_reasons.append("PAYLOAD_SANITIZED")
                sanitized_payload = verdict.sanitized_payload
                effective_hash = _sha256_text(sanitized_payload)
        else:
            decision = "ALLOW"
            sanitized_payload = None
            effective_hash = _sha256_text(intent.payload)

        reasons = _ordered_reasons([*scan_reasons, *policy_reasons])
        context_hash = action_context_sha256(intent, task)
        policy_hash = policy_sha256(self.policy)
        input_hash = _sha256_text(intent.payload)
        receipt = issue_decision_receipt(
            intent=intent,
            task=task,
            decision=decision,
            reason_codes=reasons,
            context_hash=context_hash,
            policy_hash=policy_hash,
            input_hash=input_hash,
            effective_hash=effective_hash,
            issued_at=issued_at,
            policy_binding=policy_binding,
            policy_log_seq=policy_log_seq,
            caller_verified=caller_verified,
            agent_binding=agent_binding,
        )
        return SafetyDecision(
            decision=decision,
            reason_codes=reasons,
            action_context_sha256=context_hash,
            policy_sha256=policy_hash,
            payload_sha256=input_hash,
            effective_payload_sha256=effective_hash,
            sanitized_payload=sanitized_payload,
            receipt=receipt,
        )

    def _policy_reasons(self, intent: ActionIntent) -> list[SafetyReasonCode]:
        reasons: list[SafetyReasonCode] = []
        if intent.action_type not in self.policy.allowed_actions:
            reasons.append("ACTION_NOT_ALLOWED")
        if intent.tool not in self.policy.allowed_tools:
            reasons.append("TOOL_NOT_ALLOWED")
        if intent.destination is not None and not _destination_allowed(
            intent.destination, self.policy.allowed_destinations
        ):
            reasons.append("DESTINATION_NOT_ALLOWED")
        if intent.asset is not None and intent.amount_atomic is not None:
            maximum = self.policy.max_amount_atomic_by_asset.get(intent.asset)
            if maximum is None:
                reasons.append("ASSET_NOT_ALLOWED")
            elif intent.amount_atomic > maximum:
                reasons.append("AMOUNT_LIMIT_EXCEEDED")
        if intent.action_type == "contract_call":
            # An unstated selector cannot be policed, and amount limits do not help
            # here: approve(spender, MAX) moves no value while granting away the
            # balance. Refuse rather than authorize a call we cannot see.
            if intent.selector is None or intent.selector not in self.policy.allowed_selectors:
                reasons.append("SELECTOR_NOT_ALLOWED")
        return reasons
