"""Signed, payload-free receipts for one OKX task safety decision."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from warden.badges import b64u_encode
from warden.models import TaskSafetyReceiptRecord
from warden.safety_receipts import (
    RECEIPT_FIELDS,
    RECEIPT_TTL_SECONDS,
    canonical_sha256,
    effective_status,
    issue_task_safety_receipt,
    verify_task_safety_receipt,
)

ISSUED_AT = 1_800_000_000
TASK_ID = "0xprivate-okx-job-id"
REQUEST = {
    "payload": "customer private request",
    "expected_addresses": ["0x1111111111111111111111111111111111111111"],
}
RESULT = {"verdict": "ALLOW", "private_analysis": "customer result"}
DECISION = {
    "decision": "ALLOW",
    "action_context_sha256": "a" * 64,
    "policy_sha256": "b" * 64,
}


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(private_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)


def _hashes() -> dict[str, str]:
    return {
        "request_sha256": canonical_sha256(REQUEST),
        "result_sha256": canonical_sha256(RESULT),
        "decision_sha256": canonical_sha256(DECISION),
    }


def _receipt(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "task_id": TASK_ID,
        "agent_id": "3808",
        "service_id": "warden-scan",
        "service_revision_sha256": "c" * 64,
        "verdict": "ALLOW",
        "outcome": "result-produced",
        "issued_at": ISSUED_AT,
        **_hashes(),
    }
    return issue_task_safety_receipt(**{**values, **overrides})


def test_issue_returns_a_strict_signed_payload_free_record() -> None:
    receipt = _receipt()

    assert set(receipt) == RECEIPT_FIELDS
    assert verify_task_safety_receipt(receipt)
    assert TaskSafetyReceiptRecord.model_validate(receipt, strict=True).model_dump() == receipt
    assert receipt["provider"] == "okx"
    assert receipt["task_id_sha256"] == hashlib.sha256(TASK_ID.encode("utf-8")).hexdigest()
    assert receipt["expires_at"] == ISSUED_AT + RECEIPT_TTL_SECONDS
    assert receipt["request_sha256"] == canonical_sha256(REQUEST)
    assert receipt["result_sha256"] == canonical_sha256(RESULT)
    assert receipt["decision_sha256"] == canonical_sha256(DECISION)

    serialized = json.dumps(receipt, sort_keys=True)
    for private_value in (
        TASK_ID,
        str(REQUEST["payload"]),
        str(RESULT["private_analysis"]),
        str(REQUEST["expected_addresses"][0]),
    ):
        assert private_value not in serialized
    assert "not proof of execution" in str(receipt["limitations"]).lower()
    assert "not certification" in str(receipt["limitations"]).lower()


def test_canonical_hash_is_key_order_independent_and_rejects_unsafe_values() -> None:
    assert canonical_sha256({"a": 1, "b": [True, None]}) == canonical_sha256(
        {"b": [True, None], "a": 1}
    )
    assert canonical_sha256({"a": 1}) != canonical_sha256({"a": 2})

    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_sha256({"score": float("nan")})
    with pytest.raises(ValueError, match="canonical JSON"):
        canonical_sha256({"value": object()})


@pytest.mark.parametrize(
    "field",
    ["task_id", "job_id", "payload", "request", "result", "decision"],
)
def test_model_and_verifier_reject_raw_task_or_payload_fields(field: str) -> None:
    receipt = _receipt()
    leaked = {**receipt, field: "private material"}

    assert verify_task_safety_receipt(leaked) is False
    with pytest.raises(ValidationError):
        TaskSafetyReceiptRecord.model_validate(leaked)


@pytest.mark.parametrize("field", sorted(RECEIPT_FIELDS))
def test_mutating_any_signed_field_breaks_verification(field: str) -> None:
    receipt = _receipt()
    mutations: dict[str, object] = {
        "spec_version": "warden-task-safety-receipt/999",
        "predicate_type": "https://attacker.example/receipt",
        "receipt_id": "0" * 64,
        "issuer": "attacker",
        "provider": "attacker",
        "agent_id": "9999",
        "service_id": "other-service",
        "service_revision_sha256": "d" * 64,
        "task_id_sha256": "e" * 64,
        "request_sha256": "f" * 64,
        "result_sha256": "0" * 64,
        "decision_sha256": "1" * 64,
        "verdict": "BLOCK",
        "outcome": "result-withheld",
        "issued_at": ISSUED_AT + 1,
        "expires_at": ISSUED_AT + RECEIPT_TTL_SECONDS + 1,
        "limitations": "safe forever",
        "issuer_sig": "sig:AAAA",
    }
    tampered = {**receipt, field: mutations[field]}

    assert tampered[field] != receipt[field]
    assert verify_task_safety_receipt(tampered) is False
    assert effective_status(tampered, now=ISSUED_AT) == "invalid"


@pytest.mark.parametrize(
    ("verdict", "outcome"),
    [
        ("ALLOW", "result-sanitized"),
        ("SANITIZE", "result-produced"),
        ("BLOCK", "result-produced"),
    ],
)
def test_verdict_and_outcome_must_describe_the_same_boundary_result(
    verdict: str,
    outcome: str,
) -> None:
    with pytest.raises((ValidationError, ValueError), match="outcome"):
        _receipt(verdict=verdict, outcome=outcome)


def test_status_is_active_stale_revoked_or_invalid() -> None:
    receipt = _receipt()

    assert effective_status(receipt, now=receipt["expires_at"]) == "active"
    assert effective_status(receipt, now=int(receipt["expires_at"]) + 1) == "stale"
    assert effective_status(receipt, revoked=True, now=ISSUED_AT) == "revoked"
    assert effective_status(receipt, revoked="yes", now=ISSUED_AT) == "invalid"
    assert effective_status(receipt, now=True) == "invalid"


def test_hash_or_task_changes_produce_a_distinct_receipt() -> None:
    first = _receipt()
    changed_request = _receipt(request_sha256=canonical_sha256({"payload": "different"}))
    changed_result = _receipt(result_sha256=canonical_sha256({"verdict": "BLOCK"}))
    changed_decision = _receipt(decision_sha256=canonical_sha256({"decision": "BLOCK"}))
    changed_task = _receipt(task_id="another-task")

    assert len(
        {
            first["receipt_id"],
            changed_request["receipt_id"],
            changed_result["receipt_id"],
            changed_decision["receipt_id"],
            changed_task["receipt_id"],
        }
    ) == 5


def test_issue_rejects_raw_job_id_shape_and_unsafe_time() -> None:
    with pytest.raises(ValueError, match="task_id"):
        _receipt(task_id="  ")
    with pytest.raises(ValueError, match="issued_at"):
        _receipt(issued_at=True)
