"""Signed task-receipt coverage for executor audit jobs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.badges import b64u_encode
from warden.executor.config import ExecutorConfig
from warden.executor.executor import TaskExecutor
from warden.executor.guardrails import ensure_not_apply
from warden.safety_receipts import canonical_sha256, verify_task_safety_receipt

_JOB_ID = "private-audit-job"
_TARGET_URL = "https://private-agent.example/api"


class _RecordingExecutor(TaskExecutor):
    def __init__(self, config: ExecutorConfig) -> None:
        super().__init__(config)
        self.cli_calls: list[list[str]] = []

    def _run_cli(self, args: list[str]) -> str:
        ensure_not_apply(args)
        self.cli_calls.append(args)
        return "ok"


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(private_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)


@pytest.mark.parametrize(
    ("audit_result", "audit_outcome"),
    [
        (
            {
                "score": 96.0,
                "grade": "A",
                "results": [],
                "badge": "Warden-audited: A",
                "recommendations": [],
                "badge_record": {"audit_id": "a" * 16},
                "consent_verified": True,
            },
            "graded",
        ),
        (
            {
                "score": 0.0,
                "grade": "INCONCLUSIVE",
                "results": [],
                "badge": "Warden audit inconclusive",
                "recommendations": ["Retry the audit."],
                "badge_record": None,
                "consent_verified": True,
            },
            "inconclusive",
        ),
    ],
)
async def test_audit_delivery_includes_a_signed_result_bound_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_result: dict[str, object],
    audit_outcome: str,
) -> None:
    async def run_audit(params: dict[str, object]) -> dict[str, object]:
        assert params == {"target_url": _TARGET_URL}
        return audit_result

    monkeypatch.setattr("warden.executor.executor.run_audit", run_audit)
    monkeypatch.setenv("WARDEN_EVIDENCE_DB", str(tmp_path / "evidence.sqlite3"))
    executor = _RecordingExecutor(
        ExecutorConfig(
            idempotency_store_path=str(tmp_path / "idempotency.sqlite3"),
            service_revisions={"warden-audit": "c" * 64},
            task_receipts_enabled=True,
        )
    )

    result = await executor.handle_event(
        {
            "event": "job_accepted",
            "jobId": _JOB_ID,
            "serviceId": "warden-audit",
            "paymentMode": 1,
            "price": "1.0",
            "jobStatus": "accepted",
            "serviceParams": {"target_url": _TARGET_URL},
        }
    )

    assert result["action"] == "delivered"
    deliverable = result["deliverable"]
    receipt = deliverable["task_safety_receipt"]
    assert verify_task_safety_receipt(receipt)
    assert receipt["service_id"] == "warden-audit"
    assert receipt["verdict"] == "ALLOW"
    assert receipt["outcome"] == "result-produced"
    assert receipt["result_sha256"] == canonical_sha256(audit_result)
    assert receipt["decision_sha256"] == canonical_sha256(
        {
            "audit_outcome": audit_outcome,
            "grade": audit_result["grade"],
            "score": audit_result["score"],
            "consent_verified": audit_result["consent_verified"],
            "badge_issued": audit_result["badge_record"] is not None,
        }
    )

    serialized_receipt = json.dumps(receipt, sort_keys=True)
    assert _JOB_ID not in serialized_receipt
    assert _TARGET_URL not in serialized_receipt
    assert len(executor.cli_calls) == 1

    tampered_result = {**audit_result, "grade": "F"}
    assert canonical_sha256(tampered_result) != receipt["result_sha256"]
    assert not verify_task_safety_receipt(
        {
            **receipt,
            "result_sha256": canonical_sha256(tampered_result),
        }
    )
