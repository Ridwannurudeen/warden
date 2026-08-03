"""Deterministic system-event handler for the Warden ASP seller.

Given a parsed marketplace system event, decide exactly one action:

- job_accepted for an allowlisted escrow (paymentMode == 1) service whose
  guardrails all pass → run the matching work function in-process, then
  submit the deliverable through the onchainos CLI.
- negotiation messages → firewall-screen the buyer text, then route to the
  configured Negotiator; the reply text is returned as data, never executed.
- everything else → logged no-op.

The subprocess boundary is isolated in ``TaskExecutor._run_cli`` so tests can
mock it; ``apply`` is refused there unconditionally (see guardrails).
"""

import json
import logging
import os
import subprocess

from warden import evidence_store
from warden.executor.config import ExecutorConfig
from warden.executor.firewall import screen_incoming
from warden.executor.guardrails import (
    IdempotencyStore,
    ensure_not_apply,
    price_meets_floor,
    require_accepted,
    service_is_allowlisted,
)
from warden.executor.negotiator import NegotiationContext, Negotiator, RefuseNegotiator
from warden.executor.work import WorkParamsError, run_audit, run_scan
from warden.safety_receipts import (
    canonical_sha256,
    issue_task_safety_receipt,
    verify_task_safety_receipt,
)

logger = logging.getLogger(__name__)

PAYMENT_MODE_ESCROW = 1
NEGOTIATION_EVENTS = frozenset({"negotiation_message", "buyer_message", "job_negotiating"})


class TaskExecutor:
    def __init__(
        self,
        config: ExecutorConfig,
        store: IdempotencyStore | None = None,
        negotiator: Negotiator | None = None,
    ):
        self.config = config
        self.store = store if store is not None else IdempotencyStore(config.idempotency_store_path)
        self.negotiator = negotiator if negotiator is not None else RefuseNegotiator()

    async def handle_event(self, event: dict[str, object]) -> dict[str, object]:
        event_name = event.get("event")
        job_id = event.get("jobId")
        if not isinstance(event_name, str) or not isinstance(job_id, str) or not job_id:
            return self._noop("malformed event: event and jobId are required strings")
        if event_name in NEGOTIATION_EVENTS:
            return await self._handle_negotiation(event, job_id)
        if event_name == "job_accepted":
            return await self._handle_job_accepted(event, job_id)
        logger.info("event %s for job %s: no deterministic action", event_name, job_id)
        return self._noop(f"no deterministic action for event {event_name!r}")

    async def _handle_negotiation(self, event: dict[str, object], job_id: str) -> dict[str, object]:
        buyer_message = event.get("message")
        if not isinstance(buyer_message, str) or not buyer_message.strip():
            return self._noop("negotiation event without message text")
        allowed, verdict_dict = await screen_incoming(buyer_message)
        if not allowed:
            logger.warning("firewall BLOCK on negotiation message for job %s", job_id)
            return {"action": "firewall_blocked", "jobId": job_id, "verdict": verdict_dict}
        if verdict_dict.get("verdict") == "SANITIZE":
            buyer_message = str(verdict_dict["sanitized_payload"])
        context = NegotiationContext(
            job_id=job_id,
            service_id=str(event.get("serviceId", "")),
            buyer_message=buyer_message,
            price_usdt=str(event.get("price", "")),
            verdict=verdict_dict,
        )
        reply = await self.negotiator.respond(context)
        return {"action": "negotiation_reply", "jobId": job_id, "reply": reply}

    async def _handle_job_accepted(
        self, event: dict[str, object], job_id: str
    ) -> dict[str, object]:
        service_id = event.get("serviceId")
        if not isinstance(service_id, str) or not service_is_allowlisted(
            service_id, self.config.service_allowlist
        ):
            return self._noop(f"service {service_id!r} is not allowlisted")
        service_revision = self.config.service_revisions.get(service_id)
        if self.config.task_receipts_enabled and service_revision is None:
            return self._noop(f"service revision is not configured for {service_id}")
        if event.get("paymentMode") != PAYMENT_MODE_ESCROW:
            return self._noop("only escrow (paymentMode=1) jobs are auto-fulfilled")
        price = str(event.get("price", ""))
        if not price_meets_floor(price, self.config.price_floor_usdt):
            return self._noop(f"price {price!r} is below floor {self.config.price_floor_usdt} USDT")
        if self.store.already_delivered(job_id):
            return self._noop(f"job {job_id} already delivered (idempotent skip)")
        job_status = str(event.get("jobStatus", ""))
        require_accepted(job_status)
        service_params = event.get("serviceParams")
        if not isinstance(service_params, dict):
            return self._noop("serviceParams must be an object")
        if not self.store.claim(job_id):
            status = self.store.status(job_id)
            if status == "delivered":
                return self._noop(f"job {job_id} already delivered (idempotent skip)")
            return self._noop(f"job {job_id} has pending delivery requiring reconciliation")
        try:
            if service_id == "warden-audit":
                deliverable = await run_audit(service_params)
            else:
                deliverable = await run_scan(service_params)
        except WorkParamsError as exc:
            logger.warning("job %s has malformed serviceParams: %s", job_id, exc)
            return self._noop(f"malformed serviceParams: {exc}")
        if self.config.task_receipts_enabled and service_id in {"warden-scan", "warden-audit"}:
            if service_id == "warden-scan":
                verdict = deliverable.get("verdict")
                if verdict not in {"ALLOW", "SANITIZE", "BLOCK"}:
                    return self._noop("scan result has no supported verdict for task receipt")
                outcome = {
                    "ALLOW": "result-produced",
                    "SANITIZE": "result-sanitized",
                    "BLOCK": "result-withheld",
                }[verdict]
                decision = {
                    "verdict": verdict,
                    "threat_classes": deliverable.get("threat_classes", []),
                }
            else:
                grade = deliverable.get("grade")
                score = deliverable.get("score")
                consent_verified = deliverable.get("consent_verified")
                badge_record = deliverable.get("badge_record")
                if (
                    grade not in {"A", "B", "C", "D", "F", "INCONCLUSIVE"}
                    or type(score) not in {int, float}
                    or not 0 <= score <= 100
                    or type(consent_verified) is not bool
                    or (badge_record is not None and not isinstance(badge_record, dict))
                    or (grade == "INCONCLUSIVE" and badge_record is not None)
                ):
                    return self._noop("audit result has no supported outcome for task receipt")
                verdict = "ALLOW"
                outcome = "result-produced"
                decision = {
                    "audit_outcome": ("inconclusive" if grade == "INCONCLUSIVE" else "graded"),
                    "grade": grade,
                    "score": score,
                    "consent_verified": consent_verified,
                    "badge_issued": badge_record is not None,
                }
            task_receipt = issue_task_safety_receipt(
                task_id=job_id,
                agent_id=self.config.agent_id,
                service_id=service_id,
                service_revision_sha256=service_revision,
                request_sha256=canonical_sha256(service_params),
                result_sha256=canonical_sha256(deliverable),
                decision_sha256=canonical_sha256(decision),
                verdict=verdict,
                outcome=outcome,
            )
            evidence_store.store_task_safety_receipt(
                task_receipt,
                validator=verify_task_safety_receipt,
            )
            deliverable = {**deliverable, "task_safety_receipt": task_receipt}
        output = self._run_cli(
            [
                "agent",
                "deliver",
                "--agent-id",
                self.config.agent_id,
                job_id,
                "--deliverable-text",
                json.dumps(deliverable),
                "--message",
                f"Warden {service_id} deliverable for job {job_id}",
            ]
        )
        self.store.mark_delivered(job_id)
        logger.info("delivered job %s (%s)", job_id, service_id)
        return {
            "action": "delivered",
            "jobId": job_id,
            "serviceId": service_id,
            "deliverable": deliverable,
            "cli_output": output,
        }

    def refuse(self, job_id: str, reason: str) -> dict[str, object]:
        """Decline a task the gates rejected, with the reason on the record.

        Goes through the same CLI boundary as everything else, so `apply` stays
        unreachable from here. `asp-reject` is off-chain and unsigned: the cost
        of declining wrongly is a buyer re-posting, while the cost of staying
        silent is an ASP that looks absent.
        """
        self._run_cli(
            [
                "agent",
                "asp-reject",
                "--agent-id",
                self.config.agent_id,
                job_id,
                "--reason",
                reason,
            ]
        )
        logger.info("declined job %s: %s", job_id, reason)
        return {"action": "refused", "jobId": job_id, "reason": reason}

    def _run_cli(self, args: list[str]) -> str:
        """Single subprocess boundary to the onchainos CLI (mock this in tests)."""
        ensure_not_apply(args)
        completed = subprocess.run(
            [self.config.onchainos_bin, *args],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, **self.config.onchainos_env},
            check=True,
        )
        return completed.stdout

    @staticmethod
    def _noop(reason: str) -> dict[str, object]:
        return {"action": "noop", "reason": reason}


async def _main() -> None:
    """Read one JSON system event per stdin line and handle it deterministically."""
    import sys

    logging.basicConfig(level=logging.INFO)
    executor = TaskExecutor(ExecutorConfig.from_env())
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("skipping non-JSON event line: %s", exc)
            continue
        if not isinstance(event, dict):
            logger.warning("skipping non-object event line")
            continue
        result = await executor.handle_event(event)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())
