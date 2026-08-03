"""One deterministic answer for every task in the provider queue.

A marketplace ASP can defend declining work. It cannot defend silence: a task
left unanswered is indistinguishable from an agent that is not there, and eight
of them from one buyer is what a non-responsive provider looks like.

What the answer may be comes from the platform's own designated-task flow. On
`job_asp_selected` the CLI pre-computes a decision in which **price is settled in
code** — "price gate already FAILED in code … Capability is moot; run REJECT
path regardless" — leaving exactly one judgement, whether the service
capability-matches the task. So declining an underpriced task is the platform's
own auto-decision, not an opinion, and `asp-reject` is off-chain and unsigned.

Accepting is never automated. `apply` signs and broadcasts on-chain, and is
driven by the `JobAspSelected` flow, not by this loop (see
`guardrails.FORBIDDEN_CLI_ACTIONS`).

🔴 The gate is computed HERE and the CLI's verdict is never consumed. onchainos
4.4.5 reports `Price gate (OK): offer 0.00001 ≥ registered fee 0.1 ✅` and
recommends applying — a regression; 4.1.0 correctly calls the same job TOO_LOW.
An ASP that executed 4.4.5's recommendation would commit on-chain to work at a
ten-thousandth of its listed fee. The offer arrives as structured data and the
floor is our own published price, so both inputs are verifiable without trusting
an upstream computation.
"""

from dataclasses import dataclass
from typing import Literal

from warden.executor.guardrails import price_meets_floor

PAYMENT_MODE_ESCROW = 1
STATUS_CREATED = 0
STATUS_ACCEPTED = 1

TriageAction = Literal["refuse", "surface"]

# Mirrors the wording the platform's own correct implementation emits, so a
# buyer reading the decline sees the same explanation the marketplace would give.
BELOW_FEE_REASON = "price below registered fee: offer {offer} USDT < registered fee {fee} USDT"


@dataclass(frozen=True)
class TriageDecision:
    action: TriageAction
    job_id: str
    reason: str


def triage(task: dict[str, object], *, price_floor_usdt: str) -> TriageDecision:
    """Decide the single action owed to one provider-side task."""
    job_id = task.get("jobId")
    if not isinstance(job_id, str) or not job_id:
        return TriageDecision("surface", "", "task has no usable jobId")

    status = task.get("status")
    if status == STATUS_ACCEPTED:
        # The only state that owes a deliverable, and the payload arrives during
        # the job rather than on the task record, so a human takes it.
        return TriageDecision("surface", job_id, "accepted job owes a deliverable")
    if status != STATUS_CREATED:
        return TriageDecision("surface", job_id, f"status {status!r} has no deterministic action")

    if task.get("paymentMode") != PAYMENT_MODE_ESCROW:
        # Non-escrow settles outside this path; declining it would be wrong.
        return TriageDecision("surface", job_id, "not an escrow task")

    offer = str(task.get("tokenAmount", ""))
    if not price_meets_floor(offer, price_floor_usdt):
        # price_meets_floor is fail-closed on anything it cannot parse, so an
        # unreadable offer declines rather than slipping through as acceptable.
        return TriageDecision(
            "refuse",
            job_id,
            BELOW_FEE_REASON.format(offer=offer or "unstated", fee=price_floor_usdt),
        )

    return TriageDecision(
        "surface", job_id, "meets the registered fee; applying on-chain is a human decision"
    )
