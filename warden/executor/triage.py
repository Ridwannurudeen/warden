"""One protocol-correct answer for every task in the provider queue.

A marketplace ASP can defend declining work. It cannot defend silence: a task
left at `created` is indistinguishable from an agent that is not there, and
eight of them from one buyer is what a non-responsive provider looks like.

What that answer is comes from the platform's ASP playbook, not from taste:

- A `created` task is answered by opening negotiation (`contact-user`), whose
  canonical opener asks the three topics — budget, acceptance criteria, payment
  mode. Price is therefore a thing to *negotiate*, not a reason to refuse up
  front, and a task description is explicitly "still just an inquiry, not a work
  order", so the absence of a payload in it is normal rather than a defect.
- Acceptance is never automated. `apply` is system-event-triggered, run by the
  `JobAspSelected` flow once the User Agent designates this ASP on-chain;
  invoking it from the cold-start path corrupts the state machine and risks
  escrow loss (see `guardrails.FORBIDDEN_CLI_ACTIONS`).
- Real work waits for `job_accepted`, so an `accepted` job is the only one that
  owes a deliverable.

`contact-user` is safe to automate for the same reason refusing is: it is an
off-chain call that signs nothing and moves no money, and the opener text is
fixed by the CLI, so automation cannot say the wrong thing in the owner's name.
"""

import re
from dataclasses import dataclass
from typing import Literal

PAYMENT_MODE_ESCROW = 1
STATUS_CREATED = 0
STATUS_ACCEPTED = 1

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")

TriageAction = Literal["contact", "surface"]


@dataclass(frozen=True)
class TriageDecision:
    action: TriageAction
    job_id: str
    reason: str
    expected_addresses: tuple[str, ...] = ()


def extract_expected_addresses(description: object) -> tuple[str, ...]:
    """Payout addresses the buyer names, so a later redirect is catchable.

    Collected at triage because the description is where a buyer states them,
    and negotiation may not repeat them.
    """
    if not isinstance(description, str):
        return ()
    seen: dict[str, None] = {}
    for match in _EVM_ADDRESS.findall(description):
        seen.setdefault(match.lower(), None)
    return tuple(seen)


def triage(task: dict[str, object]) -> TriageDecision:
    """Decide the single action owed to one provider-side task."""
    job_id = task.get("jobId")
    if not isinstance(job_id, str) or not job_id:
        return TriageDecision("surface", "", "task has no usable jobId")

    status = task.get("status")

    if status == STATUS_ACCEPTED:
        # The only state that owes a deliverable. Left to a human for now: the
        # payload arrives during negotiation, not on the task record.
        return TriageDecision("surface", job_id, "accepted job owes a deliverable")

    if status != STATUS_CREATED:
        return TriageDecision("surface", job_id, f"status {status!r} has no cold-start action")

    if task.get("paymentMode") != PAYMENT_MODE_ESCROW:
        # Non-escrow settles outside this path; opening a negotiation for it
        # would be answering a question nobody asked.
        return TriageDecision("surface", job_id, "not an escrow task")

    return TriageDecision(
        "contact",
        job_id,
        "created escrow task awaiting a cold-start opener",
        expected_addresses=extract_expected_addresses(task.get("description")),
    )
