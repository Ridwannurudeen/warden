"""One deterministic answer for every task sitting in the provider queue.

A marketplace ASP can defend refusing work. It cannot defend silence: a task
left at `created` is indistinguishable from an agent that is simply not there,
and eight of them from one buyer is what a non-responsive provider looks like.

So every task gets an answer. Refusal is the answer this module is allowed to
give on its own, because `asp-reject` is an off-chain backend call that signs
nothing and moves no money. Acceptance is not: `apply` signs and broadcasts an
irreversible commitment to paid work, so anything that could be accepted is
surfaced for a human instead (see `guardrails.FORBIDDEN_CLI_ACTIONS`).
"""

import re
from dataclasses import dataclass
from typing import Literal

from warden.executor.guardrails import price_meets_floor

PAYMENT_MODE_ESCROW = 1
STATUS_CREATED = 0
STATUS_ACCEPTED = 1

# How a buyer marks the text they want scanned. Free prose cannot be used: a
# description *about* a payload reads exactly like the payload itself, and
# guessing wrong means either scanning the wrong bytes or refusing real work.
_FENCED = re.compile(r"```(?:[a-zA-Z0-9_-]*)\n?(.*?)```", re.DOTALL)
_LABELLED = re.compile(r"payload\s*:\s*(.+)", re.IGNORECASE | re.DOTALL)
_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")

TriageAction = Literal["refuse", "surface", "deliver"]

BELOW_FLOOR_REASON = (
    "Declined: budget {price} USDT is below Warden's floor of {floor} USDT for this service. "
    "Re-post at or above the listed price and it will be picked up."
)
NO_PAYLOAD_REASON = (
    "Declined: no payload to scan was included. Put the exact text in the task description "
    "inside a ``` fenced block, or on a line starting with 'payload:', then re-post."
)


@dataclass(frozen=True)
class TriageDecision:
    action: TriageAction
    job_id: str
    reason: str
    payload: str | None = None
    expected_addresses: tuple[str, ...] = ()


def extract_payload(description: object) -> str | None:
    """The text a buyer explicitly marked as the thing to scan, or None.

    Deliberately strict. Treating an unmarked description as the payload would
    have Warden scanning "Check if this payload is safe for delivery" and
    returning a verdict on its own instructions.
    """
    if not isinstance(description, str):
        return None
    fenced = _FENCED.search(description)
    if fenced is not None:
        body = fenced.group(1).strip()
        if body:
            return body
    labelled = _LABELLED.search(description)
    if labelled is not None:
        body = labelled.group(1).strip()
        if body:
            return body
    return None


def extract_expected_addresses(description: object) -> tuple[str, ...]:
    """Payout addresses the buyer says it expects, so a redirect is catchable."""
    if not isinstance(description, str):
        return ()
    seen: dict[str, None] = {}
    for match in _EVM_ADDRESS.findall(description):
        seen.setdefault(match.lower(), None)
    return tuple(seen)


def triage(task: dict[str, object], *, price_floor_usdt: str) -> TriageDecision:
    """Decide the single action owed to one provider-side task.

    Gate order is deliberate: price is checked before payload, because a task
    below the floor is refused whatever it contains, and telling a buyer to
    resubmit a payload for work we would decline anyway wastes their time.
    """
    job_id = task.get("jobId")
    if not isinstance(job_id, str) or not job_id:
        return TriageDecision("surface", "", "task has no usable jobId")

    status = task.get("status")
    if status == STATUS_ACCEPTED:
        return TriageDecision("deliver", job_id, "accepted job awaiting its deliverable")
    if status != STATUS_CREATED:
        return TriageDecision("surface", job_id, f"status {status!r} has no deterministic action")

    if task.get("paymentMode") != PAYMENT_MODE_ESCROW:
        # Only escrow is fulfilled in-process; anything else settles elsewhere
        # and is not this layer's to answer.
        return TriageDecision("surface", job_id, "not an escrow task")

    price = str(task.get("tokenAmount", ""))
    if not price_meets_floor(price, price_floor_usdt):
        return TriageDecision(
            "refuse",
            job_id,
            BELOW_FLOOR_REASON.format(price=price or "unstated", floor=price_floor_usdt),
        )

    payload = extract_payload(task.get("description"))
    if payload is None:
        return TriageDecision("refuse", job_id, NO_PAYLOAD_REASON)

    return TriageDecision(
        "surface",
        job_id,
        "meets the floor and carries a payload; acceptance is a human decision",
        payload=payload,
        expected_addresses=extract_expected_addresses(task.get("description")),
    )
