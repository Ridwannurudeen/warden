"""Every provider task gets an answer, and the answer is never `apply`.

Warden had eleven tasks sitting in its provider queue with nothing delivered,
eight of them from one agent whose whole stated purpose is testing whether a
provider performs its duties. Silence is the failure being fixed.

What counts as an answer comes from the platform's ASP playbook: a `created`
task is answered by opening negotiation, price is a negotiation topic rather
than grounds for refusal, a task description is "still just an inquiry, not a
work order", and `apply` is system-event-triggered only.

The task dicts below are the real shapes returned by
`agent task-in-progress --agent-ids 3808`, descriptions included verbatim.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from warden.executor import poller as poller_module
from warden.executor.config import ExecutorConfig
from warden.executor.executor import TaskExecutor
from warden.executor.guardrails import GuardrailViolation, ensure_not_apply
from warden.executor.poller import MarketplaceUnavailable, poll_once
from warden.executor.triage import extract_expected_addresses, triage

# Verbatim from production.
REAL_DESCRIPTIONS = [
    "Check if this payload is safe for delivery to the listed recipients.",
    "Evaluate this payload for delivery to the specified addresses.",
    "Please review this payload for delivery to user@example.com and provide your decision.",
]


def _task(**overrides: object) -> dict[str, object]:
    task: dict[str, object] = {
        "jobId": "0xjob-triage",
        "status": 0,
        "paymentMode": 1,
        "tokenAmount": "0.5",
        "tokenSymbol": "USDT",
        "description": "Check if this payload is safe for delivery to the listed recipients.",
        "title": "Screen this payload text",
    }
    task.update(overrides)
    return task


def _config(tmp_path: Path, **overrides: object) -> ExecutorConfig:
    defaults: dict[str, object] = {"idempotency_store_path": str(tmp_path / "triage.sqlite3")}
    return ExecutorConfig(**{**defaults, **overrides})  # type: ignore[arg-type]


class _RecordingExecutor(TaskExecutor):
    """TaskExecutor with the one subprocess boundary replaced by a recorder."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.cli_calls: list[list[str]] = []

    def _run_cli(self, args: list[str]) -> str:
        ensure_not_apply(args)
        self.cli_calls.append(args)
        return "ok"


# --- the decision ----------------------------------------------------------


def test_a_created_escrow_task_is_answered_by_opening_negotiation():
    assert triage(_task()).action == "contact"


@pytest.mark.parametrize("amount", ["0.00001", "0.5", "999"])
def test_price_never_decides_the_cold_start_answer(amount: str):
    # The opener asks about budget, so price is settled in negotiation. Refusing
    # a nominal-priced task up front would answer "declined" to a capability
    # probe that is measuring whether the provider engages at all.
    assert triage(_task(tokenAmount=amount)).action == "contact"


@pytest.mark.parametrize("description", REAL_DESCRIPTIONS)
def test_a_description_without_a_payload_is_still_a_valid_task(description: str):
    # The playbook is explicit that a description is an inquiry, not a work
    # order. Requiring the payload here refused real work for failing to do
    # something the protocol never asked.
    assert triage(_task(description=description)).action == "contact"


def test_an_accepted_job_is_surfaced_as_owing_a_deliverable():
    decision = triage(_task(status=1))

    assert decision.action == "surface"
    assert "deliverable" in decision.reason


def test_a_non_escrow_task_is_left_alone():
    # paymentMode 3 settles by x402 outside this path. Priced below any floor on
    # purpose, so a gate that ignored paymentMode would be visible here.
    decision = triage(_task(paymentMode=3, tokenAmount="0.00001"))

    assert decision.action == "surface"
    assert "escrow" in decision.reason


def test_an_unknown_status_is_surfaced_rather_than_guessed_at():
    assert triage(_task(status=4)).action == "surface"


def test_a_task_without_a_job_id_is_never_acted_on():
    assert triage(_task(jobId="")).action == "surface"


def test_expected_addresses_are_lifted_for_redirect_detection():
    task = _task(description="Expected wallet: 0xAbCdEf0123456789aBcDeF0123456789AbCdEf01")

    assert triage(task).expected_addresses == ("0xabcdef0123456789abcdef0123456789abcdef01",)
    assert extract_expected_addresses(None) == ()


# --- the loop --------------------------------------------------------------


async def test_a_dry_run_touches_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tasks = [_task(jobId=f"0xjob{i}") for i in range(3)]
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: tasks)
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    results = await poll_once(config, dry_run=True, executor=executor)

    assert [r["action"] for r in results] == ["would-contacted"] * 3
    assert executor.cli_calls == []


async def test_a_dry_run_describes_exactly_what_the_live_run_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # An accepted job triages to "surface" and a created one to "contact". A
    # preview that announced an action the live run never takes would be worse
    # than no preview at all.
    tasks = [_task(jobId="0xa"), _task(jobId="0xb", status=1), _task(jobId="0xc", paymentMode=3)]
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: tasks)
    preview_config = _config(tmp_path / "preview")
    live_config = _config(tmp_path / "live")

    preview = await poll_once(
        preview_config, dry_run=True, executor=_RecordingExecutor(preview_config)
    )
    live = await poll_once(live_config, dry_run=False, executor=_RecordingExecutor(live_config))

    assert [str(r["action"]).removeprefix("would-") for r in preview] == [r["action"] for r in live]


async def test_a_buyer_is_not_approached_about_the_same_job_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # A repeated cold-start opener reads as a malfunctioning agent.
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: [_task()])
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    first = await poll_once(config, dry_run=False, executor=executor)
    second = await poll_once(config, dry_run=False, executor=executor)

    assert first[0]["action"] == "contacted"
    assert second[0]["action"] == "noop"
    assert len(executor.cli_calls) == 1
    assert executor.cli_calls[0][:2] == ["agent", "contact-user"]


async def test_apply_never_reaches_the_cli_for_any_task_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # The invariant that matters most: nothing this loop does can designate or
    # accept. apply is driven by JobAspSelected, and running it from cold start
    # corrupts the state machine.
    tasks = [
        _task(jobId="0xa", tokenAmount="0.00001"),
        _task(jobId="0xb", description=REAL_DESCRIPTIONS[0]),
        _task(jobId="0xc", status=1),
        _task(jobId="0xd", paymentMode=3),
        _task(jobId="0xe", status=4),
    ]
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: tasks)
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    await poll_once(config, dry_run=False, executor=executor)

    assert all("apply" not in call for call in executor.cli_calls)
    for call in executor.cli_calls:
        ensure_not_apply(call)


def test_the_apply_guard_still_bites():
    with pytest.raises(GuardrailViolation):
        ensure_not_apply(["agent", "apply", "--agent-id", "3808"])


async def test_an_unreadable_queue_raises_rather_than_reporting_an_empty_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _explode(_config: object) -> list[dict[str, object]]:
        raise MarketplaceUnavailable("cli exploded")

    monkeypatch.setattr(poller_module, "fetch_provider_tasks", _explode)

    with pytest.raises(MarketplaceUnavailable):
        await poll_once(_config(tmp_path), dry_run=True)


@pytest.mark.parametrize(
    "stdout",
    [
        '{"ok": true, "data": {}}',
        '{"ok": true, "data": {"providerTasks": null}}',
        '{"ok": true}',
        "not json at all",
    ],
)
def test_a_malformed_queue_response_is_never_read_as_an_empty_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str
):
    # Drives the real parser, not a stub of it. A shape change that silently
    # yielded [] would read as "every task answered" while the queue piles up.
    class _Completed:
        def __init__(self) -> None:
            self.stdout = stdout

    monkeypatch.setattr(poller_module.subprocess, "run", lambda *a, **k: _Completed())

    with pytest.raises(MarketplaceUnavailable):
        poller_module.fetch_provider_tasks(_config(tmp_path))


def test_a_well_formed_empty_queue_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    class _Completed:
        stdout = '{"ok": true, "data": {"providerTasks": []}}'

    monkeypatch.setattr(poller_module.subprocess, "run", lambda *a, **k: _Completed())

    assert poller_module.fetch_provider_tasks(_config(tmp_path)) == []


def test_declining_stays_available_for_the_designation_stage(tmp_path: Path):
    # Not on the poller path, but it is the playbook's answer once a User Agent
    # designates this ASP and a price or capability gate fails.
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    executor.refuse("0xdesignated", "budget below the listed price")

    assert executor.cli_calls[0][:2] == ["agent", "asp-reject"]
    assert "--reason" in executor.cli_calls[0]
