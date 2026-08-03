"""Every provider task gets an answer, and the answer is never `apply`.

Warden had eleven tasks sitting in its provider queue with nothing delivered,
eight of them from an agent whose stated purpose is testing whether a provider
performs its duties. Silence is the failure being fixed.

The gate is computed here rather than read from the marketplace CLI, and one
test below pins exactly why: onchainos 4.4.5 reports an offer of 0.00001 as
clearing a registered fee of 0.1 and recommends applying, while 4.1.0 correctly
calls the same job TOO_LOW. Trusting that verdict would commit Warden on-chain
to work at a ten-thousandth of its listed price.

The task dicts below are the real shapes returned by
`agent task-in-progress --agent-ids 3808`.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from warden.executor import poller as poller_module
from warden.executor.config import DEFAULT_PRICE_FLOOR_USDT, ExecutorConfig
from warden.executor.executor import TaskExecutor
from warden.executor.guardrails import GuardrailViolation, ensure_not_apply, price_meets_floor
from warden.executor.poller import MarketplaceUnavailable, poll_once
from warden.executor.triage import triage

# The real offers seen in production: dust from the sandbox agent, and two at
# five times the registered fee.
DUST_OFFER = "0.00001"
REGISTERED_FEE = "0.1"


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


# --- the gate --------------------------------------------------------------


def test_the_marketplace_cli_regression_does_not_reproduce_here():
    # onchainos 4.4.5 prints "Price gate (OK): offer 0.00001 >= registered fee
    # 0.1" for this exact pair and recommends applying. 4.1.0 calls it TOO_LOW.
    # This asserts our own arithmetic sides with 4.1.0, and would fail loudly if
    # anyone rewired the gate to consume the CLI's verdict.
    assert Decimal(DUST_OFFER) < Decimal(REGISTERED_FEE)
    assert not price_meets_floor(DUST_OFFER, REGISTERED_FEE)

    decision = triage(_task(tokenAmount=DUST_OFFER), price_floor_usdt=REGISTERED_FEE)
    assert decision.action == "refuse"
    assert DUST_OFFER in decision.reason and REGISTERED_FEE in decision.reason


def test_the_floor_matches_the_price_the_listing_actually_advertises():
    # It was 0.5 against a listing of 0.1, so the floor declined work offered at
    # exactly the advertised rate.
    assert DEFAULT_PRICE_FLOOR_USDT == REGISTERED_FEE


def test_an_offer_at_the_registered_fee_is_not_declined():
    decision = triage(_task(tokenAmount=REGISTERED_FEE), price_floor_usdt=REGISTERED_FEE)

    assert decision.action == "surface"
    assert "human decision" in decision.reason


@pytest.mark.parametrize("offer", ["", "not-a-number", "abc"])
def test_an_unreadable_offer_declines_rather_than_slipping_through(offer: str):
    # Fail-closed: an offer we cannot parse must never be treated as acceptable.
    assert triage(_task(tokenAmount=offer), price_floor_usdt=REGISTERED_FEE).action == "refuse"


def test_an_accepted_job_is_surfaced_as_owing_a_deliverable():
    decision = triage(_task(status=1), price_floor_usdt=REGISTERED_FEE)

    assert decision.action == "surface"
    assert "deliverable" in decision.reason


def test_a_non_escrow_task_is_left_alone():
    # paymentMode 3 settles by x402 outside this path. Priced as dust on purpose,
    # so a gate ignoring paymentMode would be visible here.
    decision = triage(_task(paymentMode=3, tokenAmount=DUST_OFFER), price_floor_usdt=REGISTERED_FEE)

    assert decision.action == "surface"
    assert "escrow" in decision.reason


def test_an_unknown_status_is_surfaced_rather_than_guessed_at():
    # Priced as dust deliberately: a disputed task must not be declined on price,
    # so if the status gate were dropped this would fall through and refuse.
    decision = triage(_task(status=4, tokenAmount=DUST_OFFER), price_floor_usdt=REGISTERED_FEE)

    assert decision.action == "surface"
    assert "4" in decision.reason


def test_a_task_without_a_job_id_is_never_acted_on():
    # Also dust-priced: without the id check this reaches the price gate and
    # returns "refuse" for an empty job id, which the loop would then hand to
    # asp-reject as a blank argument.
    decision = triage(_task(jobId="", tokenAmount=DUST_OFFER), price_floor_usdt=REGISTERED_FEE)

    assert decision.action == "surface"
    assert decision.job_id == ""


# --- the loop --------------------------------------------------------------


async def test_a_dry_run_touches_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tasks = [_task(jobId=f"0xjob{i}", tokenAmount=DUST_OFFER) for i in range(3)]
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: tasks)
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    results = await poll_once(config, dry_run=True, executor=executor)

    assert [r["action"] for r in results] == ["would-refused"] * 3
    assert executor.cli_calls == []


async def test_a_dry_run_describes_exactly_what_the_live_run_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tasks = [
        _task(jobId="0xa", tokenAmount=DUST_OFFER),
        _task(jobId="0xb", status=1),
        _task(jobId="0xc", paymentMode=3),
    ]
    monkeypatch.setattr(poller_module, "fetch_provider_tasks", lambda _c: tasks)
    preview_config = _config(tmp_path / "preview")
    live_config = _config(tmp_path / "live")

    preview = await poll_once(
        preview_config, dry_run=True, executor=_RecordingExecutor(preview_config)
    )
    live = await poll_once(live_config, dry_run=False, executor=_RecordingExecutor(live_config))

    assert [str(r["action"]).removeprefix("would-") for r in preview] == [r["action"] for r in live]


async def test_a_buyer_is_not_declined_twice_for_the_same_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        poller_module, "fetch_provider_tasks", lambda _c: [_task(tokenAmount=DUST_OFFER)]
    )
    config = _config(tmp_path)
    executor = _RecordingExecutor(config)

    first = await poll_once(config, dry_run=False, executor=executor)
    second = await poll_once(config, dry_run=False, executor=executor)

    assert first[0]["action"] == "refused"
    assert second[0]["action"] == "noop"
    assert len(executor.cli_calls) == 1
    assert executor.cli_calls[0][:2] == ["agent", "asp-reject"]
    assert "--reason" in executor.cli_calls[0]


async def test_apply_never_reaches_the_cli_for_any_task_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # The invariant that matters most: nothing this loop does can accept work.
    # apply is driven by JobAspSelected, and the CLI that would recommend it is
    # the one whose price gate cannot be trusted.
    tasks = [
        _task(jobId="0xa", tokenAmount=DUST_OFFER),
        _task(jobId="0xb", tokenAmount="0.5"),
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
