"""The event source the executor never had.

`TaskExecutor` reads one system event per stdin line, and nothing on the box
writes to that stdin — so accepted jobs were never delivered and created jobs
were never answered. This polls the marketplace for the provider queue instead
and routes every task through `triage`.

`agent task-in-progress` is the only call that returns `description`,
`paymentMode`, `tokenAmount` and `status` together, which is exactly the set the
gates need; `active-tasks` omits the description and `status <job>` returns one
task at a time.
"""

import argparse
import asyncio
import json
import logging
import subprocess
import sys

from warden.executor.config import ExecutorConfig
from warden.executor.executor import TaskExecutor
from warden.executor.triage import TriageDecision, triage

logger = logging.getLogger(__name__)


class MarketplaceUnavailable(RuntimeError):
    """The provider queue could not be read, so its contents are unknown."""


def fetch_provider_tasks(config: ExecutorConfig) -> list[dict[str, object]]:
    """Read this agent's provider-side queue straight from the marketplace."""
    try:
        completed = subprocess.run(
            [
                config.onchainos_bin,
                "agent",
                "task-in-progress",
                "--agent-ids",
                config.agent_id,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise MarketplaceUnavailable(f"could not read the provider queue: {exc}") from exc
    try:
        body = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise MarketplaceUnavailable("provider queue response was not JSON") from exc
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise MarketplaceUnavailable("provider queue response had no data object")
    tasks = data.get("providerTasks")
    if not isinstance(tasks, list):
        # An empty queue is a list, not a missing key: absence means the shape
        # changed and every task would otherwise be silently skipped.
        raise MarketplaceUnavailable("provider queue response had no providerTasks list")
    return [task for task in tasks if isinstance(task, dict)]


def decide(tasks: list[dict[str, object]]) -> list[TriageDecision]:
    return [triage(task) for task in tasks]


async def poll_once(
    config: ExecutorConfig,
    *,
    dry_run: bool = True,
    executor: TaskExecutor | None = None,
) -> list[dict[str, object]]:
    """Answer every task in the queue once. Opens negotiation; never accepts.

    Defaults to `dry_run` because the live queue holds other people's real
    tasks: the first run of anything that talks to it should only ever describe
    what it would do.
    """
    runner = executor if executor is not None else TaskExecutor(config)
    results: list[dict[str, object]] = []
    for decision in decide(fetch_provider_tasks(config)):
        if decision.action == "contact" and runner.store.already_answered(decision.job_id):
            results.append(
                {"action": "noop", "jobId": decision.job_id, "reason": "already contacted"}
            )
            continue
        # Resolve what this loop would really do *before* branching on dry_run,
        # so a dry run cannot describe an action the live run would not take.
        # Acceptance and delivery both stay out of it: `apply` is driven by the
        # JobAspSelected system event, and delivering needs the payload that
        # only arrives once negotiation has happened.
        effective = "contacted" if decision.action == "contact" else "surfaced"
        if dry_run:
            results.append(
                {
                    "action": f"would-{effective}",
                    "jobId": decision.job_id,
                    "reason": decision.reason,
                }
            )
            continue
        if effective == "contacted":
            results.append(runner.contact_user(decision.job_id))
            runner.store.mark_answered(decision.job_id, "contacted", decision.reason)
        else:
            results.append(
                {"action": "surfaced", "jobId": decision.job_id, "reason": decision.reason}
            )
    return results


async def _main() -> int:
    parser = argparse.ArgumentParser(description="Answer Warden's provider-side task queue.")
    parser.add_argument(
        "--apply-decisions",
        action="store_true",
        help="actually send the cold-start openers (default: describe only)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    config = ExecutorConfig.from_env()
    try:
        results = await poll_once(config, dry_run=not args.apply_decisions)
    except MarketplaceUnavailable as exc:
        logger.error("%s", exc)
        return 1
    for result in results:
        print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
