"""Hard invariants the executor must never violate.

- Idempotency: a jobId is delivered at most once, tracked in a JSON file.
- Price floor: never fulfil work priced below the configured USDT floor.
- Service allowlist: only fulfil explicitly allowlisted Warden service ids.
- Deliver gate: `deliver` is only valid when the job status is "accepted".
- APPLY IS NEVER INVOKED BY THIS LAYER: `apply` is triggered by on-chain
  system events, not by the seller executor. Any attempt to run it through
  the CLI boundary is a bug and raises before the subprocess is spawned.
"""

import json
from decimal import Decimal, InvalidOperation
from pathlib import Path

FORBIDDEN_CLI_ACTIONS = frozenset({"apply"})


class GuardrailViolation(RuntimeError):
    """A hard executor invariant was about to be violated."""


class IdempotencyStore:
    """JSON-file record of jobIds that have already been delivered."""

    def __init__(self, path: str):
        self._path = Path(path)

    def _load(self) -> set[str]:
        if not self._path.exists():
            return set()
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return set(data.get("delivered", []))

    def already_delivered(self, job_id: str) -> bool:
        return job_id in self._load()

    def mark_delivered(self, job_id: str) -> None:
        delivered = self._load()
        delivered.add(job_id)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"delivered": sorted(delivered)}, indent=2), encoding="utf-8"
        )


def price_meets_floor(price_usdt: str, floor_usdt: str) -> bool:
    try:
        return Decimal(price_usdt) >= Decimal(floor_usdt)
    except InvalidOperation:
        return False


def service_is_allowlisted(service_id: str, allowlist: frozenset[str]) -> bool:
    return service_id in allowlist


def require_accepted(job_status: str) -> None:
    """deliver is only valid when the job status is exactly "accepted"."""
    if job_status != "accepted":
        raise GuardrailViolation(f"deliver requires job status 'accepted', got {job_status!r}")


def ensure_not_apply(cli_args: list[str]) -> None:
    """apply is system-event-triggered on-chain; this layer must never run it."""
    forbidden = FORBIDDEN_CLI_ACTIONS.intersection(cli_args)
    if forbidden:
        raise GuardrailViolation(
            f"forbidden CLI action(s) {sorted(forbidden)}: apply is never invoked by the executor"
        )
