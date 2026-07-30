"""Hard invariants the executor must never violate.

- Idempotency: a jobId is claimed and delivered at most once through SQLite.
- Price floor: never fulfil work priced below the configured USDT floor.
- Service allowlist: only fulfil explicitly allowlisted Warden service ids.
- Deliver gate: `deliver` is only valid when the job status is "accepted".
- APPLY IS NEVER INVOKED BY THIS LAYER: `apply` is triggered by on-chain
  system events, not by the seller executor. Any attempt to run it through
  the CLI boundary is a bug and raises before the subprocess is spawned.
"""

import json
import os
import sqlite3
from contextlib import closing
from decimal import Decimal, InvalidOperation
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal, cast

FORBIDDEN_CLI_ACTIONS = frozenset({"apply"})
JobStatus = Literal["pending", "delivered"]

_BUSY_TIMEOUT_MS = 5_000
_SCHEMA = """
CREATE TABLE IF NOT EXISTS executor_jobs (
    job_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered'))
)
"""


class GuardrailViolation(RuntimeError):
    """A hard executor invariant was about to be violated."""


class IdempotencyStore:
    """Transactional record of pending and delivered marketplace jobs."""

    def __init__(self, path: str | os.PathLike[str]):
        requested_path = Path(path)
        self._legacy_path = requested_path if requested_path.suffix.lower() == ".json" else None
        self._path = (
            requested_path.with_suffix(f"{requested_path.suffix}.sqlite3")
            if self._legacy_path is not None
            else requested_path
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous = FULL")
        except BaseException:
            connection.close()
            raise
        return connection

    def _legacy_delivered(self) -> list[str]:
        if self._legacy_path is None or not self._legacy_path.exists():
            return []
        data = json.loads(self._legacy_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("delivered", []), list):
            raise ValueError("legacy idempotency store must contain a delivered list")
        delivered = data.get("delivered", [])
        if not all(isinstance(job_id, str) for job_id in delivered):
            raise ValueError("legacy idempotency store job ids must be strings")
        return delivered

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        legacy_delivered = self._legacy_delivered()
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_SCHEMA)
            connection.executemany(
                """
                INSERT OR IGNORE INTO executor_jobs (job_id, status)
                VALUES (?, 'delivered')
                """,
                ((job_id,) for job_id in legacy_delivered),
            )
            connection.commit()

    def status(self, job_id: str) -> JobStatus | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT status FROM executor_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return cast(JobStatus, row[0])

    def claim(self, job_id: str) -> bool:
        """Atomically reserve an unseen job in the pending state."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO executor_jobs (job_id, status)
                VALUES (?, 'pending')
                """,
                (job_id,),
            )
            connection.commit()
        return cursor.rowcount == 1

    def already_delivered(self, job_id: str) -> bool:
        return self.status(job_id) == "delivered"

    def mark_delivered(self, job_id: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO executor_jobs (job_id, status)
                VALUES (?, 'delivered')
                ON CONFLICT(job_id) DO UPDATE SET status = 'delivered'
                """,
                (job_id,),
            )
            connection.commit()
        self._write_legacy_projection()

    def _write_legacy_projection(self) -> None:
        if self._legacy_path is None:
            return

        temporary_path: Path | None = None
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            delivered = [
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT job_id
                    FROM executor_jobs
                    WHERE status = 'delivered'
                    ORDER BY job_id
                    """
                )
            ]
            try:
                with NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self._legacy_path.parent,
                    prefix=f".{self._legacy_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    temporary.write(json.dumps({"delivered": delivered}, indent=2))
                    temporary.flush()
                    os.fsync(temporary.fileno())
                os.replace(temporary_path, self._legacy_path)
                connection.commit()
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)


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
