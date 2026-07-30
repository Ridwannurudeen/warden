"""Runtime configuration for the deterministic ASP task executor."""

import os
import json
import re
from dataclasses import dataclass, field

DEFAULT_AGENT_ID = "3808"
DEFAULT_PRICE_FLOOR_USDT = "0.5"
DEFAULT_IDEMPOTENCY_STORE_PATH = "data/executor-idempotency.sqlite3"
DEFAULT_ONCHAINOS_BIN = "onchainos"
# Warden escrow service ids this executor is willing to fulfil. Anything not
# in this set is ignored by the executor, whatever the event says.
DEFAULT_SERVICE_ALLOWLIST = frozenset({"warden-scan", "warden-audit"})

_ENV_PREFIX = "WARDEN_EXECUTOR_"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _parse_service_revisions(raw: str) -> dict[str, str]:
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("WARDEN_EXECUTOR_SERVICE_REVISIONS must be valid JSON") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("WARDEN_EXECUTOR_SERVICE_REVISIONS must be a non-empty object")
    revisions: dict[str, str] = {}
    for service_id, revision in parsed.items():
        if (
            not isinstance(service_id, str)
            or not service_id.strip()
            or not isinstance(revision, str)
            or not _SHA256.fullmatch(revision)
        ):
            raise ValueError("service revisions must map service ids to lowercase SHA-256 hashes")
        revisions[service_id] = revision
    return revisions


def _parse_bool(raw: str, *, name: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"", "0", "false", "no"}:
        return False
    if normalized in {"1", "true", "yes"}:
        return True
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class ExecutorConfig:
    agent_id: str = DEFAULT_AGENT_ID
    service_allowlist: frozenset[str] = DEFAULT_SERVICE_ALLOWLIST
    price_floor_usdt: str = DEFAULT_PRICE_FLOOR_USDT
    idempotency_store_path: str = DEFAULT_IDEMPOTENCY_STORE_PATH
    service_revisions: dict[str, str] = field(default_factory=dict)
    task_receipts_enabled: bool = False
    onchainos_bin: str = DEFAULT_ONCHAINOS_BIN
    onchainos_env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ExecutorConfig":
        source = os.environ if env is None else env
        allowlist_raw = source.get(f"{_ENV_PREFIX}SERVICE_ALLOWLIST", "")
        allowlist = (
            frozenset(item.strip() for item in allowlist_raw.split(",") if item.strip())
            or DEFAULT_SERVICE_ALLOWLIST
        )
        onchainos_env = {
            key[len(f"{_ENV_PREFIX}CLI_ENV_") :]: value
            for key, value in source.items()
            if key.startswith(f"{_ENV_PREFIX}CLI_ENV_")
        }
        return cls(
            agent_id=source.get(f"{_ENV_PREFIX}AGENT_ID", DEFAULT_AGENT_ID),
            service_allowlist=allowlist,
            price_floor_usdt=source.get(f"{_ENV_PREFIX}PRICE_FLOOR_USDT", DEFAULT_PRICE_FLOOR_USDT),
            idempotency_store_path=source.get(
                f"{_ENV_PREFIX}IDEMPOTENCY_STORE", DEFAULT_IDEMPOTENCY_STORE_PATH
            ),
            service_revisions=_parse_service_revisions(
                source.get(f"{_ENV_PREFIX}SERVICE_REVISIONS", "")
            ),
            task_receipts_enabled=_parse_bool(
                source.get(f"{_ENV_PREFIX}TASK_RECEIPTS_ENABLED", ""),
                name=f"{_ENV_PREFIX}TASK_RECEIPTS_ENABLED",
            ),
            onchainos_bin=source.get(f"{_ENV_PREFIX}ONCHAINOS_BIN", DEFAULT_ONCHAINOS_BIN),
            onchainos_env=onchainos_env,
        )
