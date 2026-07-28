"""Runtime configuration for the deterministic ASP task executor."""

import os
from dataclasses import dataclass, field

DEFAULT_AGENT_ID = "3808"
DEFAULT_PRICE_FLOOR_USDT = "0.5"
DEFAULT_IDEMPOTENCY_STORE_PATH = "data/executor-idempotency.json"
DEFAULT_ONCHAINOS_BIN = "onchainos"
# Warden escrow service ids this executor is willing to fulfil. Anything not
# in this set is ignored by the executor, whatever the event says.
DEFAULT_SERVICE_ALLOWLIST = frozenset({"warden-scan", "warden-audit"})

_ENV_PREFIX = "WARDEN_EXECUTOR_"


@dataclass(frozen=True)
class ExecutorConfig:
    agent_id: str = DEFAULT_AGENT_ID
    service_allowlist: frozenset[str] = DEFAULT_SERVICE_ALLOWLIST
    price_floor_usdt: str = DEFAULT_PRICE_FLOOR_USDT
    idempotency_store_path: str = DEFAULT_IDEMPOTENCY_STORE_PATH
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
            onchainos_bin=source.get(f"{_ENV_PREFIX}ONCHAINOS_BIN", DEFAULT_ONCHAINOS_BIN),
            onchainos_env=onchainos_env,
        )
