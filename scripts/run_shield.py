"""Run due owner-enrolled Warden Shield endpoint audits."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.shield import (  # noqa: E402
    HttpsShieldNotifier,
    format_summary,
    run_due_audits,
    service_exit_code,
)

DEFAULT_CONFIG = Path("/opt/warden/shield-targets.json")
DEFAULT_STATE = Path("/opt/warden/data/shield/lifecycle.json")


def _require_production_environment() -> None:
    if os.getenv("WARDEN_ENVIRONMENT", "").strip().lower() != "production":
        raise ValueError("Warden Shield service requires the production environment")
    if os.getenv("WARDEN_REQUIRE_CONSENT", "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise ValueError("Warden Shield service requires hard target consent")
    for name in ("WARDEN_BADGE_SECRET", "WARDEN_ISSUER_KEY", "WARDEN_PROTECTION_DB"):
        if not os.getenv(name, "").strip():
            raise ValueError(f"Warden Shield service requires {name}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    webhook = os.getenv("WARDEN_SHIELD_WEBHOOK_URL", "").strip()
    try:
        _require_production_environment()
        notifier = HttpsShieldNotifier(webhook) if webhook else None
        summary = asyncio.run(
            run_due_audits(
                args.config,
                args.state,
                notifier=notifier,
            )
        )
    except (OSError, RuntimeError, ValueError, httpx.HTTPError):
        print(
            "Warden Shield run failed; target and credential details withheld.",
            file=sys.stderr,
        )
        return 2
    print(format_summary(summary))
    return service_exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(main())
