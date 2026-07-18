"""Notify an HTTPS webhook only when Warden's monitored service state changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.monitor_readiness import evaluate_monitor_state  # noqa: E402

DEFAULT_MONITOR = ROOT / "site" / "data" / "service-monitor.json"
DEFAULT_STATE = ROOT / "data" / "service-notifier-state.json"
MAX_INPUT_BYTES = 8_000_000
MAX_STATE_BYTES = 4_096


def _safe_path(path: Path, *, label: str, must_exist: bool) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    if any(parent.is_symlink() for parent in (candidate.parent, *candidate.parent.parents)):
        raise ValueError(f"{label} parent must not be a symbolic link")
    if must_exist and not candidate.is_file():
        raise ValueError(f"{label} must be a regular file")
    if not must_exist and candidate.exists() and not candidate.is_file():
        raise ValueError(f"{label} must be a regular file")
    return candidate


def _write_state(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _read_state(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("notifier state exceeds the size limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    observed_at = document.get("last_observed_at") if isinstance(document, dict) else None
    sample_at = document.get("last_sample_at") if isinstance(document, dict) else None
    try:
        parsed_observed_at = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
        parsed_sample_at = (
            None
            if sample_at is None
            else datetime.fromisoformat(str(sample_at).replace("Z", "+00:00"))
        )
    except ValueError as exc:
        raise ValueError("notifier state is malformed") from exc
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "last_state",
            "last_monitor_state",
            "last_observed_at",
            "last_sample_at",
        }
        or document.get("schema_version") != 2
        or document.get("last_state") not in {"ready", "degraded"}
        or document.get("last_monitor_state") not in {"collecting", "stale", "not_running"}
        or not isinstance(observed_at, str)
        or not observed_at.endswith("Z")
        or parsed_observed_at.tzinfo != timezone.utc
        or parsed_observed_at.microsecond
        or (
            sample_at is not None
            and (
                not isinstance(sample_at, str)
                or not sample_at.endswith("Z")
                or parsed_sample_at is None
                or parsed_sample_at.tzinfo != timezone.utc
                or parsed_sample_at.microsecond
            )
        )
    ):
        raise ValueError("notifier state is malformed")
    return document


def _webhook_url(environ: Mapping[str, str]) -> str:
    url = environ.get("WARDEN_ALERT_WEBHOOK_URL", "")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            "WARDEN_ALERT_WEBHOOK_URL must be an HTTPS URL without credentials or a fragment"
        )
    _ = parsed.port
    return url


def notify_transition(
    monitor_path: Path,
    state_path: Path,
    *,
    environ: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    now: datetime | None = None,
) -> str:
    monitor = _safe_path(monitor_path, label="monitor input", must_exist=True)
    state = _safe_path(state_path, label="notifier state", must_exist=False)
    if monitor.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("monitor input exceeds the size limit")
    document = json.loads(monitor.read_text(encoding="utf-8"))
    webhook = _webhook_url(os.environ if environ is None else environ)
    evaluation = evaluate_monitor_state(
        document,
        now=now or datetime.now(timezone.utc).replace(microsecond=0),
    )
    current_state = evaluation["state"]
    previous = _read_state(state)
    if (
        previous is not None
        and evaluation["latest_sample_at"] is not None
        and previous["last_sample_at"] is not None
        and evaluation["latest_sample_at"] < previous["last_sample_at"]
    ):
        raise ValueError("monitor evidence is older than notifier state")
    previous_state = previous["last_state"] if previous is not None else "unknown"
    next_state = {
        "schema_version": 2,
        "last_state": current_state,
        "last_monitor_state": evaluation["monitor_state"],
        "last_observed_at": evaluation["observed_at"],
        "last_sample_at": evaluation["latest_sample_at"],
    }

    if previous is None and current_state == "ready":
        _write_state(state, next_state)
        return "initialized"
    if previous_state == current_state:
        _write_state(state, next_state)
        return "unchanged"

    payload = {
        "schema_version": 2,
        "event": (
            "warden.service.recovered" if current_state == "ready" else "warden.service.degraded"
        ),
        "state": current_state,
        "previous_state": previous_state,
        "monitor_state": evaluation["monitor_state"],
        "observed_at": evaluation["observed_at"],
        "latest_sample_at": evaluation["latest_sample_at"],
        "components": evaluation["components"],
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    with httpx.Client(
        transport=transport,
        timeout=5.0,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        with client.stream(
            "POST",
            webhook,
            json=payload,
            headers={
                "Accept": "application/json",
                "Idempotency-Key": hashlib.sha256(encoded).hexdigest(),
            },
        ) as response:
            response.raise_for_status()
    _write_state(state, next_state)
    return "notified"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=Path, default=DEFAULT_MONITOR)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args(argv)
    try:
        outcome = notify_transition(args.monitor, args.state)
    except (OSError, ValueError, httpx.HTTPError):
        print(
            "Service transition notification failed; sensitive endpoint details withheld.",
            file=sys.stderr,
        )
        return 1
    print(f"Service transition notifier: {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
