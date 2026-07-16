"""Probe Warden readiness and publish a bounded local evidence window."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "site" / "data" / "service-monitor.json"
MAX_RESPONSE_BYTES = 16_384
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_SAMPLES = 9_000


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("checked_at must be an exact UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("checked_at must be an exact UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise ValueError("checked_at must be an exact UTC timestamp")
    return value


def _probe_record(
    *,
    checked_at: str,
    status: str,
    http_status: int | None,
    started: float,
    timer: Callable[[], float],
) -> dict[str, object]:
    return {
        "checked_at": checked_at,
        "status": status,
        "http_status": http_status,
        "latency_ms": round(max(0.0, timer() - started) * 1000, 2),
    }


def probe_readiness(
    url: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    opener=urlopen,
    checked_at: str | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> dict[str, object]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ValueError("readiness URL must be an HTTP(S) URL without credentials")
    if not 0 < timeout_seconds <= 10:
        raise ValueError("timeout_seconds must be greater than zero and no more than 10")
    observed_at = _validate_timestamp(checked_at or _utc_timestamp())
    request = Request(url, headers={"Accept": "application/json"})
    started = timer()
    try:
        try:
            response_context = opener(request, timeout=timeout_seconds)
        except HTTPError as exc:
            response_context = exc
        with response_context as response:
            http_status = int(response.status)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("readiness response exceeded the size limit")
            payload = json.loads(body)
            if not isinstance(payload, dict) or not isinstance(payload.get("checks"), dict):
                raise ValueError("readiness response is malformed")
            status = "ready" if http_status == 200 and payload.get("status") == "ready" else "not_ready"
            return _probe_record(
                checked_at=observed_at,
                status=status,
                http_status=http_status,
                started=started,
                timer=timer,
            )
    except (OSError, TimeoutError, URLError, ValueError):
        return _probe_record(
            checked_at=observed_at,
            status="error",
            http_status=None,
            started=started,
            timer=timer,
        )


def _validated_record(record: dict[str, object]) -> dict[str, object]:
    if set(record) != {"checked_at", "status", "http_status", "latency_ms"}:
        raise ValueError("probe record has an invalid field set")
    _validate_timestamp(record["checked_at"])
    if record["status"] not in {"ready", "not_ready", "error"}:
        raise ValueError("probe status is invalid")
    http_status = record["http_status"]
    if http_status is not None and (not isinstance(http_status, int) or not 100 <= http_status <= 599):
        raise ValueError("probe HTTP status is invalid")
    latency = record["latency_ms"]
    if isinstance(latency, bool) or not isinstance(latency, (int, float)) or latency < 0:
        raise ValueError("probe latency is invalid")
    return record


def record_probe(
    record: dict[str, object],
    *,
    output_path: Path = DEFAULT_OUTPUT,
    max_samples: int = DEFAULT_MAX_SAMPLES,
) -> dict[str, object]:
    if max_samples < 1:
        raise ValueError("max_samples must be positive")
    _validated_record(record)
    output_path = Path(os.path.abspath(output_path))
    if output_path.is_symlink():
        raise ValueError("monitor output must not be a symbolic link")
    if any(parent.is_symlink() for parent in (output_path.parent, *output_path.parent.parents)):
        raise ValueError("monitor output parent must not be a symbolic link")
    if output_path.exists() and not output_path.is_file():
        raise ValueError("monitor output must be a regular file")

    samples: list[dict[str, object]] = []
    if output_path.exists():
        existing = json.loads(output_path.read_text(encoding="utf-8"))
        if (
            not isinstance(existing, dict)
            or existing.get("schema_version") != 1
            or existing.get("status") not in {"not_running", "collecting"}
            or not isinstance(existing.get("samples"), list)
        ):
            raise ValueError("existing monitor output is malformed")
        samples = [_validated_record(sample) for sample in existing["samples"]]

    published = {
        "schema_version": 1,
        "status": "collecting",
        "samples": (samples + [record])[-max_samples:],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(published, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output_path)
        output_path.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)
    return published


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/health/ready",
        help="Readiness endpoint to probe (defaults to the local service)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-samples", type=int, default=DEFAULT_MAX_SAMPLES)
    args = parser.parse_args(argv)
    record = probe_readiness(args.url, timeout_seconds=args.timeout)
    record_probe(record, output_path=args.output, max_samples=args.max_samples)
    print(f"Readiness probe recorded: {record['status']}")
    return 0 if record["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
