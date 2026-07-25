"""Probe Warden readiness and publish a bounded local evidence window."""

from __future__ import annotations

import argparse
import base64
import json
import math
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
STALE_AFTER_SECONDS = 10 * 60
EXPECTED_X402_RESOURCE_URL = "https://warden.gudman.xyz/scan"
EXPECTED_X402_SCHEME = "exact"
EXPECTED_X402_NETWORK = "eip155:196"
EXPECTED_X402_PAY_TO = "0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51"
EXPECTED_X402_AMOUNT = "100000"
EXPECTED_X402_ASSET = "0x779ded0c9e1022225f8e0630b35a9b54be713736"
EXPECTED_X402_EIP712_NAME = "USD₮0"
EXPECTED_X402_EIP712_VERSION = "1"
EXPECTED_READINESS_CHECKS = {
    "deterministic_scanner",
    "paid_routes",
    "semantic_model",
}


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
    _valid_probe_url(url, "readiness")
    _validate_timeout(timeout_seconds)
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
            status = "ready" if http_status == 200 and _readiness_is_ready(payload) else "not_ready"
            return _probe_record(
                checked_at=observed_at,
                status=status,
                http_status=http_status,
                started=started,
                timer=timer,
            )
    except (OSError, TimeoutError, URLError, ValueError, RecursionError):
        return _probe_record(
            checked_at=observed_at,
            status="error",
            http_status=None,
            started=started,
            timer=timer,
        )


def _valid_probe_url(url: str, label: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} URL must be an HTTP(S) URL without credentials or a fragment")
    return parsed.path.rstrip("/") or "/"


def _validate_timeout(timeout_seconds: float) -> None:
    if not 0 < timeout_seconds <= 10:
        raise ValueError("timeout_seconds must be greater than zero and no more than 10")


def _readiness_is_ready(payload: object) -> bool:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"status", "version", "checks"}
        or payload.get("status") not in {"ready", "not_ready"}
        or not isinstance(payload.get("version"), str)
        or not payload["version"].strip()
        or not isinstance(payload.get("checks"), dict)
        or set(payload["checks"]) != EXPECTED_READINESS_CHECKS
    ):
        raise ValueError("readiness response is malformed")

    statuses: dict[str, str] = {}
    allowed = {
        "deterministic_scanner": {"ready", "not_ready"},
        "paid_routes": {"ready", "not_ready", "disabled"},
        "semantic_model": {"ready", "not_ready", "disabled"},
    }
    for name, allowed_statuses in allowed.items():
        check = payload["checks"][name]
        if (
            not isinstance(check, dict)
            or set(check) != {"status", "detail"}
            or check.get("status") not in allowed_statuses
            or not isinstance(check.get("detail"), str)
            or not check["detail"].strip()
        ):
            raise ValueError("readiness response is malformed")
        statuses[name] = check["status"]

    expected_document_status = "not_ready" if "not_ready" in statuses.values() else "ready"
    if payload["status"] != expected_document_status:
        raise ValueError("readiness response status contradicts its checks")
    return (
        payload["status"] == "ready"
        and statuses["deterministic_scanner"] == "ready"
        and statuses["paid_routes"] == "ready"
        and statuses["semantic_model"] in {"ready", "disabled"}
    )


def _validate_x402_challenge(challenge: object, expected_resource_url: str) -> None:
    expected_resource = urlsplit(expected_resource_url)
    if (
        expected_resource.scheme != "https"
        or expected_resource.hostname is None
        or expected_resource.username is not None
        or expected_resource.password is not None
        or expected_resource.query
        or expected_resource.fragment
        or expected_resource.path != "/scan"
    ):
        raise ValueError("expected x402 resource URL is invalid")
    if not isinstance(challenge, dict) or isinstance(challenge, list):
        raise ValueError("x402 challenge must be an object")
    if challenge.get("x402Version") != 2:
        raise ValueError("x402 challenge version is invalid")

    resource = challenge.get("resource")
    if not isinstance(resource, dict) or isinstance(resource, list):
        raise ValueError("x402 challenge resource is invalid")
    resource_url = resource.get("url")
    if not isinstance(resource_url, str):
        raise ValueError("x402 challenge resource URL is invalid")
    parsed_resource = urlsplit(resource_url)
    if (
        parsed_resource.scheme != expected_resource.scheme
        or parsed_resource.hostname != expected_resource.hostname
        or parsed_resource.port != expected_resource.port
        or parsed_resource.path != expected_resource.path
        or parsed_resource.username is not None
        or parsed_resource.password is not None
        or parsed_resource.query
        or parsed_resource.fragment
    ):
        raise ValueError("x402 challenge resource does not match the pinned route")

    accepts = challenge.get("accepts")
    if not isinstance(accepts, list) or len(accepts) != 1:
        raise ValueError("x402 challenge must contain one payment option")
    option = accepts[0]
    required = {
        "scheme": EXPECTED_X402_SCHEME,
        "network": EXPECTED_X402_NETWORK,
        "payTo": EXPECTED_X402_PAY_TO,
        "amount": EXPECTED_X402_AMOUNT,
        "asset": EXPECTED_X402_ASSET,
    }
    if (
        not isinstance(option, dict)
        or isinstance(option, list)
        or any(option.get(field) != value for field, value in required.items())
        or type(option.get("maxTimeoutSeconds")) is not int
        or not 1 <= option["maxTimeoutSeconds"] <= 86_400
        or option.get("extra")
        != {
            "name": EXPECTED_X402_EIP712_NAME,
            "version": EXPECTED_X402_EIP712_VERSION,
        }
    ):
        raise ValueError("x402 challenge payment option is invalid")


def probe_x402_challenge(
    url: str,
    *,
    expected_resource_url: str = EXPECTED_X402_RESOURCE_URL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    opener=urlopen,
    checked_at: str | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> dict[str, object]:
    probe_path = _valid_probe_url(url, "paid-route")
    expected_path = _valid_probe_url(expected_resource_url, "expected x402 resource")
    if probe_path != expected_path:
        raise ValueError("paid-route probe path must match the expected x402 resource path")
    _validate_timeout(timeout_seconds)
    observed_at = _validate_timestamp(checked_at or _utc_timestamp())
    request = Request(
        url,
        data=b'{"payload":"Warden scheduled payment-path readiness probe."}',
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    started = timer()
    http_status: int | None = None
    try:
        try:
            response_context = opener(request, timeout=timeout_seconds)
        except HTTPError as exc:
            response_context = exc
        with response_context as response:
            http_status = int(response.status)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("paid-route response exceeded the size limit")
            if http_status == 200:
                return _probe_record(
                    checked_at=observed_at,
                    status="disabled",
                    http_status=http_status,
                    started=started,
                    timer=timer,
                )
            if http_status != 402:
                return _probe_record(
                    checked_at=observed_at,
                    status="not_ready",
                    http_status=http_status,
                    started=started,
                    timer=timer,
                )
            encoded = response.headers.get("PAYMENT-REQUIRED")
            if not isinstance(encoded, str) or not encoded or len(encoded) > MAX_RESPONSE_BYTES:
                raise ValueError("paid-route response omitted a bounded payment challenge")
            challenge = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
            _validate_x402_challenge(challenge, expected_resource_url)
            return _probe_record(
                checked_at=observed_at,
                status="ready",
                http_status=http_status,
                started=started,
                timer=timer,
            )
    except (OSError, TimeoutError, URLError, ValueError, UnicodeError, RecursionError):
        return _probe_record(
            checked_at=observed_at,
            status="error",
            http_status=http_status,
            started=started,
            timer=timer,
        )


def _component(record: dict[str, object]) -> dict[str, object]:
    return {
        "status": record["status"],
        "http_status": record["http_status"],
        "latency_ms": record["latency_ms"],
    }


def probe_service(
    readiness_url: str,
    paid_url: str,
    *,
    expected_resource_url: str = EXPECTED_X402_RESOURCE_URL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    readiness_opener=urlopen,
    paid_opener=urlopen,
    checked_at: str | None = None,
    timer: Callable[[], float] = time.perf_counter,
) -> dict[str, object]:
    observed_at = _validate_timestamp(checked_at or _utc_timestamp())
    application = probe_readiness(
        readiness_url,
        timeout_seconds=timeout_seconds,
        opener=readiness_opener,
        checked_at=observed_at,
        timer=timer,
    )
    x402_challenge = probe_x402_challenge(
        paid_url,
        expected_resource_url=expected_resource_url,
        timeout_seconds=timeout_seconds,
        opener=paid_opener,
        checked_at=observed_at,
        timer=timer,
    )
    return {
        "checked_at": observed_at,
        "application": _component(application),
        "x402_challenge": _component(x402_challenge),
    }


def _validated_component(
    component: object,
    *,
    label: str,
    allowed_statuses: set[str],
) -> dict[str, object]:
    if not isinstance(component, dict) or set(component) != {
        "status",
        "http_status",
        "latency_ms",
    }:
        raise ValueError(f"{label} probe has an invalid field set")
    if component["status"] not in allowed_statuses:
        raise ValueError(f"{label} probe status is invalid")
    http_status = component["http_status"]
    if http_status is not None and (
        not isinstance(http_status, int) or not 100 <= http_status <= 599
    ):
        raise ValueError(f"{label} probe HTTP status is invalid")
    latency = component["latency_ms"]
    if (
        isinstance(latency, bool)
        or not isinstance(latency, (int, float))
        or not math.isfinite(latency)
        or latency < 0
    ):
        raise ValueError(f"{label} probe latency is invalid")
    return component


def _validated_record(record: dict[str, object]) -> dict[str, object]:
    if not isinstance(record, dict) or set(record) != {
        "checked_at",
        "application",
        "x402_challenge",
    }:
        raise ValueError("probe record has an invalid field set")
    _validate_timestamp(record["checked_at"])
    _validated_component(
        record["application"],
        label="application",
        allowed_statuses={"ready", "not_ready", "error"},
    )
    _validated_component(
        record["x402_challenge"],
        label="x402_challenge",
        allowed_statuses={"ready", "not_ready", "error", "disabled"},
    )
    return record


def validate_monitor_document(document: object) -> dict[str, object]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "status", "samples"}
        or document.get("schema_version") != 2
        or document.get("status") not in {"not_running", "collecting"}
        or not isinstance(document.get("samples"), list)
        or len(document["samples"]) > DEFAULT_MAX_SAMPLES
    ):
        raise ValueError("monitor output is malformed")
    samples = [_validated_record(sample) for sample in document["samples"]]
    if document["status"] == "not_running" and samples:
        raise ValueError("a stopped monitor cannot contain samples")
    if document["status"] == "collecting" and not samples:
        raise ValueError("a collecting monitor must contain samples")
    for previous, current in zip(samples, samples[1:], strict=False):
        if str(current["checked_at"]) <= str(previous["checked_at"]):
            raise ValueError("probe records must be in chronological order")
    return document


def evaluate_monitor_state(
    document: object,
    *,
    now: datetime | None = None,
    stale_after_seconds: int = STALE_AFTER_SECONDS,
) -> dict[str, object]:
    validated = validate_monitor_document(document)
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo != timezone.utc or observed_at.microsecond:
        raise ValueError("monitor evaluation time must be exact UTC seconds")
    if stale_after_seconds < 1:
        raise ValueError("stale_after_seconds must be positive")
    observed_timestamp = observed_at.isoformat().replace("+00:00", "Z")

    if validated["status"] == "not_running":
        return {
            "state": "degraded",
            "monitor_state": "not_running",
            "observed_at": observed_timestamp,
            "latest_sample_at": None,
            "components": {
                "application": "unknown",
                "x402_challenge": "unknown",
            },
        }

    latest = validated["samples"][-1]
    latest_at = datetime.fromisoformat(latest["checked_at"].replace("Z", "+00:00"))
    if latest_at > observed_at:
        raise ValueError("monitor evidence is newer than the evaluation time")
    stale = (observed_at - latest_at).total_seconds() > stale_after_seconds
    components = {
        "application": latest["application"]["status"],
        "x402_challenge": latest["x402_challenge"]["status"],
    }
    ready = not stale and all(status == "ready" for status in components.values())
    return {
        "state": "ready" if ready else "degraded",
        "monitor_state": "stale" if stale else "collecting",
        "observed_at": observed_timestamp,
        "latest_sample_at": latest["checked_at"],
        "components": components,
    }


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
        existing = validate_monitor_document(json.loads(output_path.read_text(encoding="utf-8")))
        samples = existing["samples"]
        if samples and str(record["checked_at"]) <= str(samples[-1]["checked_at"]):
            raise ValueError("probe records must be appended in chronological order")

    published = {
        "schema_version": 2,
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
    parser.add_argument(
        "--paid-url",
        default="http://127.0.0.1:8000/scan",
        help="Paid route whose unsigned x402 challenge is probed",
    )
    parser.add_argument(
        "--expected-resource-url",
        default=EXPECTED_X402_RESOURCE_URL,
        help="Pinned public x402 resource URL expected in the unsigned challenge",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-samples", type=int, default=DEFAULT_MAX_SAMPLES)
    args = parser.parse_args(argv)
    record = probe_service(
        args.url,
        args.paid_url,
        expected_resource_url=args.expected_resource_url,
        timeout_seconds=args.timeout,
    )
    record_probe(record, output_path=args.output, max_samples=args.max_samples)
    print(
        "Service probe recorded: "
        f"application={record['application']['status']} "
        f"x402_challenge={record['x402_challenge']['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
