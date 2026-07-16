"""Periodically re-probe registered APA endpoints and persist honest freshness."""

from __future__ import annotations

import argparse
import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Mapping

import httpx

from warden import protection, protection_store
from warden.badges import ed25519_verify_record

ProbeGuard = Callable[[str], Awaitable[tuple[str, str, int | None]]]
SUMMARY_FIELDS = (
    "targets",
    "endpoints",
    "active",
    "stale",
    "invalid",
    "key_changed",
    "skipped",
)


class RotationIncomplete(RuntimeError):
    """The rotation candidate did not re-sign every initially eligible record."""


def _endpoint_url(endpoint_host: str) -> str:
    return f"https://{endpoint_host}"


def _failure_status(exc: TimeoutError | ValueError | httpx.HTTPError) -> str:
    if isinstance(exc, (TimeoutError, protection.ProtectionProbeUnavailable, httpx.HTTPError)):
        return "stale"
    return "invalid"


def _status_event(record: Mapping[str, object], status: str) -> str | None:
    return None if record.get("status") == status else status


def _require_current_issuer_records(
    targets: list[dict[str, object]],
    summary: Mapping[str, int],
) -> None:
    completed = sum(summary[field] for field in ("active", "stale", "invalid", "key_changed"))
    if summary["skipped"] or completed != summary["targets"]:
        raise RotationIncomplete(
            "issuer rotation incomplete: every eligible attestation must be updated with zero skipped"
        )

    current_pub = protection.issuer_public_key()
    attestation_ids = []
    for target in targets:
        record = target.get("record")
        attestation_id = record.get("attestation_id") if isinstance(record, dict) else None
        if not isinstance(attestation_id, str) or not attestation_id:
            raise RotationIncomplete(
                "issuer rotation incomplete: eligible attestation identities are invalid"
            )
        attestation_ids.append(attestation_id)
    if len(set(attestation_ids)) != len(targets):
        raise RotationIncomplete(
            "issuer rotation incomplete: eligible attestation identities are invalid"
        )

    invalid = 0
    for attestation_id in attestation_ids:
        record = protection_store.get_attestation(attestation_id)
        if (
            not isinstance(record, dict)
            or not protection.verify_attestation_record(record)
            or not ed25519_verify_record(record, current_pub, "issuer_sig")
        ):
            invalid += 1
    if invalid:
        raise RotationIncomplete(
            f"issuer rotation incomplete: {invalid} eligible attestation(s) are not signed "
            "by the current issuer"
        )


async def reprobe_protections(
    *,
    probe_guard: ProbeGuard | None = None,
    now: int | None = None,
    probe_timeout_seconds: float = protection.PROBE_TIMEOUT_SECONDS,
    max_concurrency: int = 4,
    require_complete_current_issuer: bool = False,
) -> dict[str, int]:
    """Re-probe each bound endpoint once, oldest first, with bounded concurrency."""
    if probe_timeout_seconds <= 0:
        raise ValueError("probe_timeout_seconds must be positive")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1")

    probe = probe_guard or protection.probe_guard
    targets = protection_store.list_reprobe_targets()
    summary = {field: 0 for field in SUMMARY_FIELDS}
    summary["targets"] = len(targets)

    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for target in targets:
        record = target["record"]
        if not isinstance(record, dict) or not protection.verify_attestation_record(record):
            summary["skipped"] += 1
            continue
        if record.get("endpoint_host") != target["endpoint_host"]:
            summary["skipped"] += 1
            continue
        grouped[str(target["endpoint_host"])].append(target)

    async def reprobe_endpoint(
        endpoint_host: str,
        endpoint_targets: list[dict[str, object]],
    ) -> dict[str, int]:
        endpoint_summary = {field: 0 for field in SUMMARY_FIELDS}
        endpoint_summary["endpoints"] = 1
        probed_at = now if now is not None else int(time.time())
        bound_pub = str(endpoint_targets[0]["bound_pub"])
        records = [target["record"] for target in endpoint_targets]
        try:
            async with asyncio.timeout(probe_timeout_seconds):
                returned_host, pub, scans = await probe(_endpoint_url(endpoint_host))
        except (TimeoutError, ValueError, httpx.HTTPError) as exc:
            status = _failure_status(exc)
            results = [
                (
                    _status_event(record, status),
                    protection.resign_attestation_status(record, status),
                    record,
                )
                for record in records
            ]
            updated, _ = protection_store.commit_reprobe_results(
                results,
                endpoint_host=endpoint_host,
                bound_pub=bound_pub,
                last_probed_at=probed_at,
            )
            endpoint_summary[status] += updated
            endpoint_summary["skipped"] += len(records) - updated
            return endpoint_summary

        if returned_host != endpoint_host:
            status = "invalid"
            results = [
                (
                    _status_event(record, status),
                    protection.resign_attestation_status(record, status),
                    record,
                )
                for record in records
            ]
            updated, _ = protection_store.commit_reprobe_results(
                results,
                endpoint_host=endpoint_host,
                bound_pub=bound_pub,
                last_probed_at=probed_at,
            )
            endpoint_summary[status] += updated
            endpoint_summary["skipped"] += len(records) - updated
            return endpoint_summary

        if pub != bound_pub:
            status = "key-changed"
            results = [
                (
                    _status_event(record, status),
                    protection.resign_attestation_status(record, status),
                    record,
                )
                for record in records
            ]
            updated, _ = protection_store.commit_reprobe_results(
                results,
                endpoint_host=endpoint_host,
                bound_pub=bound_pub,
                last_probed_at=probed_at,
                key_changed_host=endpoint_host,
            )
            endpoint_summary["key_changed"] += updated
            endpoint_summary["skipped"] += len(records) - updated
            return endpoint_summary

        refreshed = [
            protection.refresh_attestation(record, scans, verified_at=probed_at)
            for record in records
        ]
        updated, _ = protection_store.commit_reprobe_results(
            [
                ("reprobed", refreshed_record, original_record)
                for original_record, refreshed_record in zip(records, refreshed)
            ],
            endpoint_host=endpoint_host,
            bound_pub=bound_pub,
            last_probed_at=probed_at,
        )
        endpoint_summary["active"] += updated
        endpoint_summary["skipped"] += len(records) - updated
        return endpoint_summary

    queue: asyncio.Queue[tuple[str, list[dict[str, object]]]] = asyncio.Queue()
    for item in grouped.items():
        queue.put_nowait(item)

    async def worker() -> None:
        while True:
            try:
                endpoint_host, endpoint_targets = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            endpoint_summary = await reprobe_endpoint(endpoint_host, endpoint_targets)
            for field in SUMMARY_FIELDS:
                summary[field] += endpoint_summary[field]

    worker_count = min(max_concurrency, len(grouped))
    await asyncio.gather(*(worker() for _ in range(worker_count)))

    if require_complete_current_issuer:
        _require_current_issuer_records(targets, summary)

    return summary


def format_summary_log(summary: Mapping[str, int]) -> str:
    """Return the single non-sensitive journal line for one timer run."""
    return " ".join(f"{field}={summary[field]}" for field in SUMMARY_FIELDS)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Re-probe stored APA protection heartbeats.")
    parser.add_argument(
        "--require-complete-current-issuer",
        action="store_true",
        help="fail unless every initially eligible record is re-signed by the current issuer",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    summary = asyncio.run(
        reprobe_protections(
            require_complete_current_issuer=args.require_complete_current_issuer,
        )
    )
    print(format_summary_log(summary))


if __name__ == "__main__":
    main()
