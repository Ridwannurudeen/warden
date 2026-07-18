"""Build deterministic monthly service-level evidence from five-minute probes."""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.monitor_readiness import validate_monitor_document  # noqa: E402

DEFAULT_INPUT = ROOT / "site" / "data" / "service-monitor.json"
DEFAULT_OUTPUT = ROOT / "site" / "data" / "service-level-monthly.json"
CADENCE_SECONDS = 300
MAX_INPUT_BYTES = 8_000_000
MONTH_PATTERN = re.compile(r"^(\d{4})-(\d{2})$")


def _month_bounds(month: str) -> tuple[datetime, datetime, int]:
    match = MONTH_PATTERN.fullmatch(month)
    if match is None:
        raise ValueError("month must use YYYY-MM")
    year, month_number = (int(part) for part in match.groups())
    if not 1 <= month_number <= 12:
        raise ValueError("month must use YYYY-MM")
    days = calendar.monthrange(year, month_number)[1]
    start = datetime(year, month_number, 1, tzinfo=timezone.utc)
    if month_number == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month_number + 1, 1, tzinfo=timezone.utc)
    return start, end, days * 24 * 60 * 60 // CADENCE_SECONDS


def build_monthly_summary(
    document: object,
    month: str,
    source_bytes: bytes,
) -> dict[str, object]:
    validated = validate_monitor_document(document)
    start, end, expected_slots = _month_bounds(month)
    start_slot = int(start.timestamp()) // CADENCE_SECONDS
    end_slot = int(end.timestamp()) // CADENCE_SECONDS
    slots: dict[int, dict[str, bool]] = {}

    for sample in validated["samples"]:
        checked_at = datetime.fromisoformat(sample["checked_at"].replace("Z", "+00:00"))
        slot = int(checked_at.timestamp()) // CADENCE_SECONDS
        if not start_slot <= slot < end_slot:
            continue
        observed = slots.setdefault(
            slot,
            {"application": True, "x402_challenge": True},
        )
        observed["application"] = (
            observed["application"] and sample["application"]["status"] == "ready"
        )
        observed["x402_challenge"] = (
            observed["x402_challenge"] and sample["x402_challenge"]["status"] == "ready"
        )

    def component(name: str, percentage_field: str) -> dict[str, object]:
        ready_slots = sum(1 for slot in slots.values() if slot[name])
        return {
            "ready_slots": ready_slots,
            percentage_field: round(ready_slots * 100 / expected_slots, 4),
        }

    return {
        "schema_version": 1,
        "month": month,
        "cadence_seconds": CADENCE_SECONDS,
        "expected_slots": expected_slots,
        "observed_slots": len(slots),
        "complete": len(slots) == expected_slots,
        "components": {
            "application": component("application", "availability_percent"),
            "x402_challenge": component("x402_challenge", "readiness_percent"),
        },
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
    }


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


def summarize_monitor(input_path: Path, output_path: Path, month: str) -> dict[str, object]:
    source = _safe_path(input_path, label="monitor input", must_exist=True)
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("monitor input exceeds the size limit")
    source_bytes = source.read_bytes()
    document = json.loads(source_bytes)
    summary = build_monthly_summary(document, month, source_bytes)

    output = _safe_path(output_path, label="summary output", must_exist=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(summary, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--month", required=True, help="Completed UTC month in YYYY-MM")
    args = parser.parse_args(argv)
    summary = summarize_monitor(args.input, args.output, args.month)
    print(
        f"Monthly service evidence written for {summary['month']}: "
        f"{summary['observed_slots']}/{summary['expected_slots']} slots"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
