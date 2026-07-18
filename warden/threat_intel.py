"""Aggregate-only threat intelligence derived from explicit feedback."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from warden.feedback_store import validate_feedback_record

K_ANONYMITY = 5
MIN_REPORT_RECORDS = 25
MIN_REPORT_WINDOW_DAYS = 30
_SOURCE = "explicit-opt-in redacted feedback; k=5 published cells; unreviewed counts"
_LIMITATIONS = (
    "Counts are self-reported, deduplicated submissions. Groups below k=5 are absent "
    "from cells, totals, and the observation-window start. Published counts do not "
    "measure prevalence and do not include submitted text or submitter details. Cell "
    "suppression cannot eliminate inference from outside knowledge."
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def normalize_utc_time(value: datetime | None) -> datetime:
    result = value or _utc_now()
    if result.tzinfo != timezone.utc:
        raise ValueError("threat-intelligence timestamps must use UTC")
    return result.replace(microsecond=0)


def parse_utc_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be exact UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be exact UTC") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise ValueError("timestamp must be exact UTC")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _aggregate_record(
    record: dict[str, object],
    generated_at: datetime,
) -> tuple[tuple[str, str], str, datetime] | None:
    validated = validate_feedback_record(record, checked_at=generated_at)
    if validated is None:
        return None
    submitted = parse_utc_timestamp(str(validated["submitted_at"]))
    return (
        (str(validated["outcome"]), str(validated["threat_class"])),
        str(validated["dedupe_key"]),
        submitted,
    )


def _summary_parts(
    records: list[dict[str, object]],
    *,
    generated_at: datetime,
) -> tuple[dict[str, object], list[datetime]]:
    accepted: list[tuple[tuple[str, str], datetime]] = []
    seen_dedupe_keys: set[str] = set()
    for record in records:
        candidate = _aggregate_record(record, generated_at)
        if candidate is None:
            continue
        key, dedupe_key, submitted = candidate
        if dedupe_key in seen_dedupe_keys:
            continue
        seen_dedupe_keys.add(dedupe_key)
        accepted.append((key, submitted))

    counts = Counter(key for key, _ in accepted)
    published_keys = {key for key, count in counts.items() if count >= K_ANONYMITY}
    cells = [
        {
            "outcome": outcome,
            "threat_class": threat_class,
            "count": count,
        }
        for (outcome, threat_class), count in sorted(counts.items())
        if (outcome, threat_class) in published_keys
    ]
    included_times = [submitted for key, submitted in accepted if key in published_keys]
    window_start = (
        min(included_times).replace(hour=0, minute=0, second=0) if included_times else None
    )
    return {
        "schema_version": 1,
        "generated_at": _timestamp(generated_at),
        "window_start": _timestamp(window_start) if window_start else None,
        "window_end": _timestamp(generated_at),
        "k_anonymity": K_ANONYMITY,
        "included_records": len(included_times),
        "cells": cells,
        "source": _SOURCE,
        "limitations": _LIMITATIONS,
    }, included_times


def build_summary(
    records: list[dict[str, object]],
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    generated = normalize_utc_time(generated_at)
    summary, _ = _summary_parts(records, generated_at=generated)
    return summary


def build_report(
    records: list[dict[str, object]],
    *,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    generated = normalize_utc_time(generated_at)
    summary, included_times = _summary_parts(records, generated_at=generated)
    window_days = (generated - min(included_times)).days if included_times else 0
    records_met = int(summary["included_records"]) >= MIN_REPORT_RECORDS
    window_met = window_days >= MIN_REPORT_WINDOW_DAYS
    cells = summary["cells"]
    publishable_cells_met = isinstance(cells, list) and bool(cells)
    return {
        **summary,
        "status": (
            "ready" if records_met and window_met and publishable_cells_met else "insufficient-data"
        ),
        "requirements": {
            "minimum_records": MIN_REPORT_RECORDS,
            "minimum_window_days": MIN_REPORT_WINDOW_DAYS,
            "publishable_cells_required": True,
            "records_met": records_met,
            "window_met": window_met,
            "publishable_cells_met": publishable_cells_met,
        },
    }


def render_report_markdown(report: dict[str, object]) -> str:
    status = str(report["status"])
    requirements = report["requirements"]
    if not isinstance(requirements, dict):
        raise ValueError("report requirements are invalid")
    lines = [
        "# Warden Threat-Intelligence Report",
        "",
        f"Status: **{status}**",
        "",
        f"Generated: {report['generated_at']}",
        f"Observation window: {report['window_start'] or 'unavailable'} to {report['window_end']}",
        f"Records included after k={report['k_anonymity']} suppression: {report['included_records']}",
        "",
    ]
    if status == "insufficient-data":
        lines.extend(
            [
                "Insufficient data for a publishable trend report.",
                "",
                (
                    f"The minimum is {requirements['minimum_records']} records across "
                    f"{requirements['minimum_window_days']} days. No prevalence claim is justified."
                ),
                "",
            ]
        )
        if requirements.get("publishable_cells_met") is False:
            lines.extend(
                [
                    f"No outcome/threat-class cell reached k={report['k_anonymity']}.",
                    "",
                ]
            )
    else:
        lines.extend(["## Aggregate observations", ""])
        cells = report["cells"]
        if not isinstance(cells, list):
            raise ValueError("report cells are invalid")
        for cell in cells:
            if not isinstance(cell, dict):
                raise ValueError("report cell is invalid")
            lines.append(f"- {cell['outcome']} / {cell['threat_class']}: {cell['count']}")
        lines.append("")
    lines.extend(
        [
            "## Evidence boundary",
            "",
            str(report["limitations"]),
            "",
        ]
    )
    return "\n".join(lines)
