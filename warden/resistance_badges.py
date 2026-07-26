"""Shareable resistance badges derived from signed variant audit reports.

A badge is a deterministic function of one retained report: every field is read
off the report, nothing is sampled at issuance time, and Ed25519 signatures are
deterministic, so re-deriving a badge produces the same bytes forever. There is
therefore no badge store to drift out of step with the evidence, and no way to
hold a badge whose report says something else.

The endpoint-audit badge and its APA predicate are deliberately not reused. Both
are shaped around the fixed 20-probe battery and its benign-liveness control,
neither of which a variant audit runs, so filling those fields in would describe
a run that never happened.
"""

from __future__ import annotations

import time

from warden import protection, variant_audit
from warden.badges import ed25519_sign_record, ed25519_verify_record

SPEC_VERSION = "warden-resistance-badge/1"
# Matches the endpoint-audit attestation TTL: the same 30 days of "recent
# enough to publish" applies to a point-in-time resistance measurement.
BADGE_TTL_SECONDS = 30 * 24 * 60 * 60
LIMITATIONS = (
    "Point-in-time adversarial resistance measured over Warden's training-derived "
    "variant corpus; not certification, continuous monitoring, or proof of future safety."
)
BADGE_FIELDS = frozenset(
    {
        "spec_version",
        "report_id",
        "target_host",
        "grade",
        "detection_rate",
        "detected",
        "conclusive",
        "variants_sent",
        "threat_classes",
        "corpus_fingerprint",
        "generator",
        "observed_at",
        "expires_at",
        "issuer",
        "limitations",
        "issuer_sig",
    }
)
_BADGE_COLORS = {
    "A": "#0ea371",
    "B": "#0ea371",
    "C": "#b45309",
    "D": "#b45309",
    "F": "#be123c",
}


def qualifies(report: dict[str, object]) -> bool:
    """Is this report publishable as a badge?

    A badge is a claim in public, so it needs a run that actually concluded:
    a consented target, at least one conclusive probe, and a real grade.
    INCONCLUSIVE is the absence of a grade and never earns a badge.
    """
    if not variant_audit.verify_report(dict(report)):
        return False
    totals = report["totals"]
    return (
        report["consent_verified"] is True
        and int(totals["conclusive"]) > 0
        and str(totals["grade"]) != variant_audit.INCONCLUSIVE_GRADE
    )


def issue_badge(report: dict[str, object]) -> dict[str, object]:
    """Derive and sign the badge for a qualifying report.

    Raises `ValueError` when the report does not qualify, so an ungraded or
    unverifiable run can never be published as one that passed.
    """
    if not qualifies(report):
        raise ValueError("only a conclusive, consented, graded report can produce a badge")
    totals = report["totals"]
    observed_at = int(report["issued_at"])
    record = {
        "spec_version": SPEC_VERSION,
        "report_id": str(report["report_id"]),
        "target_host": str(report["target_host"]),
        "grade": str(totals["grade"]),
        "detection_rate": float(totals["detection_rate"]),
        "detected": int(totals["detected"]),
        "conclusive": int(totals["conclusive"]),
        "variants_sent": int(totals["variants_sent"]),
        "threat_classes": int(totals["threat_classes"]),
        "corpus_fingerprint": str(report["corpus_fingerprint"]),
        "generator": str(report["generator"]),
        "observed_at": observed_at,
        "expires_at": observed_at + BADGE_TTL_SECONDS,
        "issuer": protection.ISSUER_NAME,
        "limitations": LIMITATIONS,
    }
    signed = ed25519_sign_record(record, protection.issuer_private_key(), "issuer_sig")
    if not verify_badge(signed):
        raise ValueError("resistance badge fields are invalid")
    return signed


def verify_badge(record: dict[str, object]) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != BADGE_FIELDS
        or not variant_audit.canonically_serializable(record)
        or record.get("spec_version") != SPEC_VERSION
        or record.get("issuer") != protection.ISSUER_NAME
        or record.get("limitations") != LIMITATIONS
        or record.get("grade") not in variant_audit.GRADES
        or record.get("grade") == variant_audit.INCONCLUSIVE_GRADE
    ):
        return False
    observed_at = record.get("observed_at")
    expires_at = record.get("expires_at")
    if (
        type(observed_at) is not int
        or type(expires_at) is not int
        # Upper bound leaves room for the TTL, matching the endpoint-audit
        # verifier, so `expires_at` cannot be pushed past the safe range.
        or not 0 <= observed_at <= protection.MAX_SAFE_UNIX_SECONDS - BADGE_TTL_SECONDS
        or expires_at != observed_at + BADGE_TTL_SECONDS
    ):
        return False
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        observed_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def effective_status(record: dict[str, object], *, now: int | None = None) -> str:
    """`active`, `stale`, or `invalid` — never a bare pass."""
    if not verify_badge(record):
        return "invalid"
    current = int(time.time()) if now is None else now
    return "stale" if current > int(record["expires_at"]) else "active"


def render_badge_svg(record: dict[str, object], *, now: int | None = None) -> str:
    """Embeddable SVG that always renders the badge's true state.

    A stale or invalid badge renders as such rather than as its old grade: the
    image is the part that gets pasted into a README, so it is the part that
    must not overstate.
    """
    status = effective_status(record, now=now)
    if status == "active":
        right = f"{record['grade']} · {record['detection_rate']}%"
        color = _BADGE_COLORS[str(record["grade"])]
    else:
        right = status
        color = "#be123c"
    label = "Warden adversarial resistance"
    left_width = 186
    right_width = 12 + 7 * len(right)
    total = left_width + right_width
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {right}">'
        f"<desc>{LIMITATIONS}</desc>"
        f'<rect width="{left_width}" height="20" fill="#1f2937"/>'
        f'<rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>'
        f'<g fill="#ffffff" font-family="Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="8" y="14">{label}</text>'
        f'<text x="{left_width + 6}" y="14">{right}</text>'
        f"</g></svg>"
    )
