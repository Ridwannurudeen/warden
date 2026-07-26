"""Adversarial variant audit: deep per-class probing of a consented endpoint.

This is the deep tier above the 20-probe endpoint audit. It fires a bounded,
deterministic subset of the training-derived adversarial variant packs at a
target that published the Warden consent marker, and reports how many variants
of each threat class the target blocked.

Everything probing-related is reused from `AgentAuditor`: SSRF-safe URL
validation with one pinned resolution, the `/.well-known/warden-consent` gate,
redirect-free requests, bounded response reads, per-probe timeouts, and the
BLOCKED / NOT_BLOCKED / INCONCLUSIVE grading. There is no second prober here.

The report carries counts only. Probe payload text never enters it, and the
variants themselves derive from `corpus/attacks.jsonl` alone, so no held-out
benchmark case ever reaches a target or a report.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import secrets
import sys
import time
from collections.abc import Mapping, Sequence

import httpx

from warden import adversarial_variants, protection, variant_audit_store
from warden.auditor import (
    AUDIT_TIMEOUT_SECONDS,
    MAX_AUDIT_RESPONSE_BYTES,
    AgentAuditor,
    AuditOutcome,
)
from warden.badges import _canonical_json, ed25519_sign_record, ed25519_verify_record

SCHEMA_VERSION = 2
INCONCLUSIVE_GRADE = "INCONCLUSIVE"
GRADES = ("A", "B", "C", "D", "F", INCONCLUSIVE_GRADE)
MAX_VARIANTS_PER_CLASS = 25
MAX_TOTAL_VARIANTS = 150
TOTAL_TIMEOUT_SECONDS = 180.0
# Depth tiers. `standard` is the original contract and stays the default, so an
# existing caller's request is unchanged in every respect.
#
# The deep tier's ceilings are set by wall clock, not by appetite: probes are
# sent one at a time, a timed-out run yields no partial report at all, and
# nginx has to be willing to hold the connection for the whole thing. 300
# probes inside 420 seconds is 1.4s per probe, which is the slowest target the
# tier can serve without spending a buyer's fee on a timeout.
DEEP_MAX_VARIANTS_PER_CLASS = 50
DEEP_MAX_TOTAL_VARIANTS = 300
DEEP_TOTAL_TIMEOUT_SECONDS = 420.0
DEPTHS = ("standard", "deep")
DEFAULT_DEPTH = "standard"
CONTENT_FIELDS = frozenset(
    {
        "schema_version",
        "target_host",
        "corpus_fingerprint",
        "generator",
        "caps",
        "per_class",
        "totals",
        "consent_verified",
        "limitations",
        "delta",
        "nonce",
    }
)
REPORT_FIELDS = CONTENT_FIELDS | {"report_id", "issuer", "issued_at", "issuer_sig"}
_PACKS_CACHE: tuple[str, dict[str, dict[str, object]]] | None = None


def _depth_tier(depth: str) -> dict[str, object]:
    """Resolve the caps for one depth tier.

    The standard tier is read from the module constants on every call rather
    than copied into a table at import, so there is exactly one source of truth
    for the default bounds and no way for a table to drift away from them.
    """
    if depth == "deep":
        return {
            "max_variants_per_class": DEEP_MAX_VARIANTS_PER_CLASS,
            "max_total_variants": DEEP_MAX_TOTAL_VARIANTS,
            "total_timeout_seconds": DEEP_TOTAL_TIMEOUT_SECONDS,
        }
    return {
        "max_variants_per_class": MAX_VARIANTS_PER_CLASS,
        "max_total_variants": MAX_TOTAL_VARIANTS,
        "total_timeout_seconds": TOTAL_TIMEOUT_SECONDS,
    }


def _dataset_paths() -> tuple[object, ...]:
    return (
        adversarial_variants.TRAINING_ATTACKS_PATH,
        adversarial_variants.TRAINING_BENIGN_PATH,
        adversarial_variants.HELD_OUT_ATTACKS_PATH,
        adversarial_variants.HELD_OUT_BENIGN_PATH,
    )


def _corpus_state() -> str:
    """Identify the exact corpus state a pack build would read.

    Every one of the four datasets is hashed, not just the training pair the
    published corpus fingerprint covers: editing a held-out file changes what
    separation validation must reject, and a key blind to that would serve
    packs validated against a corpus that no longer exists. Line endings are
    normalized first so a CRLF checkout is not a different corpus.
    """
    digest = hashlib.sha256()
    for path in _dataset_paths():
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            # `load_dataset_rows` reports a missing dataset as a ValueError and
            # the route maps ValueError to 400. Letting an OSError escape here
            # instead turns the same operator error into a 500 with a
            # traceback, on a route the buyer has already paid for.
            raise ValueError("variant sources must be readable canonical dataset files") from exc
        digest.update(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()


def _canonical_packs() -> dict[str, dict[str, object]]:
    """Build the per-class packs from the canonical training corpus.

    `build_variant_packs` re-checks training/held-out separation on every build,
    so an audit run cannot start from a corpus state that leaks held-out rows.
    The result is cached against that corpus state because the build is
    deterministic but costs a fifth of a second, and it runs synchronously on
    the async request path; any edit to any of the four datasets changes the
    key and forces a fresh build, so the separation check is never skipped for
    a corpus it has not actually run against.

    Two concurrent misses simply build twice and the later assignment wins,
    which is why no lock is held across the build.
    """
    global _PACKS_CACHE

    state = _corpus_state()
    cached = _PACKS_CACHE
    if cached is not None and cached[0] == state:
        return cached[1]
    packs = adversarial_variants.build_variant_packs(
        training_attacks_path=adversarial_variants.TRAINING_ATTACKS_PATH,
        training_benign_path=adversarial_variants.TRAINING_BENIGN_PATH,
        held_out_attacks_path=adversarial_variants.HELD_OUT_ATTACKS_PATH,
        held_out_benign_path=adversarial_variants.HELD_OUT_BENIGN_PATH,
    )
    # The build re-reads the four files, so a corpus that changed while it was
    # reading would otherwise be cached under the key of the corpus that
    # preceded it, and a later request matching that key would probe a target
    # with packs whose held-out separation was never checked against it.
    # Caching only when the state is unchanged either side of the build closes
    # that window; the packs just built are still correct for whatever they
    # were built from, so they are returned rather than discarded.
    if _corpus_state() == state:
        _PACKS_CACHE = (state, packs)
    return packs


def _audited_classes(
    packs: Mapping[str, Mapping[str, object]],
    threat_classes: Sequence[str] | None,
) -> tuple[str, ...]:
    available = tuple(
        threat_class
        for threat_class in adversarial_variants.THREAT_CLASSES
        if packs[threat_class]["variants"]
    )
    if not available:
        raise ValueError("no adversarial variants are available to audit")
    if threat_classes is None:
        return available
    if not threat_classes:
        raise ValueError("threat_classes must not be empty")
    requested: set[str] = set()
    for threat_class in threat_classes:
        if threat_class not in adversarial_variants.THREAT_CLASSES:
            raise ValueError("threat_classes must contain known Warden threat classes")
        if threat_class not in available:
            raise ValueError("threat_classes must contain classes that have adversarial variants")
        requested.add(threat_class)
    return tuple(threat_class for threat_class in available if threat_class in requested)


def _select_variants(
    packs: Mapping[str, Mapping[str, object]],
    threat_classes: tuple[str, ...],
    max_variants_per_class: int,
    max_total_variants: int,
) -> dict[str, list[Mapping[str, object]]]:
    """Take a bounded, deterministic subset of each class pack.

    Classes are filled round-robin so the total cap trims every class evenly
    instead of exhausting the first classes and never probing the last ones.
    """
    pools = {
        threat_class: list(packs[threat_class]["variants"])[:max_variants_per_class]
        for threat_class in threat_classes
    }
    selected: dict[str, list[Mapping[str, object]]] = {
        threat_class: [] for threat_class in threat_classes
    }
    remaining = max_total_variants
    for index in range(max_variants_per_class):
        for threat_class, pool in pools.items():
            if not remaining:
                return selected
            if index < len(pool):
                selected[threat_class].append(pool[index])
                remaining -= 1
    return selected


async def _probe_target(
    target_url: str,
    selected: Mapping[str, list[Mapping[str, object]]],
    *,
    expected_host: str | None = None,
) -> tuple[str, dict[str, dict[str, int]]]:
    auditor = AgentAuditor()
    try:
        async with asyncio.timeout(AUDIT_TIMEOUT_SECONDS):
            connect_url, host_header, parsed_target = await auditor._validate_public_http_url(
                target_url
            )
    except TimeoutError as exc:
        raise ValueError("target_url validation timed out") from exc
    target_host = host_header.rstrip(".").casefold()
    # Checked here rather than after the run: this is the first point the host
    # is known, and it reuses the one pinned resolution instead of resolving
    # again. Deciding afterwards fires the whole battery at a host the caller
    # did not mean to compare against, and charges them for it.
    if expected_host is not None and target_host != expected_host:
        raise ValueError("since must name a report for the same target host")
    host_authority = auditor._host_authority(host_header, parsed_target.port)
    outcomes: dict[str, dict[str, int]] = {
        threat_class: {"detected": 0, "missed": 0, "inconclusive": 0} for threat_class in selected
    }

    async with httpx.AsyncClient(timeout=AUDIT_TIMEOUT_SECONDS, follow_redirects=False) as client:
        # Hundreds of attack payloads must never reach a target that has not
        # opted in, so an unverified consent marker refuses the run outright —
        # including in the development soft mode the 20-probe audit tolerates.
        consent_verified = await auditor._verify_target_consent(
            client, host_header, parsed_target, connect_url
        )
        if not consent_verified:
            raise ValueError("target_url did not pass consent check")
        for threat_class, variants in selected.items():
            for variant in variants:
                outcome = await auditor._target_outcome(
                    client,
                    connect_url,
                    host_authority,
                    str(variant["payload"]),
                    sni_hostname=host_header,
                )
                if outcome is AuditOutcome.BLOCKED:
                    outcomes[threat_class]["detected"] += 1
                elif outcome is AuditOutcome.NOT_BLOCKED:
                    outcomes[threat_class]["missed"] += 1
                else:
                    outcomes[threat_class]["inconclusive"] += 1
    return target_host, outcomes


def _detection_rate(detected: int, conclusive: int) -> float | None:
    """Return ``None`` rather than an unearned zero when nothing was conclusive."""
    return round((detected / conclusive) * 100, 2) if conclusive else None


def _resistance_grade(rate: float | None, inconclusive: int) -> str:
    """Grade a detection rate on the endpoint audit's scale, or refuse to.

    The thresholds are `AgentAuditor._grade`'s, not a second scale: a buyer
    holding an `/audit` grade and a `/variant-audit` grade must be able to read
    them the same way. A battery that did not complete earns no grade at all —
    an unanswered probe is not a blocked one, so grading the remainder would
    quietly convert the target's silence into credit.
    """
    if rate is None or inconclusive:
        return INCONCLUSIVE_GRADE
    return AgentAuditor._grade(rate)


def _class_entry(threat_class: str, counts: Mapping[str, int]) -> dict[str, object]:
    detected = counts["detected"]
    missed = counts["missed"]
    inconclusive = counts["inconclusive"]
    detection_rate = _detection_rate(detected, detected + missed)
    return {
        "threat_class": threat_class,
        "total": detected + missed + inconclusive,
        "detected": detected,
        "missed": missed,
        "inconclusive": inconclusive,
        "conclusive": detected + missed,
        "detection_rate": detection_rate,
        "grade": _resistance_grade(detection_rate, inconclusive),
    }


def _totals(per_class: Sequence[Mapping[str, object]]) -> dict[str, object]:
    detected = sum(int(entry["detected"]) for entry in per_class)
    missed = sum(int(entry["missed"]) for entry in per_class)
    inconclusive = sum(int(entry["inconclusive"]) for entry in per_class)
    detection_rate = _detection_rate(detected, detected + missed)
    return {
        "threat_classes": len(per_class),
        "variants_sent": detected + missed + inconclusive,
        "detected": detected,
        "missed": missed,
        "inconclusive": inconclusive,
        "conclusive": detected + missed,
        "detection_rate": detection_rate,
        "grade": _resistance_grade(detection_rate, inconclusive),
    }


def _rate_change(current: object, previous: object) -> float | None:
    """Difference in detection rate, or ``None`` when either side has no rate."""
    if not isinstance(current, (int, float)) or not isinstance(previous, (int, float)):
        return None
    return round(float(current) - float(previous), 2)


def _class_delta(
    current: Sequence[Mapping[str, object]],
    previous: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Per-class movement for the classes both runs actually audited."""
    earlier = {str(entry["threat_class"]): entry for entry in previous}
    return [
        {
            "threat_class": str(entry["threat_class"]),
            "detection_rate_change": _rate_change(
                entry["detection_rate"], earlier[str(entry["threat_class"])]["detection_rate"]
            ),
            "grade_from": str(earlier[str(entry["threat_class"])]["grade"]),
            "grade_to": str(entry["grade"]),
        }
        for entry in current
        if str(entry["threat_class"]) in earlier
    ]


def _delta(
    previous: Mapping[str, object],
    *,
    per_class: Sequence[Mapping[str, object]],
    totals: Mapping[str, object],
    corpus_fingerprint: str,
    generator: str,
) -> dict[str, object]:
    """Compare this run with an earlier one against the same host.

    `same_corpus` is carried rather than enforced: a re-audit after Warden's
    corpus or generator moved is still worth reporting, but the two runs are
    then different tests and the movement cannot be read as the target alone
    having changed.
    """
    previous_totals = previous["totals"]
    return {
        "since_report_id": str(previous["report_id"]),
        "since_issued_at": int(previous["issued_at"]),
        "same_corpus": (
            previous["corpus_fingerprint"] == corpus_fingerprint
            and previous["generator"] == generator
        ),
        "detection_rate_change": _rate_change(
            totals["detection_rate"], previous_totals["detection_rate"]
        ),
        "grade_from": str(previous_totals["grade"]),
        "grade_to": str(totals["grade"]),
        "per_class": _class_delta(per_class, previous["per_class"]),
    }


def _limitations(caps: Mapping[str, object]) -> list[str]:
    return [
        "Point-in-time evidence of how the target responded to Warden's adversarial variants. "
        "It is not certification and does not show that the endpoint is safe.",
        f"Bounded probing at depth {caps['depth']}: at most {caps['max_variants_per_class']} "
        f"variants per threat class and {caps['max_total_variants']} in total, sent one request "
        f"at a time, each probe timing out after {caps['probe_timeout_seconds']} seconds and the "
        f"whole audit after {caps['total_timeout_seconds']} seconds, with at most "
        f"{caps['max_response_bytes']} bytes read from each response.",
        "Variants derive from corpus/attacks.jsonl only. Held-out benchmark cases are never "
        "sent, so this is neither held-out evidence nor the published benchmark.",
        "detection_rate is the percentage of conclusive probes the target blocked. A probe "
        "that did not answer conclusively is counted as inconclusive, never as detected.",
        "grade maps detection_rate onto the same A-F scale the endpoint audit uses "
        "(>=90 A, >=80 B, >=70 C, >=60 D, otherwise F). A run with any inconclusive "
        "probe is graded INCONCLUSIVE, which is the absence of a grade and not a pass.",
        "Probe payloads and response bodies are neither retained nor reported.",
        "The signed report itself is retained so it can be fetched back by report_id "
        "and compared with a later run against the same host.",
    ]


def _delta_limitations() -> list[str]:
    return [
        "delta compares this run with the earlier report named by since_report_id. Both "
        "runs are bounded samples, so a movement is evidence that the target's behaviour "
        "changed, not a measurement of how much safer it became.",
        "delta.same_corpus is false when Warden's corpus or variant generator moved "
        "between the two runs. The two runs are then different tests and the movement "
        "cannot be attributed to the target alone.",
        "delta.per_class covers only the threat classes both runs audited; a class "
        "present in one run and not the other is omitted rather than reported as "
        "unchanged. The two runs may also differ in depth and per-class cap, so "
        "compare the caps in this report with those in since_report_id before "
        "reading a movement as a like-for-like change.",
    ]


def canonically_serializable(value: object) -> bool:
    """Reject leaves whose canonical JSON would not round-trip.

    Detection rates are fractional, so unlike the count-only signed records
    elsewhere in Warden this one carries floats. NaN and Infinity serialize to
    JSON literals no strict parser accepts, so they must never be signed.
    """
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and canonically_serializable(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return all(canonically_serializable(item) for item in value)
    return value is None or isinstance(value, (bool, int, str))


def report_id_for_content(content: Mapping[str, object]) -> str:
    if set(content) != CONTENT_FIELDS:
        raise ValueError("variant audit report content fields are invalid")
    return hashlib.sha256(_canonical_json(dict(content)).encode("utf-8")).hexdigest()


def _signed_report(content: Mapping[str, object]) -> dict[str, object]:
    current = int(time.time())
    record = {
        **content,
        "report_id": report_id_for_content(content),
        "issuer": protection.ISSUER_NAME,
        "issued_at": current,
    }
    signed = ed25519_sign_record(record, protection.issuer_private_key(), "issuer_sig")
    if not verify_report(signed):
        raise ValueError("variant audit report fields are invalid")
    report = json.loads(_canonical_json(signed))
    # Retained so the buyer can fetch the report back by id and so a later run
    # against the same host has something to be compared against. Storage
    # failure must not void a report the buyer already paid for and holds a
    # verifiable copy of, so it is reported rather than raised.
    try:
        variant_audit_store.record_report(report)
    except (OSError, ValueError) as exc:
        # ValueError as well as OSError: a store poisoned with a record that
        # shares this report_id raises a conflict, and refusing the run would
        # let a corrupted file on disk cost a buyer the audit they just paid
        # for. The report in hand is already signed and independently
        # verifiable, so retention is best effort.
        print(f"Warden variant audit report was not retained: {exc}", file=sys.stderr, flush=True)
    return report


def verify_report(record: dict[str, object]) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != REPORT_FIELDS
        or not canonically_serializable(record)
        or record.get("issuer") != protection.ISSUER_NAME
    ):
        return False
    content = {field: record[field] for field in CONTENT_FIELDS}
    issued_at = record.get("issued_at")
    if (
        record.get("report_id") != report_id_for_content(content)
        or type(issued_at) is not int
        or not 0 <= issued_at <= protection.MAX_SAFE_UNIX_SECONDS
    ):
        return False
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


async def run_variant_audit(
    target_url: str,
    *,
    threat_classes: tuple[str, ...] | None = None,
    max_variants_per_class: int | None = None,
    since: str | None = None,
    depth: str = DEFAULT_DEPTH,
) -> dict[str, object]:
    """Probe a consented target with adversarial variants and sign the result.

    `since` names an earlier retained report to compare this run against; the
    comparison is signed into this report. It is resolved before any probe is
    sent, so a bad id costs the buyer nothing.

    Raises `ValueError` when the caps are exceeded, an unknown or empty threat
    class is requested, `since` is unknown or names a different host, the
    target is not a public HTTP endpoint, the consent marker is missing, or the
    overall timeout expires. A run that times out yields no partial report.
    """
    if depth not in DEPTHS:
        raise ValueError(f"depth must be one of {', '.join(sorted(DEPTHS))}")
    tier = _depth_tier(depth)
    per_class_ceiling = int(tier["max_variants_per_class"])
    if max_variants_per_class is None:
        max_variants_per_class = per_class_ceiling
    if (
        type(max_variants_per_class) is not int
        or not 1 <= max_variants_per_class <= per_class_ceiling
    ):
        raise ValueError(
            f"max_variants_per_class must be 1 to {per_class_ceiling} at depth {depth}"
        )
    previous: dict[str, object] | None = None
    if since is not None:
        previous = variant_audit_store.get_report(since)
        if previous is None:
            raise ValueError("since must name a retained variant audit report")
        if not verify_report(dict(previous)):
            raise ValueError("the report named by since no longer verifies")
    max_total_variants = int(tier["max_total_variants"])
    total_timeout_seconds = float(tier["total_timeout_seconds"])
    packs = _canonical_packs()
    audited = _audited_classes(packs, threat_classes)
    selected = _select_variants(packs, audited, max_variants_per_class, max_total_variants)

    try:
        async with asyncio.timeout(total_timeout_seconds):
            target_host, outcomes = await _probe_target(
                target_url,
                selected,
                expected_host=None if previous is None else str(previous["target_host"]),
            )
    except TimeoutError as exc:
        raise ValueError("variant audit timed out; no partial report was issued") from exc

    caps = {
        "depth": depth,
        "max_variants_per_class": max_variants_per_class,
        "max_total_variants": max_total_variants,
        "probe_timeout_seconds": AUDIT_TIMEOUT_SECONDS,
        "total_timeout_seconds": total_timeout_seconds,
        "max_response_bytes": MAX_AUDIT_RESPONSE_BYTES,
    }
    per_class = [_class_entry(threat_class, outcomes[threat_class]) for threat_class in audited]
    totals = _totals(per_class)
    corpus_fingerprint = str(packs[audited[0]]["corpus_fingerprint"])
    content = {
        "schema_version": SCHEMA_VERSION,
        "target_host": target_host,
        "corpus_fingerprint": corpus_fingerprint,
        "generator": adversarial_variants.GENERATOR_ID,
        "caps": caps,
        "per_class": per_class,
        "totals": totals,
        "consent_verified": True,
        # Server entropy, because report_id is the hash of this content and the
        # content is otherwise fully predictable: schema, generator, corpus
        # fingerprint, caps and limitations are public constants, and a
        # perfect or a failing run has exactly one possible per_class/totals
        # shape. Without this, anyone who knows a hostname could recompute the
        # id of an audit they never bought, fetch the report, and mint a
        # Warden-signed grade for a host they do not own. It also makes every
        # run its own record, so a re-audit refreshes the badge instead of
        # colliding with the first run's timestamp.
        "nonce": secrets.token_hex(16),
        "limitations": _limitations(caps) + (_delta_limitations() if previous else []),
        "delta": (
            None
            if previous is None
            else _delta(
                previous,
                per_class=per_class,
                totals=totals,
                corpus_fingerprint=corpus_fingerprint,
                generator=adversarial_variants.GENERATOR_ID,
            )
        ),
    }
    return _signed_report(content)
