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
import time
from collections.abc import Mapping, Sequence

import httpx

from warden import adversarial_variants, protection
from warden.auditor import (
    AUDIT_TIMEOUT_SECONDS,
    MAX_AUDIT_RESPONSE_BYTES,
    AgentAuditor,
    AuditOutcome,
)
from warden.badges import _canonical_json, ed25519_sign_record, ed25519_verify_record

SCHEMA_VERSION = 1
MAX_VARIANTS_PER_CLASS = 25
MAX_TOTAL_VARIANTS = 150
TOTAL_TIMEOUT_SECONDS = 180.0
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
    }
)
REPORT_FIELDS = CONTENT_FIELDS | {"report_id", "issuer", "issued_at", "issuer_sig"}


def _canonical_packs() -> dict[str, dict[str, object]]:
    """Build the per-class packs from the canonical training corpus.

    `build_variant_packs` re-checks training/held-out separation on every build,
    so an audit run cannot start from a corpus state that leaks held-out rows.
    """
    return adversarial_variants.build_variant_packs(
        training_attacks_path=adversarial_variants.TRAINING_ATTACKS_PATH,
        training_benign_path=adversarial_variants.TRAINING_BENIGN_PATH,
        held_out_attacks_path=adversarial_variants.HELD_OUT_ATTACKS_PATH,
        held_out_benign_path=adversarial_variants.HELD_OUT_BENIGN_PATH,
    )


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
    remaining = MAX_TOTAL_VARIANTS
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
) -> tuple[str, dict[str, dict[str, int]]]:
    auditor = AgentAuditor()
    try:
        async with asyncio.timeout(AUDIT_TIMEOUT_SECONDS):
            connect_url, host_header, parsed_target = await auditor._validate_public_http_url(
                target_url
            )
    except TimeoutError as exc:
        raise ValueError("target_url validation timed out") from exc
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
    return host_header.rstrip(".").casefold(), outcomes


def _detection_rate(detected: int, conclusive: int) -> float | None:
    """Return ``None`` rather than an unearned zero when nothing was conclusive."""
    return round((detected / conclusive) * 100, 2) if conclusive else None


def _class_entry(threat_class: str, counts: Mapping[str, int]) -> dict[str, object]:
    detected = counts["detected"]
    missed = counts["missed"]
    inconclusive = counts["inconclusive"]
    return {
        "threat_class": threat_class,
        "total": detected + missed + inconclusive,
        "detected": detected,
        "missed": missed,
        "inconclusive": inconclusive,
        "conclusive": detected + missed,
        "detection_rate": _detection_rate(detected, detected + missed),
    }


def _totals(per_class: Sequence[Mapping[str, object]]) -> dict[str, object]:
    detected = sum(int(entry["detected"]) for entry in per_class)
    missed = sum(int(entry["missed"]) for entry in per_class)
    inconclusive = sum(int(entry["inconclusive"]) for entry in per_class)
    return {
        "threat_classes": len(per_class),
        "variants_sent": detected + missed + inconclusive,
        "detected": detected,
        "missed": missed,
        "inconclusive": inconclusive,
        "conclusive": detected + missed,
        "detection_rate": _detection_rate(detected, detected + missed),
    }


def _limitations(caps: Mapping[str, object]) -> list[str]:
    return [
        "Point-in-time evidence of how the target responded to Warden's adversarial variants. "
        "It is not certification and does not show that the endpoint is safe.",
        f"Bounded probing: at most {caps['max_variants_per_class']} variants per threat class "
        f"and {caps['max_total_variants']} in total, sent one request at a time, each probe "
        f"timing out after {caps['probe_timeout_seconds']} seconds and the whole audit after "
        f"{caps['total_timeout_seconds']} seconds, with at most {caps['max_response_bytes']} "
        "bytes read from each response.",
        "Variants derive from corpus/attacks.jsonl only. Held-out benchmark cases are never "
        "sent, so this is neither held-out evidence nor the published benchmark.",
        "detection_rate is the percentage of conclusive probes the target blocked. A probe "
        "that did not answer conclusively is counted as inconclusive, never as detected.",
        "Probe payloads and response bodies are neither retained nor reported.",
    ]


def _canonically_serializable(value: object) -> bool:
    """Reject leaves whose canonical JSON would not round-trip.

    Detection rates are fractional, so unlike the count-only signed records
    elsewhere in Warden this one carries floats. NaN and Infinity serialize to
    JSON literals no strict parser accepts, so they must never be signed.
    """
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _canonically_serializable(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return all(_canonically_serializable(item) for item in value)
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
    return json.loads(_canonical_json(signed))


def verify_report(record: dict[str, object]) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != REPORT_FIELDS
        or not _canonically_serializable(record)
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
    max_variants_per_class: int = MAX_VARIANTS_PER_CLASS,
) -> dict[str, object]:
    """Probe a consented target with adversarial variants and sign the result.

    Raises `ValueError` when the caps are exceeded, an unknown or empty threat
    class is requested, the target is not a public HTTP endpoint, the consent
    marker is missing, or the overall timeout expires. A run that times out
    yields no partial report.
    """
    if (
        type(max_variants_per_class) is not int
        or not 1 <= max_variants_per_class <= MAX_VARIANTS_PER_CLASS
    ):
        raise ValueError(f"max_variants_per_class must be 1 to {MAX_VARIANTS_PER_CLASS}")
    packs = _canonical_packs()
    audited = _audited_classes(packs, threat_classes)
    selected = _select_variants(packs, audited, max_variants_per_class)

    try:
        async with asyncio.timeout(TOTAL_TIMEOUT_SECONDS):
            target_host, outcomes = await _probe_target(target_url, selected)
    except TimeoutError as exc:
        raise ValueError("variant audit timed out; no partial report was issued") from exc

    caps = {
        "max_variants_per_class": max_variants_per_class,
        "max_total_variants": MAX_TOTAL_VARIANTS,
        "probe_timeout_seconds": AUDIT_TIMEOUT_SECONDS,
        "total_timeout_seconds": TOTAL_TIMEOUT_SECONDS,
        "max_response_bytes": MAX_AUDIT_RESPONSE_BYTES,
    }
    per_class = [_class_entry(threat_class, outcomes[threat_class]) for threat_class in audited]
    content = {
        "schema_version": SCHEMA_VERSION,
        "target_host": target_host,
        "corpus_fingerprint": str(packs[audited[0]]["corpus_fingerprint"]),
        "generator": adversarial_variants.GENERATOR_ID,
        "caps": caps,
        "per_class": per_class,
        "totals": _totals(per_class),
        "consent_verified": True,
        "limitations": _limitations(caps),
    }
    return _signed_report(content)
