"""Contracts for the public ASP Payload Security Standard draft."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from warden.audit_attestations import (
    ATTESTATION_TTL_SECONDS,
    PREDICATE_TYPE,
    SPEC_VERSION,
)
from warden.auditor import (
    AUDIT_BATTERY_PATH,
    AUDIT_BATTERY_SHA256,
    AUDIT_BATTERY_SIZE,
    BENIGN_CONTROLS,
    AuditOutcome,
)
from warden.core.verdict import ReasonCode, VERDICT_ORDER
from warden.models import MAX_PAYLOAD_LENGTH


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "spec" / "payload-security-profile-v0.1.json"
STANDARD_PATH = ROOT / "spec" / "ASP-PAYLOAD-SECURITY-STANDARD.md"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_machine_profile_matches_runtime_and_immutable_battery() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    battery = json.loads(AUDIT_BATTERY_PATH.read_text(encoding="utf-8"))

    assert profile["profile"] == "asp-payload-security/0.1"
    assert profile["status"] == "public-draft"
    assert profile["input"] == {
        "type": "string",
        "blank_allowed": False,
        "max_characters": MAX_PAYLOAD_LENGTH,
        "silent_truncation_allowed": False,
    }
    assert profile["decisions"]["values"] == list(VERDICT_ORDER)
    assert profile["decisions"]["allow_is_safety_guarantee"] is False
    assert profile["decisions"]["sanitize_requires_exact_transformed_payload"] is True
    assert profile["decisions"]["block_requires_action_withheld"] is True
    assert set(profile["reason_codes"]) == {reason.value for reason in ReasonCode}

    audit = profile["endpoint_audit"]
    assert audit["battery_id"] == battery["battery_id"]
    assert audit["battery_version"] == battery["version"]
    assert audit["battery_sha256"] == AUDIT_BATTERY_SHA256
    assert hashlib.sha256(_canonical(battery)).hexdigest() == AUDIT_BATTERY_SHA256
    assert audit["attack_probes"] == AUDIT_BATTERY_SIZE == len(battery["probes"])
    assert audit["benign_controls"] == len(BENIGN_CONTROLS)
    assert audit["outcomes"] == [outcome.value for outcome in AuditOutcome]
    assert audit["caller_prompts_affect_signed_grade"] is False
    assert audit["complete_conclusive_run_required"] is True
    assert audit["all_benign_controls_must_pass"] is True
    assert audit["consent_required_for_signed_evidence"] is True


def test_machine_profile_matches_portable_audit_evidence() -> None:
    evidence = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))["portable_evidence"]

    assert evidence == {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "point_in_time": True,
        "certification": False,
        "ttl_seconds": ATTESTATION_TTL_SECONDS,
        "signature": "Ed25519",
        "transparency_lifecycle_required": True,
    }


def test_standard_publishes_normative_enforcement_and_evidence_limits() -> None:
    standard = STANDARD_PATH.read_text(encoding="utf-8")
    normalized = " ".join(standard.split())

    for required in (
        "MUST return exactly one decision: `ALLOW`, `SANITIZE`, or `BLOCK`",
        "The original payload MUST NOT be used",
        "the consequential action MUST NOT be invoked",
        "It is not a universal safety guarantee",
        "point-in-time evidence, not certification",
        "issues no grade or signed audit evidence",
        "Changing any probe or benign control requires a new battery version",
    ):
        assert required in normalized


def test_site_builder_publishes_the_standard_and_machine_profile(tmp_path: Path) -> None:
    public_spec = tmp_path / "spec" / "APA-SPEC.md"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/build_site.py",
            "--docs-output",
            str(tmp_path / "docs"),
            "--spec-output",
            str(public_spec),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert public_spec.read_bytes() == (ROOT / "spec" / "APA-SPEC.md").read_bytes()
    for name in (
        "ASP-PAYLOAD-SECURITY-STANDARD.md",
        "payload-security-profile-v0.1.json",
    ):
        assert (public_spec.parent / name).read_bytes() == (ROOT / "spec" / name).read_bytes()
