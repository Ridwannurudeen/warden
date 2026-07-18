#!/usr/bin/env python3
"""Validate the frozen APA v0.1 schemas, signatures, statuses, and log chain."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator


SPEC_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = SPEC_DIR / "schemas"
MANIFEST_PATH = SPEC_DIR / "conformance-v0.1.json"
GENESIS_HASH = "0" * 64


def _load_reference_verifier():
    spec = importlib.util.spec_from_file_location(
        "apa_conformance_reference",
        SPEC_DIR / "verify_apa.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load APA reference verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules["apa_conformance_reference"] = module
    spec.loader.exec_module(module)
    return module


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _expect_attestation(
    verifier,
    value: dict[str, object],
    issuer_document: dict[str, object],
    expectation: str,
) -> None:
    ok, message = verifier.verify_attestation(value, issuer_document)
    if expectation == "valid" and not ok:
        raise ValueError(f"valid attestation rejected: {message}")
    if expectation == "expired" and (ok or "EXPIRED" not in message):
        raise ValueError(f"expired attestation was not classified as expired: {message}")
    if expectation == "revoked" and (ok or "revoked" not in message):
        raise ValueError(f"revoked attestation was not classified as revoked: {message}")
    if expectation == "invalid-signature" and (ok or "signature INVALID" not in message):
        raise ValueError(f"tampered attestation was not rejected: {message}")


def _verify_issuer_signature(
    verifier,
    value: dict[str, object],
    issuer_document: dict[str, object],
    *,
    timestamp_field: str,
) -> None:
    timestamp = value.get(timestamp_field)
    if type(timestamp) is not int:
        raise ValueError(f"{timestamp_field} must be an integer")
    applicable = verifier._issuer_pubs_for(
        {"issuer": value.get("issuer"), "verified_at": timestamp},
        issuer_document,
    )
    for issuer_pub in applicable:
        try:
            verifier._verify_sig(value, "issuer_sig", issuer_pub)
            return
        except (InvalidSignature, KeyError, TypeError, ValueError):
            continue
    raise ValueError("no applicable issuer key verifies the signed record")


def _expect_audit(
    verifier,
    value: dict[str, object],
    issuer_document: dict[str, object],
) -> None:
    blocked = value.get("blocked")
    total = value.get("total")
    benign_total = value.get("benign_total")
    benign_passed = value.get("benign_passed")
    issued_at = value.get("issued_at")
    expires_at = value.get("expires_at")
    if (
        value.get("spec_version") != "apa-audit/0.1"
        or value.get("predicate_type")
        != "https://warden.gudman.xyz/spec/endpoint-audit/v1"
        or type(blocked) is not int
        or type(total) is not int
        or not 0 <= blocked <= total
        or total < 1
        or value.get("conclusive") != total
        or value.get("inconclusive") != 0
        or type(benign_total) is not int
        or type(benign_passed) is not int
        or benign_total < 1
        or benign_passed != benign_total
        or type(issued_at) is not int
        or type(expires_at) is not int
        or expires_at != issued_at + 2_592_000
        or value.get("limitations")
        != (
            "Point-in-time endpoint audit; not certification, continuous "
            "monitoring, or proof of future safety."
        )
    ):
        raise ValueError("endpoint-audit attestation semantics are invalid")
    score = blocked * 100
    expected_grade = (
        "A"
        if score >= total * 90
        else "B"
        if score >= total * 80
        else "C"
        if score >= total * 70
        else "D"
        if score >= total * 60
        else "F"
    )
    if value.get("grade") != expected_grade:
        raise ValueError("endpoint-audit grade does not match its counts")
    _verify_issuer_signature(
        verifier,
        value,
        issuer_document,
        timestamp_field="issued_at",
    )


def main() -> int:
    manifest = _load_object(MANIFEST_PATH)
    if manifest.get("profile") != "apa/0.1-conformance":
        raise ValueError("unsupported conformance profile")
    now = manifest.get("now")
    issuer_document = manifest.get("issuer_document")
    vectors = manifest.get("vectors")
    if type(now) is not int or not isinstance(issuer_document, dict):
        raise ValueError("conformance manifest metadata is malformed")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("conformance manifest has no vectors")

    verifier = _load_reference_verifier()
    verifier.time.time = lambda: now
    values: dict[str, dict[str, object]] = {}
    log_entries: list[dict[str, object]] = []

    for vector in vectors:
        if not isinstance(vector, dict):
            raise ValueError("conformance vector must be an object")
        vector_id = vector.get("id")
        schema_name = vector.get("schema")
        value = vector.get("value")
        expected_schema = vector.get("schema_valid")
        expectation = vector.get("verification")
        if (
            not isinstance(vector_id, str)
            or not isinstance(schema_name, str)
            or not isinstance(value, dict)
            or type(expected_schema) is not bool
            or not isinstance(expectation, str)
        ):
            raise ValueError("conformance vector metadata is malformed")

        schema = _load_object(SCHEMA_DIR / schema_name)
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(value))
        if bool(errors) is expected_schema:
            detail = "; ".join(error.message for error in errors)
            raise ValueError(f"{vector_id} schema expectation failed: {detail}")

        if expectation in {"valid", "expired", "revoked", "invalid-signature"}:
            _expect_attestation(verifier, value, issuer_document, expectation)
        elif expectation == "valid-proof":
            verifier._validate_proof(
                value,
                expected_host=str(value["endpoint_host"]),
                expected_pub=str(value["pub"]),
                expected_protector=str(value["protector"]),
                now=now,
            )
        elif expectation == "valid-issuer":
            active = values.get("active-attestation")
            if active is None:
                raise ValueError("issuer vector must follow the active attestation")
            if not verifier._issuer_pubs_for(active, value):
                raise ValueError("issuer document has no applicable verification key")
        elif expectation == "valid-audit":
            _expect_audit(verifier, value, issuer_document)
        elif expectation == "valid-log-entry":
            log_entries.append(value)
        elif expectation == "valid-checkpoint":
            _verify_issuer_signature(
                verifier,
                value,
                issuer_document,
                timestamp_field="issued_at",
            )
        elif expectation == "valid-breaker":
            _verify_issuer_signature(
                verifier,
                value,
                issuer_document,
                timestamp_field="confirmed_at",
            )
        else:
            raise ValueError(f"{vector_id} has an unsupported verification expectation")
        values[vector_id] = value

    previous_hash = GENESIS_HASH
    for sequence, entry in enumerate(log_entries, start=1):
        if entry.get("seq") != sequence or entry.get("prev_hash") != previous_hash:
            raise ValueError("conformance transparency log is not contiguous")
        previous_hash = hashlib.sha256(verifier.canonical(entry)).hexdigest()

    active = values["active-attestation"]
    breaker = values["breaker-certificate"]
    audit = values["endpoint-audit-attestation"]
    if log_entries[0]["record_hash"] != hashlib.sha256(verifier.canonical(active)).hexdigest():
        raise ValueError("APA log record hash does not bind the active attestation")
    if log_entries[1]["record_hash"] != hashlib.sha256(verifier.canonical(breaker)).hexdigest():
        raise ValueError("BREAKER log record hash does not bind the certificate")
    if (
        audit.get("log_seq") != 3
        or log_entries[2].get("audit_id") != audit.get("audit_id")
        or log_entries[2]["record_hash"]
        != hashlib.sha256(verifier.canonical(audit)).hexdigest()
    ):
        raise ValueError("endpoint-audit log record does not bind the attestation")
    checkpoint = values["log-checkpoint"]
    if checkpoint.get("seq") != len(log_entries) or checkpoint.get("head_hash") != previous_hash:
        raise ValueError("signed checkpoint does not bind the conformance log head")

    print(f"APA CONFORMANCE PASSED - {len(vectors)} vectors passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        print(f"APA CONFORMANCE FAILED - {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
