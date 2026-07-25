"""Verify and run signed Hardening Pack vectors without producing a grade."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from warden_guard.apa import b64u_decode, b64u_encode, canonical
from warden_guard.client import ScanResult, WardenClient, WardenError

MAX_PACK_BYTES = 2_000_000
MAX_VECTOR_PAYLOAD_LENGTH = 100_000
MAX_LOG_SUFFIX_ENTRIES = 10_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
PUBLIC_ORIGIN = "https://warden.gudman.xyz"
_PACK_PATH = re.compile(r"^/apa/hardening/([0-9a-f]{64})$")
_LOWER_HEX_16 = re.compile(r"^[0-9a-f]{16}$")
_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERDICTS = frozenset({"ALLOW", "SANITIZE", "BLOCK"})
_DEPTHS = frozenset({"fast", "thorough"})
_PACK_CONTENT_FIELDS = {
    "schema_version",
    "audit_id",
    "target_host",
    "battery_id",
    "battery_version",
    "observed_on",
    "corpus_fingerprint",
    "addressed_classes",
    "remediation",
    "integration",
    "limitations",
    "message",
}
_PACK_FIELDS = _PACK_CONTENT_FIELDS | {
    "spec_version",
    "predicate_type",
    "pack_id",
    "issuer",
    "issued_at",
    "expires_at",
    "log_seq",
    "issuer_sig",
}
_REMEDIATION_FIELDS = {
    "attack_class",
    "missed",
    "blocked",
    "total",
    "summary",
    "pattern_families",
    "analyzers",
    "example_attacks",
    "taxonomy_ids",
}
_EXAMPLE_FIELDS = {
    "id",
    "payload",
    "expected_verdict",
    "expected_classes",
    "depth",
    "context",
    "source_id",
    "source_revision",
    "source_path",
    "source_record_id",
    "source_url",
    "source_file_sha256",
    "license_spdx",
    "license_url",
}
_BUNDLE_FIELDS = {
    "pack",
    "status",
    "verified",
    "revoked_at",
    "issuer_document",
    "log_suffix",
    "checkpoint",
    "limitations",
}
_HARDENING_LOG_FIELDS = {
    "seq",
    "ts",
    "event",
    "record_type",
    "pack_id",
    "audit_id",
    "record_hash",
    "prev_hash",
}


@dataclass(frozen=True)
class SelfTestVector:
    vector_id: str
    attack_class: str
    payload: str
    expected_verdict: str
    expected_classes: tuple[str, ...] = ()
    depth: str = "fast"
    expected_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifiedHardeningPack:
    pack_id: str
    vectors: tuple[SelfTestVector, ...]
    message: str = ""


class HardeningPackVerifier(Protocol):
    def __call__(
        self,
        document: object,
        *,
        source: str,
    ) -> VerifiedHardeningPack: ...


class VectorScanner(Protocol):
    def __call__(
        self,
        payload: str,
        *,
        depth: str,
        expected_addresses: list[str],
    ) -> ScanResult: ...


@dataclass(frozen=True)
class SelfTestFailure:
    vector_id: str
    attack_class: str
    expected_verdict: str
    observed_verdict: str

    def as_dict(self) -> dict[str, str]:
        return {
            "vector_id": self.vector_id,
            "attack_class": self.attack_class,
            "expected_verdict": self.expected_verdict,
            "observed_verdict": self.observed_verdict,
        }


@dataclass(frozen=True)
class SelfTestClassResult:
    total: int
    passed: int
    failed: int

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
        }


@dataclass(frozen=True)
class SelfTestReport:
    pack_id: str
    total: int
    passed: int
    failed: int
    no_op: bool
    message: str
    classes: dict[str, SelfTestClassResult]
    failures: tuple[SelfTestFailure, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "pack_id": self.pack_id,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "no_op": self.no_op,
            "message": self.message,
            "classes": {
                attack_class: result.as_dict()
                for attack_class, result in sorted(self.classes.items())
            },
            "failures": [failure.as_dict() for failure in self.failures],
        }


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _parse_json(raw: bytes, *, label: str) -> object:
    if len(raw) > MAX_PACK_BYTES:
        raise ValueError(f"{label} exceeds the size limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is invalid JSON") from exc


def _is_safe_integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_SAFE_INTEGER


def _canonical_signature(value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith("sig:"):
        raise ValueError("signed evidence has a malformed signature")
    try:
        decoded = b64u_decode(value)
    except ValueError as exc:
        raise ValueError("signed evidence has a malformed signature") from exc
    if len(decoded) != 64 or b64u_encode(decoded, "sig") != value:
        raise ValueError("signed evidence has a malformed signature")
    return decoded


def _issuer_keys(document: object) -> tuple[dict[str, object], ...]:
    if (
        not isinstance(document, dict)
        or set(document) != {"issuer", "keys"}
        or document.get("issuer") != "warden"
        or not isinstance(document.get("keys"), list)
        or not document["keys"]
    ):
        raise ValueError("issuer document is invalid")
    validated: list[dict[str, object]] = []
    kids: set[str] = set()
    pubs: set[str] = set()
    previous_not_after = -1
    for key in document["keys"]:
        if not isinstance(key, dict) or set(key) != {"kid", "pub", "not_after"}:
            raise ValueError("issuer document is invalid")
        kid = key["kid"]
        pub = key["pub"]
        not_after = key["not_after"]
        if (
            not isinstance(kid, str)
            or not kid
            or kid in kids
            or not isinstance(pub, str)
            or not pub.startswith("ed25519:")
            or pub in pubs
            or not _is_safe_integer(not_after)
            or not_after <= previous_not_after
        ):
            raise ValueError("issuer document is invalid")
        try:
            public_bytes = b64u_decode(pub)
        except ValueError as exc:
            raise ValueError("issuer document is invalid") from exc
        if len(public_bytes) != 32 or b64u_encode(public_bytes, "ed25519") != pub:
            raise ValueError("issuer document is invalid")
        kids.add(kid)
        pubs.add(pub)
        previous_not_after = not_after
        validated.append(key)
    if validated[-1]["not_after"] != MAX_SAFE_INTEGER:
        raise ValueError("issuer document has no current key")
    return tuple(validated)


def _verify_issuer_signature(
    record: dict[str, object],
    *,
    time_field: str,
    keys: tuple[dict[str, object], ...],
) -> None:
    signed_at = record.get(time_field)
    if not _is_safe_integer(signed_at):
        raise ValueError("signed evidence time is invalid")
    signature = _canonical_signature(record.get("issuer_sig"))
    material = {key: value for key, value in record.items() if key != "issuer_sig"}
    for key in keys:
        if signed_at > key["not_after"]:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(b64u_decode(key["pub"])).verify(
                signature,
                canonical(material),
            )
        except InvalidSignature:
            continue
        return
    raise ValueError("signed evidence does not match issuer history")


def _validate_example(
    example: object,
    *,
    attack_class: str,
) -> SelfTestVector:
    if not isinstance(example, dict) or set(example) != _EXAMPLE_FIELDS:
        raise ValueError("Hardening Pack example fields are invalid")
    vector_id = example.get("id")
    payload = example.get("payload")
    verdict = example.get("expected_verdict")
    expected_classes = example.get("expected_classes")
    depth = example.get("depth")
    context = example.get("context")
    if (
        not isinstance(vector_id, str)
        or not vector_id
        or len(vector_id) > 256
        or not isinstance(payload, str)
        or not payload
        or len(payload) > MAX_VECTOR_PAYLOAD_LENGTH
        or verdict not in _VERDICTS
        or not isinstance(expected_classes, list)
        or not expected_classes
        or not all(isinstance(value, str) and value for value in expected_classes)
        or attack_class not in expected_classes
        or depth not in _DEPTHS
        or not isinstance(context, dict)
        or set(context) != {"expected_addresses"}
        or not isinstance(context["expected_addresses"], list)
        or len(context["expected_addresses"]) > 20
        or not all(
            isinstance(address, str) and address
            for address in context["expected_addresses"]
        )
    ):
        raise ValueError("Hardening Pack example is invalid")
    try:
        payload.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Hardening Pack example payload is invalid") from exc
    licenses = example.get("license_spdx")
    if (
        not isinstance(licenses, list)
        or not licenses
        or not all(isinstance(value, str) and value for value in licenses)
    ):
        raise ValueError("Hardening Pack example license is invalid")
    return SelfTestVector(
        vector_id=vector_id,
        attack_class=attack_class,
        payload=payload,
        expected_verdict=verdict,
        expected_classes=tuple(expected_classes),
        depth=depth,
        expected_addresses=tuple(context["expected_addresses"]),
    )


def _verify_pack(
    record: object,
    *,
    keys: tuple[dict[str, object], ...],
    now: int,
) -> VerifiedHardeningPack:
    if (
        not isinstance(record, dict)
        or set(record) != _PACK_FIELDS
        or record.get("spec_version") != "warden-hardening-pack/0.1"
        or record.get("predicate_type")
        != "https://warden.gudman.xyz/spec/hardening-pack/v1"
        or record.get("issuer") != "warden"
        or record.get("schema_version") != 1
        or not isinstance(record.get("pack_id"), str)
        or _LOWER_HEX_64.fullmatch(record["pack_id"]) is None
        or not isinstance(record.get("audit_id"), str)
        or _LOWER_HEX_16.fullmatch(record["audit_id"]) is None
        or not isinstance(record.get("corpus_fingerprint"), str)
        or _SHA256.fullmatch(record["corpus_fingerprint"]) is None
        or not _is_safe_integer(record.get("issued_at"))
        or not _is_safe_integer(record.get("expires_at"))
        or record["expires_at"] < record["issued_at"]
        or not _is_safe_integer(record.get("log_seq"), minimum=1)
    ):
        raise ValueError("Hardening Pack fields are invalid")
    content = {field: record[field] for field in _PACK_CONTENT_FIELDS}
    expected_id = hashlib.sha256(canonical(content)).hexdigest()
    if record["pack_id"] != expected_id:
        raise ValueError("Hardening Pack identifier does not match its content")
    _verify_issuer_signature(record, time_field="issued_at", keys=keys)
    if now > record["expires_at"]:
        raise ValueError("Hardening Pack is expired")

    addressed = record.get("addressed_classes")
    remediation = record.get("remediation")
    if (
        not isinstance(addressed, list)
        or not all(isinstance(value, str) and value for value in addressed)
        or addressed != sorted(set(addressed))
        or not isinstance(remediation, list)
    ):
        raise ValueError("Hardening Pack remediation is invalid")
    vectors: list[SelfTestVector] = []
    remediation_classes: list[str] = []
    for entry in remediation:
        if not isinstance(entry, dict) or set(entry) != _REMEDIATION_FIELDS:
            raise ValueError("Hardening Pack remediation is invalid")
        attack_class = entry.get("attack_class")
        examples = entry.get("example_attacks")
        if (
            not isinstance(attack_class, str)
            or not attack_class
            or not isinstance(examples, list)
        ):
            raise ValueError("Hardening Pack remediation is invalid")
        remediation_classes.append(attack_class)
        vectors.extend(
            _validate_example(example, attack_class=attack_class)
            for example in examples
        )
    if remediation_classes != addressed:
        raise ValueError("Hardening Pack addressed classes do not match remediation")
    vector_ids = [vector.vector_id for vector in vectors]
    if len(vector_ids) != len(set(vector_ids)):
        raise ValueError("Hardening Pack contains a duplicate vector id")
    message = record.get("message")
    if not isinstance(message, str) or not message:
        raise ValueError("Hardening Pack message is invalid")
    return VerifiedHardeningPack(
        pack_id=record["pack_id"],
        vectors=tuple(vectors),
        message=message,
    )


def _verify_checkpoint(
    checkpoint: object,
    *,
    keys: tuple[dict[str, object], ...],
) -> dict[str, object]:
    fields = {
        "spec_version",
        "issuer",
        "seq",
        "head_hash",
        "issued_at",
        "issuer_sig",
    }
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != fields
        or checkpoint.get("spec_version") != "apa-log/0.1"
        or checkpoint.get("issuer") != "warden"
        or not _is_safe_integer(checkpoint.get("seq"))
        or not isinstance(checkpoint.get("head_hash"), str)
        or _LOWER_HEX_64.fullmatch(checkpoint["head_hash"]) is None
    ):
        raise ValueError("Hardening Pack checkpoint is invalid")
    _verify_issuer_signature(checkpoint, time_field="issued_at", keys=keys)
    return checkpoint


def _verify_inclusion(
    *,
    record: dict[str, object],
    log_suffix: object,
    checkpoint: dict[str, object],
) -> bool:
    if (
        not isinstance(log_suffix, list)
        or not log_suffix
        or len(log_suffix) > MAX_LOG_SUFFIX_ENTRIES
    ):
        raise ValueError("Hardening Pack log suffix is invalid")
    record_hash = hashlib.sha256(canonical(record)).hexdigest()
    previous_hash: str | None = None
    revoked = False
    for index, entry in enumerate(log_suffix):
        if not isinstance(entry, dict):
            raise ValueError("Hardening Pack log suffix is invalid")
        seq = entry.get("seq")
        prev_hash = entry.get("prev_hash")
        if (
            not _is_safe_integer(seq, minimum=1)
            or seq != record["log_seq"] + index
            or not isinstance(prev_hash, str)
            or _LOWER_HEX_64.fullmatch(prev_hash) is None
            or (
                previous_hash is not None
                and prev_hash != previous_hash
            )
        ):
            raise ValueError("Hardening Pack log suffix is invalid")
        if index == 0:
            expected = {
                "seq": record["log_seq"],
                "ts": record["issued_at"],
                "event": "hardening-pack-issued",
                "record_type": "hardening-pack",
                "pack_id": record["pack_id"],
                "audit_id": record["audit_id"],
                "record_hash": record_hash,
                "prev_hash": prev_hash,
            }
            if entry != expected:
                raise ValueError("Hardening Pack inclusion entry is invalid")
        elif (
            entry.get("record_type") == "hardening-pack"
            and entry.get("pack_id") == record["pack_id"]
        ):
            if (
                set(entry) != _HARDENING_LOG_FIELDS
                or entry.get("event") != "hardening-pack-revoked"
                or entry.get("audit_id") != record["audit_id"]
                or entry.get("record_hash") != record_hash
                or revoked
            ):
                raise ValueError("Hardening Pack revocation evidence is invalid")
            revoked = True
        previous_hash = hashlib.sha256(canonical(entry)).hexdigest()
    if (
        checkpoint["seq"] != log_suffix[-1]["seq"]
        or checkpoint["head_hash"] != previous_hash
        or checkpoint["issued_at"] != log_suffix[-1].get("ts")
    ):
        raise ValueError("Hardening Pack checkpoint does not include the pack")
    return revoked


def verify_evidence_bundle(
    document: object,
    *,
    source: str,
    now: int | None = None,
) -> VerifiedHardeningPack:
    if not isinstance(document, dict) or set(document) != _BUNDLE_FIELDS:
        raise ValueError("Hardening Pack evidence bundle fields are invalid")
    current = int(time.time()) if now is None else now
    if not _is_safe_integer(current):
        raise ValueError("verification time is invalid")
    keys = _issuer_keys(document.get("issuer_document"))
    record = document.get("pack")
    if not isinstance(record, dict):
        raise ValueError("Hardening Pack evidence is missing")
    parsed_source = urlsplit(source)
    if "://" in source:
        match = _PACK_PATH.fullmatch(parsed_source.path)
        if (
            f"{parsed_source.scheme}://{parsed_source.netloc}" != PUBLIC_ORIGIN
            or parsed_source.username is not None
            or parsed_source.password is not None
            or parsed_source.query
            or parsed_source.fragment
            or match is None
            or match.group(1) != record.get("pack_id")
        ):
            raise ValueError("Hardening Pack URL does not match the signed pack")
    pack = _verify_pack(record, keys=keys, now=current)
    checkpoint = _verify_checkpoint(document.get("checkpoint"), keys=keys)
    revoked = _verify_inclusion(
        record=record,
        log_suffix=document.get("log_suffix"),
        checkpoint=checkpoint,
    )
    expected_status = "revoked" if revoked else "active"
    if document.get("status") != expected_status:
        raise ValueError("Hardening Pack status does not match its evidence")
    revoked_at = document.get("revoked_at")
    if (revoked and not _is_safe_integer(revoked_at)) or (
        not revoked and revoked_at is not None
    ):
        raise ValueError("Hardening Pack revocation time is invalid")
    if revoked:
        raise ValueError("Hardening Pack is revoked")
    if document.get("verified") is not True:
        raise ValueError("Hardening Pack server evidence is invalid")
    return pack


def _validate_pack(pack: VerifiedHardeningPack) -> None:
    if not isinstance(pack, VerifiedHardeningPack):
        raise ValueError("Hardening Pack verifier returned an invalid value")
    if not isinstance(pack.pack_id, str) or not pack.pack_id or len(pack.pack_id) > 256:
        raise ValueError("verified Hardening Pack has an invalid pack_id")
    if not isinstance(pack.vectors, tuple):
        raise ValueError("verified Hardening Pack vectors are invalid")
    vector_ids: set[str] = set()
    for vector in pack.vectors:
        if not isinstance(vector, SelfTestVector):
            raise ValueError("verified Hardening Pack contains an invalid vector")
        if (
            not isinstance(vector.vector_id, str)
            or not vector.vector_id
            or len(vector.vector_id) > 256
            or vector.vector_id in vector_ids
        ):
            raise ValueError("verified Hardening Pack contains an invalid or duplicate vector id")
        vector_ids.add(vector.vector_id)
        if (
            not isinstance(vector.attack_class, str)
            or not vector.attack_class
            or len(vector.attack_class) > 128
            or not isinstance(vector.payload, str)
            or not vector.payload
            or len(vector.payload) > MAX_VECTOR_PAYLOAD_LENGTH
            or vector.expected_verdict not in _VERDICTS
            or vector.depth not in _DEPTHS
        ):
            raise ValueError("verified Hardening Pack vector is invalid")


def _local_scanner() -> VectorScanner:
    client = WardenClient(local=True, fail_open=False)

    def scan(
        payload: str,
        *,
        depth: str,
        expected_addresses: list[str],
    ) -> ScanResult:
        return client.scan(
            payload,
            depth=depth,
            expected_addresses=expected_addresses,
        )

    return scan


def _endpoint_scanner(endpoint: str, *, timeout_seconds: float) -> VectorScanner:
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("self-test endpoint must be an explicit HTTP or HTTPS URL")

    def scan(
        payload: str,
        *,
        depth: str,
        expected_addresses: list[str],
    ) -> ScanResult:
        body: dict[str, object] = {"payload": payload, "depth": depth}
        if expected_addresses:
            body["context"] = {"expected_addresses": expected_addresses}
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout_seconds,
            trust_env=False,
        ) as client:
            with client.stream("POST", endpoint, json=body) as response:
                if response.status_code != 200:
                    raise WardenError(
                        f"self-test endpoint returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_PACK_BYTES:
                        raise WardenError("self-test endpoint response exceeds the size limit")
                    chunks.append(chunk)
        try:
            document = _parse_json(
                b"".join(chunks),
                label="self-test endpoint response",
            )
        except ValueError as exc:
            raise WardenError(str(exc)) from exc
        return ScanResult.from_response(document)

    return scan


def run_verified_pack(
    pack: VerifiedHardeningPack,
    *,
    scanner: VectorScanner | None = None,
) -> SelfTestReport:
    _validate_pack(pack)
    scan = scanner or (_local_scanner() if pack.vectors else None)
    class_counts: dict[str, list[int]] = {}
    failures: list[SelfTestFailure] = []
    for vector in pack.vectors:
        assert scan is not None
        result = scan(
            vector.payload,
            depth=vector.depth,
            expected_addresses=list(vector.expected_addresses),
        )
        if not isinstance(result, ScanResult):
            raise ValueError("self-test scanner returned an invalid result")
        expected_classes = vector.expected_classes or (vector.attack_class,)
        passed = (
            result.verdict == vector.expected_verdict
            and all(reason in result.threat_classes for reason in expected_classes)
        )
        counts = class_counts.setdefault(vector.attack_class, [0, 0])
        counts[0] += 1
        if passed:
            counts[1] += 1
        else:
            failures.append(
                SelfTestFailure(
                    vector_id=vector.vector_id,
                    attack_class=vector.attack_class,
                    expected_verdict=vector.expected_verdict,
                    observed_verdict=result.verdict,
                )
            )
    classes = {
        attack_class: SelfTestClassResult(
            total=counts[0],
            passed=counts[1],
            failed=counts[0] - counts[1],
        )
        for attack_class, counts in class_counts.items()
    }
    failed = len(failures)
    return SelfTestReport(
        pack_id=pack.pack_id,
        total=len(pack.vectors),
        passed=len(pack.vectors) - failed,
        failed=failed,
        no_op=not pack.vectors,
        message=pack.message,
        classes=classes,
        failures=tuple(failures),
    )


def _load_source(
    source: str,
    *,
    client: httpx.Client | None = None,
) -> tuple[object, str]:
    parsed = urlsplit(source)
    if "://" in source:
        match = _PACK_PATH.fullmatch(parsed.path)
        if (
            f"{parsed.scheme}://{parsed.netloc}" != PUBLIC_ORIGIN
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or match is None
        ):
            raise ValueError(
                f"public Hardening Pack URL must use {PUBLIC_ORIGIN}/apa/hardening/<pack_id>"
            )
        owned_client = client is None
        active_client = client or httpx.Client(
            follow_redirects=False,
            timeout=10.0,
            trust_env=False,
        )
        try:
            with active_client.stream("GET", source) as response:
                if response.status_code != 200:
                    raise ValueError(
                        f"Hardening Pack source returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_PACK_BYTES:
                        raise ValueError("Hardening Pack response exceeds the size limit")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise ValueError("Hardening Pack request failed") from exc
        finally:
            if owned_client:
                active_client.close()
        return _parse_json(b"".join(chunks), label="Hardening Pack response"), source

    path = Path(source)
    if path.is_symlink():
        raise ValueError("Hardening Pack file must not be a symlink")
    if not path.is_file():
        raise ValueError("Hardening Pack file does not exist")
    return _parse_json(path.read_bytes(), label="Hardening Pack file"), str(path.resolve())


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="warden-selftest",
        description=(
            "Verify and run signed Hardening Pack vectors. This command reports "
            "practice results only; it does not issue a grade, badge, or certification."
        ),
    )
    parser.add_argument("pack", help="Evidence-bundle file or canonical public pack URL")
    parser.add_argument(
        "--endpoint",
        help=(
            "Caller-authorized Warden-compatible endpoint to exercise. "
            "Omit to use local fail-closed enforcement."
        ),
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 60:
        parser.error("--timeout must be greater than zero and at most 60 seconds")
    return args


def main(
    argv: list[str] | None = None,
    *,
    verifier: HardeningPackVerifier | None = None,
    scanner: VectorScanner | None = None,
    client: httpx.Client | None = None,
) -> int:
    args = _parse_args(argv)
    try:
        document, source = _load_source(args.pack, client=client)
        verify = verifier or verify_evidence_bundle
        pack = verify(document, source=source)
        active_scanner = scanner
        if active_scanner is None and args.endpoint:
            active_scanner = _endpoint_scanner(
                args.endpoint,
                timeout_seconds=args.timeout,
            )
        report = run_verified_pack(pack, scanner=active_scanner)
    except (OSError, ValueError, WardenError) as exc:
        print(f"SELFTEST FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
