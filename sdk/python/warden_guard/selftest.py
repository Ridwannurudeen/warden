"""Run locally verified Hardening Pack vectors without producing certification."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from warden_guard.client import ScanResult, WardenClient, WardenError

MAX_PACK_BYTES = 2_000_000
MAX_VECTOR_PAYLOAD_LENGTH = 100_000
_VERDICTS = frozenset({"ALLOW", "SANITIZE", "BLOCK"})


@dataclass(frozen=True)
class SelfTestVector:
    """One normalized vector returned by a trusted signed-pack verifier."""

    vector_id: str
    attack_class: str
    payload: str
    expected_verdict: str


@dataclass(frozen=True)
class VerifiedHardeningPack:
    """Verifier output; constructing this value does not itself verify a signature."""

    pack_id: str
    vectors: tuple[SelfTestVector, ...]


class HardeningPackVerifier(Protocol):
    """Normalize a document only after all signature, history, and status checks pass."""

    def __call__(
        self,
        document: object,
        *,
        source: str,
    ) -> VerifiedHardeningPack: ...


class VectorScanner(Protocol):
    def __call__(self, payload: str) -> ScanResult: ...


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
    classes: dict[str, SelfTestClassResult]
    failures: tuple[SelfTestFailure, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "pack_id": self.pack_id,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "classes": {
                attack_class: result.as_dict()
                for attack_class, result in sorted(self.classes.items())
            },
            "failures": [failure.as_dict() for failure in self.failures],
        }


def _validate_pack(pack: VerifiedHardeningPack) -> None:
    if not isinstance(pack, VerifiedHardeningPack):
        raise ValueError("Hardening Pack verifier returned an invalid value")
    if not isinstance(pack.pack_id, str) or not pack.pack_id or len(pack.pack_id) > 256:
        raise ValueError("verified Hardening Pack has an invalid pack_id")
    if not isinstance(pack.vectors, tuple) or not pack.vectors:
        raise ValueError("verified Hardening Pack must contain vectors")

    vector_ids: set[str] = set()
    for vector in pack.vectors:
        if not isinstance(vector, SelfTestVector):
            raise ValueError("verified Hardening Pack contains an invalid vector")
        if (
            not isinstance(vector.vector_id, str)
            or not vector.vector_id
            or len(vector.vector_id) > 256
        ):
            raise ValueError("verified Hardening Pack vector has an invalid id")
        if vector.vector_id in vector_ids:
            raise ValueError("verified Hardening Pack contains a duplicate vector id")
        vector_ids.add(vector.vector_id)
        if (
            not isinstance(vector.attack_class, str)
            or not vector.attack_class
            or len(vector.attack_class) > 128
        ):
            raise ValueError("verified Hardening Pack vector has an invalid attack class")
        if (
            not isinstance(vector.payload, str)
            or not vector.payload
            or len(vector.payload) > MAX_VECTOR_PAYLOAD_LENGTH
        ):
            raise ValueError("verified Hardening Pack vector has an invalid payload")
        try:
            vector.payload.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "verified Hardening Pack vector payload must contain Unicode scalar text"
            ) from exc
        if vector.expected_verdict not in _VERDICTS:
            raise ValueError("verified Hardening Pack vector has an invalid expected verdict")


def _local_scanner() -> Callable[[str], ScanResult]:
    client = WardenClient(local=True, fail_open=False)
    return client.scan


def run_verified_pack(
    pack: VerifiedHardeningPack,
    *,
    scanner: VectorScanner | None = None,
) -> SelfTestReport:
    """Exercise a verifier-normalized pack and retain only aggregate results."""
    _validate_pack(pack)
    scan = scanner or _local_scanner()
    class_counts: dict[str, list[int]] = {}
    failures: list[SelfTestFailure] = []

    for vector in pack.vectors:
        result = scan(vector.payload)
        if not isinstance(result, ScanResult):
            raise ValueError("self-test scanner returned an invalid result")
        passed = (
            result.verdict == vector.expected_verdict
            and vector.attack_class in result.threat_classes
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
        classes=classes,
        failures=tuple(failures),
    )


def _load_local_document(source: str) -> tuple[object, str]:
    parsed = urlsplit(source)
    if "://" in source:
        if parsed.scheme == "https":
            raise ValueError(
                "public pack URL contract is unavailable until signed Hardening Pack "
                "origin verification is merged"
            )
        raise ValueError("Hardening Pack source must be a local file or HTTPS URL")
    path = Path(source)
    if path.is_symlink():
        raise ValueError("Hardening Pack file must not be a symlink")
    if not path.is_file():
        raise ValueError("Hardening Pack file does not exist")
    if path.stat().st_size > MAX_PACK_BYTES:
        raise ValueError("Hardening Pack file exceeds the size limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Hardening Pack file is invalid JSON") from exc
    return document, str(path.resolve())


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="warden-selftest",
        description=(
            "Run signed Hardening Pack vectors locally. This command reports self-test "
            "results only; it does not issue a grade, badge, or certification."
        ),
    )
    parser.add_argument("pack", help="Signed Hardening Pack file or verified public pack URL")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    verifier: HardeningPackVerifier | None = None,
    scanner: VectorScanner | None = None,
) -> int:
    args = _parse_args(argv)
    if verifier is None:
        print(
            "SELFTEST FAILED: signed Hardening Pack verifier is unavailable; "
            "unsigned or unverified packs are refused",
            file=sys.stderr,
        )
        return 2
    try:
        document, source = _load_local_document(args.pack)
        pack = verifier(document, source=source)
        report = run_verified_pack(pack, scanner=scanner)
    except (OSError, ValueError, WardenError) as exc:
        print(f"SELFTEST FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
