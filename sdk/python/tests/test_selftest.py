from __future__ import annotations

import json
from pathlib import Path

import pytest

from warden_guard.client import ScanResult
from warden_guard.selftest import (
    SelfTestVector,
    VerifiedHardeningPack,
    main,
    run_verified_pack,
)


def _result(verdict: str, threat_classes: list[str]) -> ScanResult:
    return ScanResult(
        verdict=verdict,
        risk_level="HIGH" if verdict != "ALLOW" else "NONE",
        threat_classes=threat_classes,
        raw={"verdict": verdict},
    )


def _pack() -> VerifiedHardeningPack:
    return VerifiedHardeningPack(
        pack_id="pack-123",
        vectors=(
            SelfTestVector(
                vector_id="vector-1",
                attack_class="PROMPT_INJECTION",
                payload="private prompt injection vector",
                expected_verdict="SANITIZE",
            ),
            SelfTestVector(
                vector_id="vector-2",
                attack_class="SECRET_EXFIL",
                payload="private secret exfiltration vector",
                expected_verdict="BLOCK",
            ),
        ),
    )


def test_run_verified_pack_reports_totals_without_retaining_payloads() -> None:
    seen: list[str] = []

    def scanner(payload: str) -> ScanResult:
        seen.append(payload)
        if "injection" in payload:
            return _result("SANITIZE", ["PROMPT_INJECTION"])
        return _result("ALLOW", [])

    report = run_verified_pack(_pack(), scanner=scanner)

    assert seen == [
        "private prompt injection vector",
        "private secret exfiltration vector",
    ]
    assert report.as_dict() == {
        "pack_id": "pack-123",
        "total": 2,
        "passed": 1,
        "failed": 1,
        "classes": {
            "PROMPT_INJECTION": {"total": 1, "passed": 1, "failed": 0},
            "SECRET_EXFIL": {"total": 1, "passed": 0, "failed": 1},
        },
        "failures": [
            {
                "vector_id": "vector-2",
                "attack_class": "SECRET_EXFIL",
                "expected_verdict": "BLOCK",
                "observed_verdict": "ALLOW",
            }
        ],
    }
    serialized = json.dumps(report.as_dict(), sort_keys=True)
    assert "private prompt injection vector" not in serialized
    assert "private secret exfiltration vector" not in serialized
    assert "grade" not in serialized
    assert "badge" not in serialized
    assert "certification" not in serialized


@pytest.mark.parametrize(
    "pack",
    [
        VerifiedHardeningPack(
            pack_id="pack-duplicate",
            vectors=(
                SelfTestVector("same", "PROMPT_INJECTION", "first payload", "SANITIZE"),
                SelfTestVector("same", "SECRET_EXFIL", "second payload", "BLOCK"),
            ),
        ),
    ],
)
def test_verified_pack_rejects_duplicate_vector_ids(pack: VerifiedHardeningPack) -> None:
    with pytest.raises(ValueError, match="duplicate"):
        run_verified_pack(pack, scanner=lambda _payload: _result("BLOCK", ["SECRET_EXFIL"]))


def test_cli_fails_closed_until_signed_pack_verifier_is_available(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text('{"vectors": []}', encoding="utf-8")

    assert main([str(unsigned)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "signed Hardening Pack verifier is unavailable" in captured.err


def test_cli_runs_only_the_normalized_pack_returned_by_injected_verifier(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "signed-pack.json"
    path.write_text('{"opaque": "signed-envelope"}', encoding="utf-8")
    verifier_calls: list[tuple[object, str]] = []
    scanned: list[str] = []

    def verifier(document: object, *, source: str) -> VerifiedHardeningPack:
        verifier_calls.append((document, source))
        return _pack()

    def scanner(payload: str) -> ScanResult:
        scanned.append(payload)
        if "injection" in payload:
            return _result("SANITIZE", ["PROMPT_INJECTION"])
        return _result("BLOCK", ["SECRET_EXFIL"])

    assert main([str(path)], verifier=verifier, scanner=scanner) == 0
    assert verifier_calls == [({"opaque": "signed-envelope"}, str(path.resolve()))]
    assert scanned == [
        "private prompt injection vector",
        "private secret exfiltration vector",
    ]
    output = json.loads(capsys.readouterr().out)
    assert output["passed"] == 2
    assert "private prompt injection vector" not in json.dumps(output)


def test_cli_rejects_urls_before_network_access(
    capsys: pytest.CaptureFixture[str],
) -> None:
    called = False

    def verifier(document: object, *, source: str) -> VerifiedHardeningPack:
        nonlocal called
        called = True
        return _pack()

    assert main(["https://issuer.example/pack.json"], verifier=verifier) == 2
    assert called is False
    assert "public pack URL contract is unavailable" in capsys.readouterr().err
