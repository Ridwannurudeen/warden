"""Verdict engine hard gates and band tests."""

from warden.core.analyzer import AnalyzerResult
from warden.core.verdict import ReasonCode, VerdictEngine


def scanner_result(risk_level: str = "NONE", detections: list[dict] | None = None) -> dict:
    return {
        "risk_level": risk_level,
        "detections": detections or [],
        "sanitized_content": "payload",
        "recommendation": "",
    }


def score_result(score: float) -> AnalyzerResult:
    return AnalyzerResult(name="synthetic", weight=1.0, score=score, data={"detections": []})


def detection_result(reason: ReasonCode, confidence: float) -> AnalyzerResult:
    return AnalyzerResult(
        name="synthetic",
        weight=1.0,
        score=confidence * 100,
        data={
            "detections": [
                {
                    "class": reason.value,
                    "match": "payload",
                    "confidence": confidence,
                }
            ]
        },
    )


def test_invalid_input_fails_closed():
    verdict = VerdictEngine().decide(None, None, [])
    assert verdict.verdict == "BLOCK"
    assert verdict.risk_level == "CRITICAL"


def test_drain_hard_gate_short_circuits():
    verdict = VerdictEngine().decide(
        "payload",
        scanner_result(),
        [detection_result(ReasonCode.DRAIN_ADDRESS, 0.95)],
    )
    assert verdict.verdict == "BLOCK"
    assert verdict.failed_checks == [ReasonCode.DRAIN_ADDRESS]


def test_secret_hard_gate_short_circuits():
    verdict = VerdictEngine().decide(
        "payload",
        scanner_result(),
        [detection_result(ReasonCode.SECRET_EXFIL, 0.95)],
    )
    assert verdict.verdict == "BLOCK"
    assert verdict.failed_checks == [ReasonCode.SECRET_EXFIL]


def test_scanner_critical_short_circuits():
    verdict = VerdictEngine().decide("payload", scanner_result("CRITICAL"), [score_result(0)])
    assert verdict.verdict == "BLOCK"


def test_band_boundary_19_allows():
    verdict = VerdictEngine().decide("payload", scanner_result(), [score_result(19)])
    assert verdict.verdict == "ALLOW"


def test_band_boundary_20_sanitizes():
    verdict = VerdictEngine().decide("payload", scanner_result(), [score_result(20)])
    assert verdict.verdict == "SANITIZE"


def test_band_boundary_69_sanitizes():
    verdict = VerdictEngine().decide("payload", scanner_result(), [score_result(69)])
    assert verdict.verdict == "SANITIZE"


def test_band_boundary_70_blocks():
    verdict = VerdictEngine().decide("payload", scanner_result(), [score_result(70)])
    assert verdict.verdict == "BLOCK"


def test_scanner_high_stays_sanitizable_under_the_policy_table():
    verdict = VerdictEngine().decide(
        "payload",
        scanner_result(
            "HIGH",
            [
                {
                    "pattern_category": "direct_instruction",
                    "match_text": "payload",
                    "confidence": 0.95,
                    "layer": 1,
                }
            ],
        ),
        [score_result(0)],
    )

    assert verdict.verdict == "SANITIZE"
    assert verdict.risk_level == "HIGH"


def test_analyzer_block_band_is_not_diluted_by_scanner_score():
    verdict = VerdictEngine().decide(
        "payload",
        scanner_result("MEDIUM"),
        [score_result(70)],
    )

    assert verdict.verdict == "BLOCK"
    assert "composite_score" not in verdict.checks


def test_unknown_scanner_risk_fails_closed():
    verdict = VerdictEngine().decide(
        "payload",
        scanner_result("UNRECOGNIZED"),
        [score_result(0)],
    )

    assert verdict.verdict == "BLOCK"
    assert verdict.risk_level == "CRITICAL"
    assert verdict.checks["scanner_risk"].startswith("fail")
