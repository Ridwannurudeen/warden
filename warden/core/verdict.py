"""Deterministic verdict aggregation for Warden scans."""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Mapping, Sequence

from warden.core.analyzer import AnalyzerResult

VerdictValue = Literal["ALLOW", "SANITIZE", "BLOCK"]
RiskLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ReasonCode(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    ROLE_OVERRIDE = "ROLE_OVERRIDE"
    WEB3_INJECTION = "WEB3_INJECTION"
    HIDDEN_UNICODE = "HIDDEN_UNICODE"
    ENCODING_TRICK = "ENCODING_TRICK"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"
    CORPUS_MATCH = "CORPUS_MATCH"
    DRAIN_ADDRESS = "DRAIN_ADDRESS"
    TOOL_HIJACK = "TOOL_HIJACK"
    SECRET_EXFIL = "SECRET_EXFIL"
    MALICIOUS_LINK = "MALICIOUS_LINK"


SCANNER_CATEGORY_REASON_CODES: dict[str, ReasonCode] = {
    "direct_instruction": ReasonCode.PROMPT_INJECTION,
    "role_override": ReasonCode.ROLE_OVERRIDE,
    "web3_specific": ReasonCode.WEB3_INJECTION,
    "control_characters": ReasonCode.HIDDEN_UNICODE,
    "encoding_tricks": ReasonCode.ENCODING_TRICK,
    "statistical_analysis": ReasonCode.STATISTICAL_ANOMALY,
    "corpus_match": ReasonCode.CORPUS_MATCH,
    "ai_analysis": ReasonCode.PROMPT_INJECTION,
}

SCANNER_RISK_SCORE = {
    "NONE": 0.0,
    "LOW": 30.0,
    "MEDIUM": 55.0,
    "HIGH": 80.0,
    "CRITICAL": 100.0,
}

REDACTED_SECRET_MATCH = "[REDACTED SECRET]"


@dataclass
class Verdict:
    verdict: VerdictValue
    risk_level: RiskLevel
    threat_classes: list[ReasonCode] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    sanitized_payload: str = ""
    recommendation: str = ""
    checks: dict[str, str] = field(default_factory=dict)
    failed_checks: list[ReasonCode] = field(default_factory=list)
    latency_ms: float = 0.0


class VerdictEngine:
    """Short-circuit hard gates before applying deterministic risk bands."""

    def decide(
        self,
        payload: str | None,
        scanner_result: Mapping[str, object] | None,
        analyzer_results: Sequence[AnalyzerResult],
    ) -> Verdict:
        if payload is None:
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                sanitized_payload="",
                recommendation="Invalid payload. Warden fails closed.",
                checks={"input_validation": "fail - payload is required"},
            )

        checks: dict[str, str] = {"input_validation": "pass - payload provided"}
        scanner_detections = self._scanner_detections(scanner_result)
        analyzer_detections = self._analyzer_detections(analyzer_results)
        raw_detections = scanner_detections + analyzer_detections
        detections = self._redact_secret_matches(raw_detections)
        threat_classes = self._dedupe_reason_codes(
            self._reason_code_from_detection(detection) for detection in detections
        )
        sanitized_payload = self._sanitize(
            str(scanner_result.get("sanitized_content", payload)) if scanner_result else payload,
            raw_detections,
        )

        analyzer_errors = [result for result in analyzer_results if result.error]
        if analyzer_errors:
            for result in analyzer_errors:
                checks[f"analyzer_{result.name}"] = "fail - analysis unavailable"
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. A Warden analyzer did not complete.",
                checks=checks,
                failed_checks=threat_classes,
            )

        scanner_risk = str(scanner_result.get("risk_level", "NONE")) if scanner_result else "NONE"
        scanner_score = SCANNER_RISK_SCORE.get(scanner_risk, 100.0)
        analyzer_score = self._analyzer_score(analyzer_results)
        score = self._composite_score(scanner_score, analyzer_score, analyzer_results)

        checks["scanner_risk"] = f"{scanner_risk.lower()} - score {scanner_score:.0f}"
        checks["analyzer_score"] = f"score {analyzer_score:.1f}"
        checks["composite_score"] = f"score {score:.1f}"

        hard_block = self._hard_block_reason(detections, scanner_risk)
        if hard_block is not None:
            checks[hard_block.value.lower()] = "fail - hard block gate fired"
            if hard_block is ReasonCode.TOOL_HIJACK:
                checks["sanitization_validation"] = (
                    "fail - executable tool payload cannot be safely rewritten"
                )
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. A hard Warden gate fired.",
                checks=checks,
                failed_checks=[hard_block],
            )

        if not math.isfinite(score) or score < 0:
            checks["score_validation"] = f"fail - invalid score ({score})"
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. Composite risk score is invalid.",
                checks=checks,
                failed_checks=threat_classes,
            )

        if score >= 70:
            checks["risk_band"] = f"block - score {score:.1f} >= 70"
            return Verdict(
                verdict="BLOCK",
                risk_level=self._risk_level(score, scanner_risk, hard_block=False),
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload before agent execution.",
                checks=checks,
                failed_checks=threat_classes,
            )

        if score < 20 and not detections:
            checks["risk_band"] = f"allow - score {score:.1f} < 20 and no detections"
            return Verdict(
                verdict="ALLOW",
                risk_level="NONE",
                threat_classes=[],
                detections=[],
                sanitized_payload=payload,
                recommendation="Payload appears clean. No Warden threat classes detected.",
                checks=checks,
                failed_checks=[],
            )

        # SANITIZE means the returned payload is safe to use. If nothing was
        # actually removed (e.g. a tool-hijack, which the redactor cannot rewrite),
        # do not hand back the untouched attack labelled "sanitized" — block it.
        if detections and sanitized_payload == payload:
            checks["risk_band"] = f"block - threat present but not sanitizable (score {score:.1f})"
            unsanitizable_risk = self._risk_level(score, scanner_risk, hard_block=False)
            if unsanitizable_risk in ("NONE", "LOW"):
                unsanitizable_risk = "MEDIUM"
            return Verdict(
                verdict="BLOCK",
                risk_level=unsanitizable_risk,
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. Warden could not neutralize the detected threat.",
                checks=checks,
                failed_checks=threat_classes,
            )

        checks["risk_band"] = f"sanitize - score {score:.1f} in review band or detections present"
        risk_level = self._risk_level(score, scanner_risk, hard_block=False)
        if detections and risk_level in {"NONE", "LOW"}:
            risk_level = "MEDIUM"
        return Verdict(
            verdict="SANITIZE",
            risk_level=risk_level,
            threat_classes=threat_classes,
            detections=detections,
            sanitized_payload=sanitized_payload,
            recommendation="Sanitize before agent execution and inspect the listed threat classes.",
            checks=checks,
            failed_checks=threat_classes,
        )

    @staticmethod
    def _scanner_detections(scanner_result: Mapping[str, object] | None) -> list[dict[str, object]]:
        if not scanner_result:
            return []

        unified: list[dict[str, object]] = []
        raw_detections = scanner_result.get("detections", [])
        if not isinstance(raw_detections, list):
            return unified

        for detection in raw_detections:
            if not isinstance(detection, dict):
                continue
            category = str(detection.get("pattern_category", ""))
            reason_code = SCANNER_CATEGORY_REASON_CODES.get(category)
            if reason_code is None:
                continue
            layer = detection.get("layer", "scanner")
            unified.append(
                {
                    "class": reason_code.value,
                    "match": detection.get("match_text") or "",
                    "confidence": float(detection.get("confidence", 0.0)),
                    "source": f"layer_{layer}",
                }
            )
        return unified

    @staticmethod
    def _analyzer_detections(analyzer_results: Sequence[AnalyzerResult]) -> list[dict[str, object]]:
        unified: list[dict[str, object]] = []
        for result in analyzer_results:
            raw_detections = result.data.get("detections", [])
            if not isinstance(raw_detections, list):
                continue
            for detection in raw_detections:
                if not isinstance(detection, dict):
                    continue
                class_value = detection.get("class")
                if class_value not in {reason.value for reason in ReasonCode}:
                    continue
                unified.append(
                    {
                        "class": str(class_value),
                        "match": str(detection.get("match", "")),
                        "confidence": float(detection.get("confidence", 0.0)),
                        "source": result.name,
                    }
                )
        return unified

    @staticmethod
    def _reason_code_from_detection(detection: Mapping[str, object]) -> ReasonCode | None:
        class_value = detection.get("class")
        if isinstance(class_value, ReasonCode):
            return class_value
        if isinstance(class_value, str):
            try:
                return ReasonCode(class_value)
            except ValueError:
                return None
        return None

    @staticmethod
    def _redact_secret_matches(
        detections: Sequence[Mapping[str, object]],
    ) -> list[dict[str, object]]:
        redacted: list[dict[str, object]] = []
        for detection in detections:
            public_detection = dict(detection)
            if public_detection.get("class") == ReasonCode.SECRET_EXFIL.value:
                public_detection["match"] = REDACTED_SECRET_MATCH
            redacted.append(public_detection)
        return redacted

    @staticmethod
    def _dedupe_reason_codes(codes: Sequence[ReasonCode | None]) -> list[ReasonCode]:
        seen: set[ReasonCode] = set()
        deduped: list[ReasonCode] = []
        for code in codes:
            if code is not None and code not in seen:
                seen.add(code)
                deduped.append(code)
        return deduped

    @staticmethod
    def _analyzer_score(analyzer_results: Sequence[AnalyzerResult]) -> float:
        if not analyzer_results:
            return 0.0
        return sum(result.score * result.weight for result in analyzer_results)

    @staticmethod
    def _composite_score(
        scanner_score: float,
        analyzer_score: float,
        analyzer_results: Sequence[AnalyzerResult],
    ) -> float:
        if scanner_score > 0 and analyzer_results:
            return scanner_score * 0.5 + analyzer_score * 0.5
        if analyzer_results:
            return analyzer_score
        return scanner_score

    @staticmethod
    def _hard_block_reason(
        detections: Sequence[Mapping[str, object]],
        scanner_risk: str,
    ) -> ReasonCode | None:
        for detection in detections:
            if detection.get("class") == ReasonCode.DRAIN_ADDRESS.value:
                if float(detection.get("confidence", 0.0)) >= 0.9:
                    return ReasonCode.DRAIN_ADDRESS
        for detection in detections:
            if detection.get("class") == ReasonCode.SECRET_EXFIL.value:
                if float(detection.get("confidence", 0.0)) >= 0.9:
                    return ReasonCode.SECRET_EXFIL
        for detection in detections:
            if detection.get("class") == ReasonCode.TOOL_HIJACK.value:
                if float(detection.get("confidence", 0.0)) >= 0.8:
                    return ReasonCode.TOOL_HIJACK
        if scanner_risk == "CRITICAL":
            return VerdictEngine._highest_confidence_scanner_reason(detections)
        return None

    @staticmethod
    def _highest_confidence_scanner_reason(
        detections: Sequence[Mapping[str, object]],
    ) -> ReasonCode:
        """Attribute a scanner-driven CRITICAL to whichever scanner category actually
        scored highest, instead of always blaming PROMPT_INJECTION."""
        scanner_codes = {reason.value for reason in SCANNER_CATEGORY_REASON_CODES.values()}
        best_code = ReasonCode.PROMPT_INJECTION
        best_confidence = -1.0
        for detection in detections:
            class_value = detection.get("class")
            if class_value not in scanner_codes:
                continue
            confidence = float(detection.get("confidence", 0.0))
            if confidence > best_confidence:
                best_confidence = confidence
                best_code = ReasonCode(class_value)
        return best_code

    @staticmethod
    def _sanitize(payload: str, detections: Sequence[Mapping[str, object]]) -> str:
        sanitized = payload
        for detection in detections:
            if detection.get("class") == ReasonCode.TOOL_HIJACK.value:
                continue
            match = str(detection.get("match", ""))
            if match:
                sanitized = sanitized.replace(match, "[REDACTED]")
        return sanitized

    @staticmethod
    def _risk_level(score: float, scanner_risk: str, hard_block: bool) -> RiskLevel:
        if hard_block or scanner_risk == "CRITICAL":
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 55:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "NONE"
