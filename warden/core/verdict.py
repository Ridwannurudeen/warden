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
    "embedding_match": ReasonCode.CORPUS_MATCH,
    "ai_prompt_injection": ReasonCode.PROMPT_INJECTION,
    "ai_drain_address": ReasonCode.DRAIN_ADDRESS,
    "ai_secret_exfil": ReasonCode.SECRET_EXFIL,
    "ai_tool_hijack": ReasonCode.TOOL_HIJACK,
}

REDACTED_SECRET_MATCH = "[REDACTED SECRET]"
VERDICT_ORDER = {"ALLOW": 0, "SANITIZE": 1, "BLOCK": 2}
RISK_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class PolicyRule:
    minimum_score: float
    verdict: VerdictValue
    risk_level: RiskLevel


SCANNER_POLICY_TABLE: dict[str, PolicyRule] = {
    "NONE": PolicyRule(0, "ALLOW", "NONE"),
    "LOW": PolicyRule(0, "SANITIZE", "LOW"),
    "MEDIUM": PolicyRule(0, "SANITIZE", "MEDIUM"),
    "HIGH": PolicyRule(0, "SANITIZE", "HIGH"),
    "CRITICAL": PolicyRule(0, "BLOCK", "CRITICAL"),
}
ANALYZER_POLICY_TABLE = (
    PolicyRule(70, "BLOCK", "HIGH"),
    PolicyRule(55, "SANITIZE", "MEDIUM"),
    PolicyRule(20, "SANITIZE", "LOW"),
    PolicyRule(0, "ALLOW", "NONE"),
)


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
    """Short-circuit hard gates before applying deterministic policy tables."""

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
        scanner_policy = SCANNER_POLICY_TABLE.get(scanner_risk)
        if scanner_policy is None:
            checks["scanner_risk"] = f"fail - unsupported risk level ({scanner_risk})"
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. Scanner risk metadata is invalid.",
                checks=checks,
                failed_checks=threat_classes,
            )

        analyzer_score = self._analyzer_score(analyzer_results)
        checks["scanner_risk"] = f"{scanner_risk.lower()} - policy {scanner_policy.verdict.lower()}"
        checks["analyzer_score"] = f"score {analyzer_score:.1f}"

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

        if not math.isfinite(analyzer_score) or analyzer_score < 0:
            checks["score_validation"] = f"fail - invalid analyzer score ({analyzer_score})"
            return Verdict(
                verdict="BLOCK",
                risk_level="CRITICAL",
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload. Analyzer risk score is invalid.",
                checks=checks,
                failed_checks=threat_classes,
            )

        analyzer_policy = next(
            rule for rule in ANALYZER_POLICY_TABLE if analyzer_score >= rule.minimum_score
        )
        selected_policy = max(
            (scanner_policy, analyzer_policy),
            key=lambda rule: VERDICT_ORDER[rule.verdict],
        )
        selected_risk = max(
            (scanner_policy.risk_level, analyzer_policy.risk_level),
            key=lambda risk: RISK_ORDER[risk],
        )
        selected_verdict = selected_policy.verdict
        if detections and selected_verdict == "ALLOW":
            selected_verdict = "SANITIZE"
            if selected_risk in {"NONE", "LOW"}:
                selected_risk = "MEDIUM"
        checks["policy_table"] = (
            f"{selected_verdict.lower()} - scanner {scanner_policy.verdict.lower()}, "
            f"analyzers {analyzer_policy.verdict.lower()}"
        )

        if selected_verdict == "BLOCK":
            checks["risk_band"] = f"block - analyzer score {analyzer_score:.1f} or scanner policy"
            return Verdict(
                verdict="BLOCK",
                risk_level=selected_risk,
                threat_classes=threat_classes,
                detections=detections,
                sanitized_payload=sanitized_payload,
                recommendation="Block this payload before agent execution.",
                checks=checks,
                failed_checks=threat_classes,
            )

        if selected_verdict == "ALLOW":
            checks["risk_band"] = (
                f"allow - analyzer score {analyzer_score:.1f} and scanner policy allow"
            )
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
            checks["risk_band"] = "block - threat present but not sanitizable"
            unsanitizable_risk = selected_risk
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

        checks["risk_band"] = f"sanitize - analyzer score {analyzer_score:.1f} or scanner policy"
        risk_level = selected_risk
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
        for detection in detections:
            if detection.get("class") == ReasonCode.MALICIOUS_LINK.value:
                match = str(detection.get("match", ""))
                normalized_match = (
                    match.replace("\t", "").replace("\r", "").replace("\n", "").lower()
                )
                if normalized_match.startswith(("file:", "javascript:", "vbscript:")):
                    return ReasonCode.MALICIOUS_LINK
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
