"""Single-source Warden scan orchestration."""

from time import perf_counter

from warden.analyzers import (
    DrainAddressAnalyzer,
    ExfiltrationAnalyzer,
    MaliciousLinkAnalyzer,
    ToolHijackAnalyzer,
)
from warden.core.analyzer import AnalysisContext
from warden.core.registry import AnalyzerRegistry
from warden.core.verdict import ReasonCode, Verdict, VerdictEngine
from warden.scanner.normalize import TRANSFORM_DECODED, derive_candidates
from warden.scanner.scanner import InjectionScanner
from warden.scanner.semantic import SemanticAnalyzer, build_semantic_analyzer_from_env


class WardenEngine:
    def __init__(self, semantic_analyzer: SemanticAnalyzer | None = None):
        configured_analyzer = (
            semantic_analyzer
            if semantic_analyzer is not None
            else build_semantic_analyzer_from_env()
        )
        self.semantic_enabled = configured_analyzer is not None
        self.scanner = InjectionScanner(ai_analyzer=configured_analyzer)
        self.registry = AnalyzerRegistry()
        self.registry.register(DrainAddressAnalyzer())
        self.registry.register(ToolHijackAnalyzer())
        self.registry.register(ExfiltrationAnalyzer())
        self.registry.register(MaliciousLinkAnalyzer())
        self.verdict_engine = VerdictEngine()

    async def scan(
        self,
        payload: str | None,
        depth: str = "fast",
        context: dict[str, object] | None = None,
        allow_paid_semantic: bool = False,
    ) -> Verdict:
        started = perf_counter()
        if payload is None:
            verdict = self.verdict_engine.decide(None, None, [])
            verdict.latency_ms = self._elapsed_ms(started)
            return verdict

        scan_context = context or {}
        expected_addresses = scan_context.get("expected_addresses", [])
        analyzer_context = AnalysisContext(
            address="",
            extra={
                "payload": payload,
                "expected_addresses": expected_addresses
                if isinstance(expected_addresses, list)
                else [],
            },
        )
        analyzer_results = await self.registry.run_all(analyzer_context)
        semantic_allowed = allow_paid_semantic and not any(
            result.error or result.flags or result.score > 0 for result in analyzer_results
        )
        scanner_result = await self.scanner.scan(
            payload,
            depth=depth,
            allow_semantic=semantic_allowed,
        )
        verdict = self.verdict_engine.decide(payload, scanner_result, analyzer_results)
        if verdict.verdict == "SANITIZE":
            sanitized_analyzer_context = AnalysisContext(
                address="",
                extra={
                    "payload": verdict.sanitized_payload,
                    "expected_addresses": (
                        expected_addresses if isinstance(expected_addresses, list) else []
                    ),
                },
            )
            sanitized_analyzer_results = await self.registry.run_all(sanitized_analyzer_context)
            sanitized_semantic_allowed = semantic_allowed and not any(
                result.error or result.flags or result.score > 0
                for result in sanitized_analyzer_results
            )
            sanitized_scanner_result = await self.scanner.scan(
                verdict.sanitized_payload,
                depth=depth,
                allow_semantic=sanitized_semantic_allowed,
            )
            sanitized_verdict = self.verdict_engine.decide(
                verdict.sanitized_payload,
                sanitized_scanner_result,
                sanitized_analyzer_results,
            )
            if sanitized_verdict.verdict == "ALLOW":
                verdict.checks["sanitization_validation"] = (
                    "pass - sanitized payload rescanned clean"
                )
            else:
                verdict.verdict = "BLOCK"
                if verdict.risk_level in {"NONE", "LOW", "MEDIUM"}:
                    verdict.risk_level = "HIGH"
                verdict.recommendation = (
                    "Block this payload. Dangerous content remained after sanitization."
                )
                verdict.checks["sanitization_validation"] = (
                    "fail - sanitized payload still triggers Warden"
                )
                for reason in sanitized_verdict.failed_checks:
                    if reason not in verdict.failed_checks:
                        verdict.failed_checks.append(reason)
        if verdict.verdict != "BLOCK":
            await self._apply_decoder_wall(verdict, payload, depth, expected_addresses)
        verdict.latency_ms = self._elapsed_ms(started)
        return verdict

    async def _apply_decoder_wall(
        self,
        verdict: Verdict,
        payload: str,
        depth: str,
        expected_addresses: object,
    ) -> None:
        """Scan normalized/decoded variants of the payload and union findings.

        This pre-pass is strictly additive: it can escalate an ALLOW/SANITIZE
        verdict when a decoded or homoglyph-folded variant reveals a real
        threat, but it never suppresses or downgrades a raw-text verdict.
        """
        for candidate, transform in derive_candidates(payload):
            candidate_context = AnalysisContext(
                address="",
                extra={
                    "payload": candidate,
                    "expected_addresses": (
                        expected_addresses if isinstance(expected_addresses, list) else []
                    ),
                },
            )
            candidate_analyzer_results = await self.registry.run_all(candidate_context)
            candidate_scanner_result = await self.scanner.scan(
                candidate,
                depth=depth,
                allow_semantic=False,
            )
            candidate_verdict = self.verdict_engine.decide(
                candidate,
                candidate_scanner_result,
                candidate_analyzer_results,
            )
            if candidate_verdict.verdict == "ALLOW":
                continue

            obfuscation_reason = (
                ReasonCode.ENCODING_TRICK
                if transform == TRANSFORM_DECODED
                else ReasonCode.HIDDEN_UNICODE
            )
            # The threat only exists inside an obfuscation layer, so the raw
            # payload cannot be sanitized safely — block it outright.
            verdict.verdict = "BLOCK"
            verdict.risk_level = self._max_risk(
                verdict.risk_level, candidate_verdict.risk_level, "HIGH"
            )
            verdict.recommendation = (
                "Block this payload. A decoded or normalized variant contains "
                "a threat hidden behind an obfuscation layer."
            )
            verdict.checks["decoder_wall"] = (
                f"fail - {transform} variant triggered {candidate_verdict.verdict.lower()} verdict"
            )
            for reason in [obfuscation_reason, *candidate_verdict.threat_classes]:
                if reason not in verdict.threat_classes:
                    verdict.threat_classes.append(reason)
                if reason not in verdict.failed_checks:
                    verdict.failed_checks.append(reason)
            for detection in candidate_verdict.detections:
                tagged = dict(detection)
                tagged["source"] = f"decoder_wall:{tagged.get('source', 'scanner')}"
                verdict.detections.append(tagged)
            return

    _RISK_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    @classmethod
    def _max_risk(cls, *levels: str) -> str:
        return max(levels, key=lambda level: cls._RISK_ORDER.index(level))

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
