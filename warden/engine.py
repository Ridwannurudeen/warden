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
from warden.core.verdict import Verdict, VerdictEngine
from warden.scanner.scanner import InjectionScanner


class WardenEngine:
    def __init__(self):
        self.scanner = InjectionScanner(ai_analyzer=None)
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
    ) -> Verdict:
        started = perf_counter()
        if payload is None:
            verdict = self.verdict_engine.decide(None, None, [])
            verdict.latency_ms = self._elapsed_ms(started)
            return verdict

        scan_context = context or {}
        expected_addresses = scan_context.get("expected_addresses", [])
        scanner_result = await self.scanner.scan(payload, depth=depth)
        analyzer_context = AnalysisContext(
            address="",
            extra={
                "payload": payload,
                "expected_addresses": expected_addresses if isinstance(expected_addresses, list) else [],
            },
        )
        analyzer_results = await self.registry.run_all(analyzer_context)
        verdict = self.verdict_engine.decide(payload, scanner_result, analyzer_results)
        if verdict.verdict == "SANITIZE":
            sanitized_scanner_result = await self.scanner.scan(
                verdict.sanitized_payload,
                depth=depth,
            )
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
            sanitized_verdict = self.verdict_engine.decide(
                verdict.sanitized_payload,
                sanitized_scanner_result,
                sanitized_analyzer_results,
            )
            if sanitized_verdict.verdict == "ALLOW":
                verdict.checks["sanitization_validation"] = "pass - sanitized payload rescanned clean"
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
        verdict.latency_ms = self._elapsed_ms(started)
        return verdict

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
