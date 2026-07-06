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
        verdict.latency_ms = self._elapsed_ms(started)
        return verdict

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((perf_counter() - started) * 1000, 3)
