import logging

import pytest

from warden.core.analyzer import AnalysisContext, Analyzer
from warden.core.registry import AnalyzerRegistry


class FailingAnalyzer(Analyzer):
    @property
    def name(self):
        return "failing"

    @property
    def weight(self):
        return 1.0

    async def analyze(self, ctx):
        raise RuntimeError("sensitive-marker-from-upstream")


@pytest.mark.asyncio
async def test_analyzer_exception_does_not_expose_sensitive_message(caplog):
    registry = AnalyzerRegistry()
    registry.register(FailingAnalyzer())

    with caplog.at_level(logging.ERROR):
        results = await registry.run_all(AnalysisContext(address=""))

    assert results[0].error == "analysis unavailable"
    assert "sensitive-marker-from-upstream" not in caplog.text
    assert "RuntimeError" in caplog.text
