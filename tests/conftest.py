import pytest

from warden.engine import WardenEngine
from warden.scanner.scanner import InjectionScanner


@pytest.fixture(autouse=True)
def _isolated_variant_audit_store(tmp_path, monkeypatch):
    """Keep retained variant audit reports out of the working tree.

    A completed audit persists its signed report, so without this every test
    that runs one would append to the real store.
    """
    monkeypatch.setenv(
        "WARDEN_VARIANT_AUDIT_STORE",
        str(tmp_path / "variant-audit-reports.jsonl"),
    )


@pytest.fixture
def scanner():
    return InjectionScanner(ai_analyzer=None)


@pytest.fixture
def engine():
    return WardenEngine()
