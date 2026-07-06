import pytest

from warden.engine import WardenEngine
from warden.scanner.scanner import InjectionScanner


@pytest.fixture
def scanner():
    return InjectionScanner(ai_analyzer=None)


@pytest.fixture
def engine():
    return WardenEngine()
