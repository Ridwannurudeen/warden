"""CI regressions for independently exercised optional Python adapters."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_installs_and_runs_optional_python_adapters() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert 'python -m pip install -e "sdk/python[dev,langchain,llamaindex]"' in workflow
    assert "permissions:\n  contents: read\n" in workflow
    assert "python -m pytest -q sdk/python/tests" in workflow


def test_optional_adapter_tests_skip_independently() -> None:
    langchain_test = (ROOT / "sdk" / "python" / "tests" / "test_langchain_adapter.py").read_text(
        encoding="utf-8"
    )
    llamaindex_test = (ROOT / "sdk" / "python" / "tests" / "test_llamaindex_adapter.py").read_text(
        encoding="utf-8"
    )

    assert 'pytest.importorskip("langchain_core")' in langchain_test
    assert "llama_index" not in langchain_test
    assert 'pytest.importorskip("llama_index.core")' in llamaindex_test
    assert "langchain_core" not in llamaindex_test
