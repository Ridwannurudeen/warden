"""Regression tests for isolated-operation timeout accounting."""

import subprocess

import pytest

from tests.subprocess_helpers import run_python_operation_after_startup


def test_worker_startup_is_not_charged_to_operation_timeout():
    run_python_operation_after_startup(
        setup="import time\ntime.sleep(0.1)",
        operation="pass",
        timeout=0.05,
    )


def test_worker_operation_timeout_remains_enforced():
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_python_operation_after_startup(
            setup="import time",
            operation="time.sleep(0.1)",
            timeout=0.05,
        )

    assert exc_info.value.timeout == 0.05
