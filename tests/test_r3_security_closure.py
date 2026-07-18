"""Regressions for the deferred R3 security and release gates."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from warden.api import app


ROOT = Path(__file__).resolve().parents[1]


def test_mcp_entrypoint_pins_stdio_transport() -> None:
    module = ast.parse((ROOT / "warden" / "mcp_server.py").read_text(encoding="utf-8"))
    run_calls = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "mcp"
        and node.func.attr == "run"
    ]

    assert len(run_calls) == 1
    transport = next(
        (keyword.value for keyword in run_calls[0].keywords if keyword.arg == "transport"),
        None,
    )
    assert isinstance(transport, ast.Constant)
    assert transport.value == "stdio"


def test_configured_cors_origin_is_exact_and_unconfigured_origin_is_rejected() -> None:
    preflight_headers = {
        "Access-Control-Request-Method": "POST",
        "Origin": "https://warden.gudman.xyz",
    }
    with TestClient(app) as client:
        allowed = client.options("/api/demo/scan", headers=preflight_headers)
        rejected = client.options(
            "/api/demo/scan",
            headers={**preflight_headers, "Origin": "https://attacker.example"},
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://warden.gudman.xyz"
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert "access-control-allow-origin" not in rejected.headers


def test_wildcard_cors_never_enables_credentials() -> None:
    script = """
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from warden.api import app

cors = next(middleware for middleware in app.user_middleware if middleware.cls is CORSMiddleware)
assert cors.kwargs["allow_origins"] == ["*"]
assert cors.kwargs["allow_credentials"] is False
with TestClient(app) as client:
    response = client.options(
        "/api/demo/scan",
        headers={
            "Access-Control-Request-Method": "POST",
            "Origin": "https://attacker.example",
        },
    )
assert response.status_code == 200
assert response.headers["access-control-allow-origin"] == "*"
assert "access-control-allow-credentials" not in response.headers
"""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OKX_")
        and key not in {"PAY_TO_ADDRESS", "WARDEN_REQUIRE_PAYWALL"}
    }
    environment["WARDEN_CORS_ORIGINS"] = "*"

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_ci_runs_locked_dependency_and_distribution_security_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read\n" in workflow
    assert "python -m pip install --require-hashes -r requirements.lock" in workflow
    assert "python -m pip_audit --require-hashes -r requirements.lock" in workflow
    assert "python -m build --no-isolation" in workflow
    assert "python -m twine check dist/*" in workflow
    assert "python -m pytest -q tests/test_r4_distribution.py" in workflow
    assert "python -m pytest -q sdk/python/tests" in workflow
    assert "npm test" in workflow
    assert "npm run build" in workflow
    assert "npm pack --dry-run" in workflow
    assert "npm audit --audit-level=high" in workflow
    assert "python spec/verify_apa.py --selftest" in workflow


def test_python_dependency_lock_is_exact_and_hashed() -> None:
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    records: list[str] = []
    current: list[str] = []
    for line in lock.splitlines():
        if not line.strip() or (not current and line.lstrip().startswith("#")):
            continue
        if current and not line[0].isspace():
            records.append("\n".join(current))
            current = []
        current.append(line)
    if current:
        records.append("\n".join(current))

    assert records
    for record in records:
        requirement = record.splitlines()[0]
        assert "==" in requirement
        assert "--hash=sha256:" in record


def test_public_scan_price_and_corpus_count_match_runtime_contract() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    payment = (ROOT / "PAYMENT.md").read_text(encoding="utf-8")
    ui_audit = (ROOT / "docs" / "UI_AUDIT.md").read_text(encoding="utf-8")
    challenge = json.loads(
        (ROOT / "tests" / "fixtures" / "payment_required.json").read_text(encoding="utf-8")
    )
    attack_count = sum(
        bool(line.strip())
        for line in (ROOT / "corpus" / "attacks.jsonl").read_text(encoding="utf-8").splitlines()
    )

    assert attack_count == 94
    assert "94 attack cases" in readme
    assert "0.01 USDT" not in payment
    assert "0.01 USDT" not in ui_audit
    assert challenge["scan"]["accepts"][0]["amount"] == "500000"
