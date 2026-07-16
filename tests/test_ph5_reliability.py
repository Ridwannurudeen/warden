"""PH5 readiness and bounded monitor regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scripts.monitor_readiness import probe_readiness, record_probe
from warden.api import app


client = TestClient(app)


class _Response:
    def __init__(self, payload: dict[str, object], status: int = 200):
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


def test_readiness_is_additive_and_reports_optional_layers_honestly():
    response = client.get("/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["version"]
    assert payload["checks"]["deterministic_scanner"]["status"] == "ready"
    assert payload["checks"]["paid_routes"]["status"] == "disabled"
    assert payload["checks"]["semantic_model"]["status"] == "disabled"


def test_readiness_fails_closed_when_paid_mode_loses_required_configuration(monkeypatch):
    monkeypatch.setenv("WARDEN_REQUIRE_PAYWALL", "1")
    for name in (
        "OKX_API_KEY",
        "OKX_SECRET_KEY",
        "OKX_PASSPHRASE",
        "PAY_TO_ADDRESS",
        "WARDEN_BADGE_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)

    response = client.get("/health/ready")

    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["checks"]["paid_routes"] == {
        "status": "not_ready",
        "detail": "Required paid-route configuration is incomplete.",
    }
    assert "OKX" not in json.dumps(payload)


def test_monitor_probe_is_bounded_and_records_a_ready_response(tmp_path):
    calls: list[tuple[str, float]] = []

    def opener(request, *, timeout):
        calls.append((request.full_url, timeout))
        return _Response(
            {
                "status": "ready",
                "version": "0.1.0",
                "checks": {
                    "deterministic_scanner": {
                        "status": "ready",
                        "detail": "Loaded.",
                    }
                },
            }
        )

    record = probe_readiness(
        "http://127.0.0.1:8000/health/ready",
        timeout_seconds=1.5,
        opener=opener,
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.125)).__next__,
    )
    output = tmp_path / "service-monitor.json"
    published = record_probe(record, output_path=output, max_samples=2)

    assert calls == [("http://127.0.0.1:8000/health/ready", 1.5)]
    assert record == {
        "checked_at": "2026-07-16T17:00:00Z",
        "status": "ready",
        "http_status": 200,
        "latency_ms": 125.0,
    }
    assert published["status"] == "collecting"
    assert published["samples"] == [record]
    assert json.loads(output.read_text(encoding="utf-8")) == published


def test_monitor_records_malformed_or_unreachable_readiness_as_error():
    def malformed(request, *, timeout):
        return _Response({"status": "ready"})

    record = probe_readiness(
        "http://127.0.0.1:8000/health/ready",
        opener=malformed,
        checked_at="2026-07-16T17:01:00Z",
        timer=iter((20.0, 20.05)).__next__,
    )

    assert record == {
        "checked_at": "2026-07-16T17:01:00Z",
        "status": "error",
        "http_status": None,
        "latency_ms": 50.0,
    }


def test_monitor_history_is_bounded_and_refuses_symlink_output(tmp_path, monkeypatch):
    output = tmp_path / "service-monitor.json"
    for minute, status in enumerate(("ready", "not_ready", "ready")):
        record_probe(
            {
                "checked_at": f"2026-07-16T17:0{minute}:00Z",
                "status": status,
                "http_status": 200 if status == "ready" else 503,
                "latency_ms": float(10 + minute),
            },
            output_path=output,
            max_samples=2,
        )

    published = json.loads(output.read_text(encoding="utf-8"))
    assert [sample["status"] for sample in published["samples"]] == [
        "not_ready",
        "ready",
    ]

    link = tmp_path / "linked.json"
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == link or original_is_symlink(path),
    )
    with pytest.raises(ValueError, match="symbolic link"):
        record_probe(published["samples"][-1], output_path=link)

    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == link.parent or original_is_symlink(path),
    )
    with pytest.raises(ValueError, match="parent must not be a symbolic link"):
        record_probe(published["samples"][-1], output_path=link)


def test_status_surface_publishes_an_unmeasured_objective_not_an_uptime_claim():
    root = Path(__file__).resolve().parents[1]
    html = (root / "site" / "status.html").read_text(encoding="utf-8")
    monitor = json.loads((root / "site" / "data" / "service-monitor.json").read_text())

    assert "99.5% application-readiness objective" in html
    assert "not a contractual SLA" in html
    assert "Third-party payment-facilitator availability is outside this measurement" in html
    assert monitor == {"schema_version": 1, "status": "not_running", "samples": []}
