"""Operational regressions for monthly SLI evidence and transition alerts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from scripts import notify_service_transition
from scripts.notify_service_transition import notify_transition
from scripts.summarize_service_monitor import (
    build_monthly_summary,
    summarize_monitor,
)


def _component(status: str, http_status: int | None) -> dict[str, object]:
    return {
        "status": status,
        "http_status": http_status,
        "latency_ms": 10.0,
    }


def _sample(
    checked_at: str,
    *,
    application: str = "ready",
    x402_challenge: str = "ready",
) -> dict[str, object]:
    return {
        "checked_at": checked_at,
        "application": _component(
            application,
            200 if application == "ready" else 503,
        ),
        "x402_challenge": _component(
            x402_challenge,
            402 if x402_challenge == "ready" else None,
        ),
    }


def _monitor(*samples: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 2,
        "status": "collecting",
        "samples": list(samples),
    }


def _write_monitor(path, *samples: dict[str, object]) -> None:
    path.write_text(json.dumps(_monitor(*samples)), encoding="utf-8")


def _now(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_monthly_summary_counts_missing_and_degraded_slots_as_unavailable():
    document = _monitor(
        _sample("2026-02-01T00:00:05Z"),
        _sample("2026-02-01T00:04:55Z", application="error"),
        _sample("2026-02-01T00:05:01Z"),
    )
    source = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()

    summary = build_monthly_summary(document, "2026-02", source)

    assert summary == {
        "schema_version": 1,
        "month": "2026-02",
        "cadence_seconds": 300,
        "expected_slots": 8_064,
        "observed_slots": 2,
        "complete": False,
        "components": {
            "application": {
                "ready_slots": 1,
                "availability_percent": 0.0124,
            },
            "x402_challenge": {
                "ready_slots": 2,
                "readiness_percent": 0.0248,
            },
        },
        "source_sha256": hashlib.sha256(source).hexdigest(),
    }
    assert build_monthly_summary(document, "2026-02", source) == summary


def test_monthly_summary_write_is_atomic_and_refuses_symlink_output(
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "service-monitor.json"
    _write_monitor(source, _sample("2026-02-01T00:00:05Z"))
    output = tmp_path / "service-level.json"

    summary = summarize_monitor(source, output, "2026-02")

    assert json.loads(output.read_text()) == summary
    link = tmp_path / "linked-summary.json"
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == link or original_is_symlink(path),
    )
    with pytest.raises(ValueError, match="symbolic link"):
        summarize_monitor(source, link, "2026-02")


def test_notifier_sends_only_degradation_and_recovery_transitions(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(204)

    environment = {"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"}
    transport = httpx.MockTransport(handler)
    ready = _sample("2026-07-18T10:00:00Z")
    _write_monitor(monitor_path, ready)

    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "initialized"
    )
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "unchanged"
    )
    degraded = _sample("2026-07-18T10:05:00Z", x402_challenge="error")
    _write_monitor(monitor_path, ready, degraded)
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:05:00Z"),
        )
        == "notified"
    )
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:05:00Z"),
        )
        == "unchanged"
    )
    recovered = _sample("2026-07-18T10:10:00Z")
    _write_monitor(monitor_path, ready, degraded, recovered)
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:10:00Z"),
        )
        == "notified"
    )

    assert requests == [
        {
            "schema_version": 2,
            "event": "warden.service.degraded",
            "state": "degraded",
            "previous_state": "ready",
            "monitor_state": "collecting",
            "observed_at": "2026-07-18T10:05:00Z",
            "latest_sample_at": "2026-07-18T10:05:00Z",
            "components": {
                "application": "ready",
                "x402_challenge": "error",
            },
        },
        {
            "schema_version": 2,
            "event": "warden.service.recovered",
            "state": "ready",
            "previous_state": "degraded",
            "monitor_state": "collecting",
            "observed_at": "2026-07-18T10:10:00Z",
            "latest_sample_at": "2026-07-18T10:10:00Z",
            "components": {
                "application": "ready",
                "x402_challenge": "ready",
            },
        },
    ]


def test_notifier_alerts_on_the_first_degraded_observation(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    _write_monitor(
        monitor_path,
        _sample("2026-07-18T10:00:00Z", x402_challenge="disabled"),
    )
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(204)

    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ={"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"},
            transport=httpx.MockTransport(handler),
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "notified"
    )
    assert requests[0]["previous_state"] == "unknown"
    assert requests[0]["components"]["x402_challenge"] == "disabled"


def test_failed_notification_is_retried_without_advancing_state(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    environment = {"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"}
    ready = _sample("2026-07-18T10:00:00Z")
    _write_monitor(monitor_path, ready)
    notify_transition(
        monitor_path,
        state_path,
        environ=environment,
        transport=httpx.MockTransport(lambda request: httpx.Response(204)),
        now=_now("2026-07-18T10:00:00Z"),
    )

    degraded = _sample("2026-07-18T10:05:00Z", application="error")
    _write_monitor(monitor_path, ready, degraded)
    with pytest.raises(httpx.HTTPStatusError):
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=httpx.MockTransport(lambda request: httpx.Response(503)),
            now=_now("2026-07-18T10:05:00Z"),
        )
    assert json.loads(state_path.read_text())["last_state"] == "ready"

    attempts = 0

    def recovered_transport(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(204)

    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=httpx.MockTransport(recovered_transport),
            now=_now("2026-07-18T10:05:00Z"),
        )
        == "notified"
    )
    assert attempts == 1


def test_notifier_rejects_monitor_evidence_older_than_its_state(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    environment = {"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"}
    _write_monitor(monitor_path, _sample("2026-07-18T10:05:00Z"))
    transport = httpx.MockTransport(lambda request: httpx.Response(204))
    notify_transition(
        monitor_path,
        state_path,
        environ=environment,
        transport=transport,
        now=_now("2026-07-18T10:05:00Z"),
    )

    _write_monitor(monitor_path, _sample("2026-07-18T10:00:00Z"))

    with pytest.raises(ValueError, match="older"):
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:05:00Z"),
        )
    assert json.loads(state_path.read_text())["last_sample_at"] == ("2026-07-18T10:05:00Z")


def test_notifier_dead_man_alerts_on_stale_evidence_and_recovers(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    environment = {"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"}
    requests: list[dict[str, object]] = []
    transport = httpx.MockTransport(
        lambda request: requests.append(json.loads(request.content)) or httpx.Response(204)
    )
    ready = _sample("2026-07-18T10:00:00Z")
    _write_monitor(monitor_path, ready)
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "initialized"
    )

    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:10:01Z"),
        )
        == "notified"
    )
    assert requests[-1]["monitor_state"] == "stale"
    assert requests[-1]["components"] == {
        "application": "ready",
        "x402_challenge": "ready",
    }

    recovered = _sample("2026-07-18T10:15:00Z")
    _write_monitor(monitor_path, ready, recovered)
    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ=environment,
            transport=transport,
            now=_now("2026-07-18T10:15:00Z"),
        )
        == "notified"
    )
    assert requests[-1]["event"] == "warden.service.recovered"


def test_notifier_exposes_a_not_running_monitor_state(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    state_path = tmp_path / "notifier-state.json"
    monitor_path.write_text(
        json.dumps({"schema_version": 2, "status": "not_running", "samples": []}),
        encoding="utf-8",
    )
    requests: list[dict[str, object]] = []

    assert (
        notify_transition(
            monitor_path,
            state_path,
            environ={"WARDEN_ALERT_WEBHOOK_URL": "https://alerts.example.test/warden"},
            transport=httpx.MockTransport(
                lambda request: requests.append(json.loads(request.content)) or httpx.Response(204)
            ),
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "notified"
    )
    assert requests[0]["monitor_state"] == "not_running"
    assert requests[0]["latest_sample_at"] is None
    assert json.loads(state_path.read_text())["last_monitor_state"] == "not_running"


def test_notifier_accepts_a_root_managed_private_https_destination(tmp_path):
    monitor_path = tmp_path / "service-monitor.json"
    _write_monitor(monitor_path, _sample("2026-07-18T10:00:00Z", application="error"))
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(204)

    assert (
        notify_transition(
            monitor_path,
            tmp_path / "state.json",
            environ={"WARDEN_ALERT_WEBHOOK_URL": "https://127.0.0.1/warden"},
            transport=httpx.MockTransport(handler),
            now=_now("2026-07-18T10:00:00Z"),
        )
        == "notified"
    )
    assert calls == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://alerts.example.test/warden",
        "https://user:password@alerts.example.test/warden",
        "https://alerts.example.test/warden#secret",
    ],
)
def test_notifier_rejects_non_https_or_credential_bearing_webhooks(tmp_path, url):
    monitor_path = tmp_path / "service-monitor.json"
    _write_monitor(monitor_path, _sample("2026-07-18T10:00:00Z"))

    with pytest.raises(ValueError, match="HTTPS"):
        notify_transition(
            monitor_path,
            tmp_path / "state.json",
            environ={"WARDEN_ALERT_WEBHOOK_URL": url},
            transport=httpx.MockTransport(lambda request: httpx.Response(204)),
            now=_now("2026-07-18T10:00:00Z"),
        )


def test_notifier_command_fails_without_printing_a_secret_webhook_url(
    monkeypatch,
    capsys,
):
    secret_url = "https://alerts.example.test/hooks/secret-token"

    def fail(*args, **kwargs):
        raise httpx.ConnectError(
            "connection failed",
            request=httpx.Request("POST", secret_url),
        )

    monkeypatch.setattr(notify_service_transition, "notify_transition", fail)

    assert notify_service_transition.main([]) == 1
    output = capsys.readouterr()
    assert "secret-token" not in output.out
    assert "secret-token" not in output.err
    assert "notification failed" in output.err.lower()
