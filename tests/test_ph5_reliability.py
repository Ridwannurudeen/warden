"""PH5 readiness and bounded monitor regressions."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scripts import monitor_readiness
from scripts.monitor_readiness import (
    EXPECTED_X402_AMOUNT,
    EXPECTED_X402_ASSET,
    EXPECTED_X402_EIP712_NAME,
    EXPECTED_X402_EIP712_VERSION,
    EXPECTED_X402_NETWORK,
    EXPECTED_X402_PAY_TO,
    EXPECTED_X402_RESOURCE_URL,
    EXPECTED_X402_SCHEME,
    probe_readiness,
    probe_x402_challenge,
    record_probe,
)
from warden.api import app


client = TestClient(app)


class _Response:
    def __init__(
        self,
        payload: object,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ):
        self.status = status
        self.headers = headers or {}
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


def _x402_challenge() -> dict[str, object]:
    return {
        "x402Version": 2,
        "resource": {"url": EXPECTED_X402_RESOURCE_URL},
        "accepts": [
            {
                "scheme": EXPECTED_X402_SCHEME,
                "network": EXPECTED_X402_NETWORK,
                "payTo": EXPECTED_X402_PAY_TO,
                "amount": EXPECTED_X402_AMOUNT,
                "asset": EXPECTED_X402_ASSET,
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": EXPECTED_X402_EIP712_NAME,
                    "version": EXPECTED_X402_EIP712_VERSION,
                },
            }
        ],
    }


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
                    },
                    "paid_routes": {
                        "status": "ready",
                        "detail": "Configured.",
                    },
                    "semantic_model": {
                        "status": "disabled",
                        "detail": "Optional.",
                    },
                },
            }
        )

    application = probe_readiness(
        "http://127.0.0.1:8000/health/ready",
        timeout_seconds=1.5,
        opener=opener,
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.125)).__next__,
    )
    record = {
        "checked_at": application.pop("checked_at"),
        "application": application,
        "x402_challenge": {
            "status": "ready",
            "http_status": 402,
            "latency_ms": 40.0,
        },
    }
    output = tmp_path / "service-monitor.json"
    published = record_probe(record, output_path=output, max_samples=2)

    assert calls == [("http://127.0.0.1:8000/health/ready", 1.5)]
    assert application == {
        "status": "ready",
        "http_status": 200,
        "latency_ms": 125.0,
    }
    assert published["status"] == "collecting"
    assert published["samples"] == [record]
    assert json.loads(output.read_text(encoding="utf-8")) == published


def test_paid_route_probe_validates_the_frozen_x402_challenge_without_paying():
    calls: list[tuple[str, str, bytes, float]] = []
    challenge = base64.b64encode(json.dumps(_x402_challenge()).encode("utf-8")).decode("ascii")

    def opener(request, *, timeout):
        calls.append((request.full_url, request.method, request.data, timeout))
        return _Response(
            {"error": "Payment required"},
            status=402,
            headers={"PAYMENT-REQUIRED": challenge},
        )

    record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        timeout_seconds=1.5,
        opener=opener,
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.04)).__next__,
    )

    assert record == {
        "checked_at": "2026-07-16T17:00:00Z",
        "status": "ready",
        "http_status": 402,
        "latency_ms": 40.0,
    }
    assert calls == [
        (
            "http://127.0.0.1:8000/scan",
            "POST",
            b'{"payload":"Warden scheduled payment-path readiness probe."}',
            1.5,
        )
    ]


def test_paid_route_probe_distinguishes_disabled_and_malformed_challenge():
    def disabled(request, *, timeout):
        return _Response({"verdict": "ALLOW"}, status=200)

    disabled_record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=disabled,
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.01)).__next__,
    )

    def malformed(request, *, timeout):
        return _Response(
            {"error": "Payment required"},
            status=402,
            headers={"PAYMENT-REQUIRED": "not-base64"},
        )

    malformed_record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=malformed,
        checked_at="2026-07-16T17:01:00Z",
        timer=iter((20.0, 20.02)).__next__,
    )

    assert disabled_record["status"] == "disabled"
    assert disabled_record["http_status"] == 200
    assert malformed_record["status"] == "error"
    assert malformed_record["http_status"] == 402


@pytest.mark.parametrize(
    "challenge",
    [
        [],
        {"x402Version": 2, "resource": [], "accepts": []},
        {"x402Version": 2, "resource": {"url": EXPECTED_X402_RESOURCE_URL}, "accepts": {}},
        {
            "x402Version": 2,
            "resource": {"url": EXPECTED_X402_RESOURCE_URL},
            "accepts": [[]],
        },
    ],
)
def test_x402_probe_records_malformed_arrays_and_objects_as_error(challenge):
    encoded = base64.b64encode(json.dumps(challenge).encode()).decode()

    record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=lambda request, timeout: _Response(
            {},
            status=402,
            headers={"PAYMENT-REQUIRED": encoded},
        ),
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.01)).__next__,
    )

    assert record["status"] == "error"
    assert record["http_status"] == 402


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scheme", "upto"),
        ("network", "eip155:1"),
        ("payTo", "0x0000000000000000000000000000000000000000"),
        ("amount", "1"),
        ("asset", "0x0000000000000000000000000000000000000000"),
    ],
)
def test_x402_probe_requires_every_pinned_payment_field(field, value):
    challenge = _x402_challenge()
    challenge["accepts"][0][field] = value
    encoded = base64.b64encode(json.dumps(challenge).encode()).decode()

    record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=lambda request, timeout: _Response(
            {},
            status=402,
            headers={"PAYMENT-REQUIRED": encoded},
        ),
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.01)).__next__,
    )

    assert record["status"] == "error"


@pytest.mark.parametrize(
    "extra",
    [
        None,
        {},
        {"name": "USDT", "version": "1"},
        {"name": "USD₮0", "version": "2"},
        {"name": "USD₮0", "version": "1", "salt": "unexpected"},
    ],
)
def test_x402_probe_requires_exact_eip712_domain_metadata(extra):
    challenge = _x402_challenge()
    if extra is None:
        challenge["accepts"][0].pop("extra")
    else:
        challenge["accepts"][0]["extra"] = extra
    encoded = base64.b64encode(json.dumps(challenge).encode()).decode()

    record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=lambda request, timeout: _Response(
            {},
            status=402,
            headers={"PAYMENT-REQUIRED": encoded},
        ),
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.01)).__next__,
    )

    assert record["status"] == "error"


@pytest.mark.parametrize(
    "resource_url",
    [
        "https://attacker.example/scan",
        "https://warden.gudman.xyz/audit",
        "https://warden.gudman.xyz/scan?changed=true",
    ],
)
def test_x402_probe_requires_the_pinned_resource_origin_and_path(resource_url):
    challenge = _x402_challenge()
    challenge["resource"]["url"] = resource_url
    encoded = base64.b64encode(json.dumps(challenge).encode()).decode()

    record = probe_x402_challenge(
        "http://127.0.0.1:8000/scan",
        opener=lambda request, timeout: _Response(
            {},
            status=402,
            headers={"PAYMENT-REQUIRED": encoded},
        ),
        checked_at="2026-07-16T17:00:00Z",
        timer=iter((10.0, 10.01)).__next__,
    )

    assert record["status"] == "error"


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


@pytest.mark.parametrize(
    "checks",
    [
        {},
        {"deterministic_scanner": {"status": "ready", "detail": "Loaded."}},
        {
            "deterministic_scanner": {"status": "ready", "detail": "Loaded."},
            "paid_routes": {"status": "ready", "detail": "Configured."},
            "semantic_model": {"status": "disabled", "detail": "Optional."},
            "unexpected": {"status": "ready", "detail": "Unexpected."},
        },
        [],
    ],
)
def test_readiness_probe_requires_the_exact_documented_check_set(checks):
    record = probe_readiness(
        "http://127.0.0.1:8000/health/ready",
        opener=lambda request, timeout: _Response(
            {"status": "ready", "version": "0.1.0", "checks": checks}
        ),
        checked_at="2026-07-16T17:01:00Z",
        timer=iter((20.0, 20.01)).__next__,
    )

    assert record["status"] == "error"


def test_readiness_probe_does_not_call_disabled_paid_routes_ready():
    record = probe_readiness(
        "http://127.0.0.1:8000/health/ready",
        opener=lambda request, timeout: _Response(
            {
                "status": "ready",
                "version": "0.1.0",
                "checks": {
                    "deterministic_scanner": {
                        "status": "ready",
                        "detail": "Loaded.",
                    },
                    "paid_routes": {
                        "status": "disabled",
                        "detail": "Not configured.",
                    },
                    "semantic_model": {
                        "status": "disabled",
                        "detail": "Optional.",
                    },
                },
            }
        ),
        checked_at="2026-07-16T17:01:00Z",
        timer=iter((20.0, 20.01)).__next__,
    )

    assert record["status"] == "not_ready"
    assert record["http_status"] == 200


def test_monitor_rejects_nonfinite_latency(tmp_path):
    with pytest.raises(ValueError, match="latency"):
        record_probe(
            {
                "checked_at": "2026-07-16T17:01:00Z",
                "application": {
                    "status": "ready",
                    "http_status": 200,
                    "latency_ms": float("nan"),
                },
                "x402_challenge": {
                    "status": "ready",
                    "http_status": 402,
                    "latency_ms": 10.0,
                },
            },
            output_path=tmp_path / "service-monitor.json",
        )


def test_monitor_history_is_bounded_and_refuses_symlink_output(tmp_path, monkeypatch):
    output = tmp_path / "service-monitor.json"
    for minute, status in enumerate(("ready", "not_ready", "ready")):
        record_probe(
            {
                "checked_at": f"2026-07-16T17:0{minute}:00Z",
                "application": {
                    "status": status,
                    "http_status": 200 if status == "ready" else 503,
                    "latency_ms": float(10 + minute),
                },
                "x402_challenge": {
                    "status": "ready",
                    "http_status": 402,
                    "latency_ms": float(20 + minute),
                },
            },
            output_path=output,
            max_samples=2,
        )

    published = json.loads(output.read_text(encoding="utf-8"))
    assert [sample["application"]["status"] for sample in published["samples"]] == [
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


def test_monitor_command_records_degraded_evidence_without_skipping_notifier(
    tmp_path,
    monkeypatch,
):
    record = {
        "checked_at": "2026-07-16T17:00:00Z",
        "application": {
            "status": "error",
            "http_status": None,
            "latency_ms": 2_000.0,
        },
        "x402_challenge": {
            "status": "error",
            "http_status": None,
            "latency_ms": 2_000.0,
        },
    }
    monkeypatch.setattr(monitor_readiness, "probe_service", lambda *args, **kwargs: record)
    output = tmp_path / "service-monitor.json"

    result = monitor_readiness.main(["--output", str(output)])

    assert result == 0
    assert json.loads(output.read_text())["samples"] == [record]


def test_status_surface_publishes_an_unmeasured_objective_not_an_uptime_claim():
    root = Path(__file__).resolve().parents[1]
    html = (root / "site" / "status.html").read_text(encoding="utf-8")
    normalized_html = " ".join(html.split())
    monitor = json.loads((root / "site" / "data" / "service-monitor.json").read_text())

    assert "99.5% application-readiness objective" in normalized_html
    assert "not a contractual SLA" in normalized_html
    assert "does not establish payment settlement or facilitator uptime" in normalized_html
    assert "data-monitor-challenge-readiness" in html
    assert monitor == {"schema_version": 2, "status": "not_running", "samples": []}
