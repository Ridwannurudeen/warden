"""Warden Shield scheduling, evidence, drift, and persistence contracts."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import api, audit_attestations, shield
from warden.badges import b64u_encode

NOW = 1_900_000_000
TARGET_URL = "https://agent.example.com/scan"
BATTERY_ID = "warden-core-http"
BATTERY_VERSION = "2026-07"
BATTERY_SHA256 = "7e18f89d7249fe97e007f37dc91839492cfb7a40af4d7b660309645c0fe33f3f"


@dataclass
class _QueuedAuditor:
    responses: list[object]

    def __post_init__(self) -> None:
        self.calls: list[str] = []

    async def audit(self, target_url: str) -> object:
        self.calls.append(target_url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _SlowAuditor:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls = 0

    async def audit(self, target_url: str) -> object:
        assert target_url == TARGET_URL
        self.calls += 1
        await asyncio.sleep(0.05)
        return self.response


class _FailingNotifier:
    async def notify(self, event: object) -> None:
        raise httpx.ConnectError("operator webhook unavailable")


def _hold_state_lock(path: str, acquired: object, release: object) -> None:
    with shield._exclusive_state_lock(Path(path)):
        acquired.set()
        if not release.wait(10):
            raise RuntimeError("test lock holder timed out")


def _observe_state_lock(path: str, acquired: object) -> None:
    with shield._exclusive_state_lock(Path(path)):
        acquired.set()


@pytest.fixture(autouse=True)
def _issuer(monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)


def _target(
    *,
    revision: int = 1,
    interval_hours: int = 24,
    target_url: str = TARGET_URL,
    owner_enrolled: bool = True,
    battery_id: str = BATTERY_ID,
    battery_version: str = BATTERY_VERSION,
    battery_sha256: str = BATTERY_SHA256,
) -> dict[str, object]:
    return {
        "target_id": "example-production",
        "owner_id": "example-owner",
        "owner_enrolled": owner_enrolled,
        "enrollment_revision": revision,
        "target_url": target_url,
        "interval_hours": interval_hours,
        "battery": {
            "id": battery_id,
            "version": battery_version,
            "sha256": battery_sha256,
        },
    }


def _write_config(path: Path, targets: list[dict[str, object]] | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "targets": [_target()] if targets is None else targets,
            }
        ),
        encoding="utf-8",
    )
    return path


def _response(audit_id: str, *, grade: str = "A") -> object:
    return SimpleNamespace(
        grade=grade,
        badge_record=(None if grade == "INCONCLUSIVE" else SimpleNamespace(audit_id=audit_id)),
    )


def _evidence(
    audit_id: str,
    *,
    blocked: int,
    issued_at: int,
    battery_id: str = BATTERY_ID,
    battery_version: str = BATTERY_VERSION,
    battery_sha256: str = BATTERY_SHA256,
    subject: str = TARGET_URL,
    status: str = "active",
) -> dict[str, object]:
    record = audit_attestations.issue_audit_attestation(
        audit_id=audit_id,
        subject=subject,
        endpoint_host="agent.example.com",
        battery_id=battery_id,
        battery_version=battery_version,
        battery_sha256=battery_sha256,
        blocked=blocked,
        total=20,
        benign_total=3,
        benign_passed=3,
        observed_on="2030-03-17",
        log_seq=1,
        issued_at=issued_at,
    )
    return {"attestation": record, "status": status, "revoked_at": None}


def _state(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_config_requires_explicit_bounded_canonical_owner_enrollments(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    loaded = shield.load_shield_config(config)

    assert len(loaded) == 1
    assert loaded[0].target_url == TARGET_URL
    assert loaded[0].battery_sha256 == BATTERY_SHA256

    _write_config(config, [_target(owner_enrolled=False)])
    with pytest.raises(ValueError, match="explicit owner enrollment"):
        shield.load_shield_config(config)

    _write_config(config, [_target(target_url=f"{TARGET_URL}?token=secret")])
    with pytest.raises(ValueError, match="without credentials, query, or fragment"):
        shield.load_shield_config(config)

    _write_config(config, [_target(interval_hours=shield.MAX_INTERVAL_HOURS + 1)])
    with pytest.raises(ValueError, match="interval_hours"):
        shield.load_shield_config(config)
    assert (
        shield.MAX_INTERVAL_HOURS * 60 * 60
        == audit_attestations.ATTESTATION_TTL_SECONDS - shield.RENEWAL_SAFETY_MARGIN_SECONDS
    )

    too_many = [
        {
            **_target(target_url=f"https://agent-{index}.example.com/scan"),
            "target_id": f"agent-{index}",
        }
        for index in range(shield.MAX_TARGETS + 1)
    ]
    _write_config(config, too_many)
    with pytest.raises(ValueError, match="invalid target count"):
        shield.load_shield_config(config)


def test_config_rejects_duplicate_keys_and_allows_an_explicit_empty_set(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1,"targets":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        shield.load_shield_config(duplicate)

    empty = _write_config(tmp_path / "empty.json", [])
    assert shield.load_shield_config(empty) == ()


@pytest.mark.asyncio
async def test_only_due_targets_run_and_initial_evidence_sets_the_schedule(tmp_path):
    config = _write_config(tmp_path / "targets.json", [_target(interval_hours=168)])
    state = tmp_path / "state.json"
    audit_id = "0000000000000001"
    auditor = _QueuedAuditor([_response(audit_id)])
    evidence = {audit_id: _evidence(audit_id, blocked=18, issued_at=NOW)}

    first = await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        now=NOW,
    )
    second = await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        now=NOW + 1,
    )

    assert auditor.calls == [TARGET_URL]
    assert first["due"] == 1
    assert first["initial"] == 1
    assert second["due"] == 0
    assert second["not_due"] == 1
    target_state = _state(state)["targets"]["example-production"]
    assert target_state["comparison"] == "initial"
    assert target_state["baseline"]["audit_id"] == audit_id
    assert target_state["next_due_at"] == NOW + (168 * 60 * 60)


@pytest.mark.asyncio
async def test_same_battery_score_drift_is_unchanged_regressed_then_improved(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    ids = [f"{index:016x}" for index in range(1, 5)]
    times = [NOW + (index * 24 * 60 * 60) for index in range(4)]
    blocked = [16, 16, 14, 19]
    auditor = _QueuedAuditor([_response(audit_id) for audit_id in ids])
    evidence = {
        audit_id: _evidence(audit_id, blocked=count, issued_at=observed_at)
        for audit_id, count, observed_at in zip(ids, blocked, times)
    }

    summaries = [
        await shield.run_due_audits(
            config,
            state,
            auditor=auditor,
            evidence_resolver=evidence.__getitem__,
            now=observed_at,
        )
        for observed_at in times
    ]

    assert [next(key for key in shield._COMPARISONS if summary[key]) for summary in summaries] == [
        "initial",
        "unchanged",
        "regressed",
        "improved",
    ]
    lifecycle = _state(state)
    assert [event["comparison"] for event in lifecycle["events"]] == [
        "initial",
        "unchanged",
        "regressed",
        "improved",
    ]
    assert lifecycle["events"][2]["notification"] == "not_configured"
    assert lifecycle["targets"]["example-production"]["baseline"]["audit_id"] == ids[-1]
    assert shield.service_exit_code(summaries[2]) == 1
    assert shield.service_exit_code(summaries[3]) == 0

    lineage = shield.get_certification_lineage(
        state,
        "example-production",
        evidence_resolver=evidence.__getitem__,
        now=times[-1],
    )
    assert lineage is not None
    assert [entry["attestation"]["audit_id"] for entry in lineage["entries"]] == ids
    assert [entry["comparison"] for entry in lineage["entries"]] == [
        "initial",
        "unchanged",
        "regressed",
        "improved",
    ]
    assert [entry["enrollment_revision"] for entry in lineage["entries"]] == [1, 1, 1, 1]
    assert all(entry["verified"] is True for entry in lineage["entries"])


@pytest.mark.asyncio
async def test_battery_change_is_inconclusive_and_does_not_replace_the_baseline(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    initial_id = "0000000000000001"
    changed_id = "0000000000000002"
    changed_hash = "b" * 64
    auditor = _QueuedAuditor([_response(initial_id), _response(changed_id)])
    evidence = {
        initial_id: _evidence(initial_id, blocked=18, issued_at=NOW),
        changed_id: _evidence(
            changed_id,
            blocked=20,
            issued_at=NOW + 86_400,
            battery_version="2026-08",
            battery_sha256=changed_hash,
        ),
    }

    await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        now=NOW,
    )
    changed = await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        now=NOW + 86_400,
    )

    lifecycle = _state(state)
    target_state = lifecycle["targets"]["example-production"]
    event = lifecycle["events"][-1]
    assert changed["inconclusive"] == 1
    assert target_state["reason"] == "battery_changed"
    assert target_state["baseline"]["audit_id"] == initial_id
    assert event["previous_evidence"]["audit_id"] == initial_id
    assert event["observed_evidence"]["audit_id"] == changed_id
    assert event["notification"] == "not_configured"


@pytest.mark.asyncio
async def test_failed_inconclusive_and_stale_audits_never_renew_prior_evidence(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    initial_id = "0000000000000001"
    stale_id = "0000000000000002"
    auditor = _QueuedAuditor(
        [
            _response(initial_id),
            ValueError("consent unavailable"),
            _response("0000000000000000", grade="INCONCLUSIVE"),
            _response(stale_id),
        ]
    )
    stale_run = NOW + (35 * 24 * 60 * 60)
    evidence_calls: list[str] = []
    evidence = {
        initial_id: _evidence(initial_id, blocked=18, issued_at=NOW),
        stale_id: _evidence(stale_id, blocked=20, issued_at=NOW),
    }

    def resolve(audit_id: str) -> dict[str, object]:
        evidence_calls.append(audit_id)
        return evidence[audit_id]

    summaries = []
    for observed_at in (NOW, NOW + 86_400, NOW + 172_800, stale_run):
        summaries.append(
            await shield.run_due_audits(
                config,
                state,
                auditor=auditor,
                evidence_resolver=resolve,
                now=observed_at,
            )
        )

    lifecycle = _state(state)
    assert [event["reason"] for event in lifecycle["events"]] == [
        "first_conclusive_audit",
        "audit_failed",
        "audit_inconclusive",
        "evidence_stale",
    ]
    assert lifecycle["targets"]["example-production"]["baseline"]["audit_id"] == initial_id
    assert evidence_calls == [initial_id, stale_id]
    assert [summary["inconclusive"] for summary in summaries] == [0, 1, 1, 1]

    lineage = shield.get_certification_lineage(
        state,
        "example-production",
        evidence_resolver=evidence.__getitem__,
        now=stale_run,
    )
    assert lineage is not None
    assert [entry["attestation"]["audit_id"] for entry in lineage["entries"]] == [initial_id]
    assert lineage["entries"][0]["status"] == "stale"


@pytest.mark.parametrize(
    ("failure_stage", "reason"),
    [
        ("audit", "audit_failed"),
        ("evidence", "evidence_unavailable"),
    ],
)
@pytest.mark.asyncio
async def test_runtime_configuration_failure_persists_metadata_only_inconclusive_event(
    tmp_path,
    failure_stage,
    reason,
):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    initial_id = "0000000000000001"
    next_id = "0000000000000002"
    await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(initial_id)]),
        evidence_resolver=lambda _audit_id: _evidence(
            initial_id,
            blocked=18,
            issued_at=NOW,
        ),
        now=NOW,
    )
    failure = RuntimeError("sensitive runtime configuration detail")
    auditor = _QueuedAuditor([failure if failure_stage == "audit" else _response(next_id)])

    def resolve(_audit_id: str) -> dict[str, object]:
        raise failure

    summary = await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=resolve,
        now=NOW + 86_400,
    )

    lifecycle = _state(state)
    target_state = lifecycle["targets"]["example-production"]
    event = lifecycle["events"][-1]
    serialized = json.dumps(event)
    assert summary["inconclusive"] == 1
    assert shield.service_exit_code(summary) == 1
    assert target_state["baseline"]["audit_id"] == initial_id
    assert event["comparison"] == "inconclusive"
    assert event["reason"] == reason
    assert event["previous_evidence"]["audit_id"] == initial_id
    assert event["observed_evidence"] is None
    assert event["notification"] == "not_configured"
    assert "RuntimeError" not in serialized
    assert "sensitive runtime configuration detail" not in serialized


@pytest.mark.asyncio
async def test_changed_enrollment_requires_a_revision_and_starts_a_new_baseline(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    initial_id = "0000000000000001"
    next_id = "0000000000000002"
    changed_hash = "c" * 64

    initial_evidence = _evidence(
        initial_id,
        blocked=18,
        issued_at=NOW,
    )
    await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(initial_id)]),
        evidence_resolver=lambda _audit_id: initial_evidence,
        now=NOW,
    )

    _write_config(config, [_target(interval_hours=48)])
    with pytest.raises(ValueError, match="without increasing enrollment_revision"):
        await shield.run_due_audits(
            config,
            state,
            auditor=_QueuedAuditor([]),
            evidence_resolver=lambda _audit_id: {},
            now=NOW + 1,
        )

    _write_config(
        config,
        [
            _target(
                revision=2,
                battery_version="2026-08",
                battery_sha256=changed_hash,
            )
        ],
    )
    next_evidence = _evidence(
        next_id,
        blocked=20,
        issued_at=NOW + 1,
        battery_version="2026-08",
        battery_sha256=changed_hash,
    )
    summary = await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(next_id)]),
        evidence_resolver=lambda _audit_id: next_evidence,
        now=NOW + 1,
    )

    target_state = _state(state)["targets"]["example-production"]
    assert summary["initial"] == 1
    assert target_state["enrollment_revision"] == 2
    assert target_state["baseline"]["audit_id"] == next_id
    assert target_state["last_conclusive_at"] == NOW + 1

    evidence = {initial_id: initial_evidence, next_id: next_evidence}
    lineage = shield.get_certification_lineage(
        state,
        "example-production",
        evidence_resolver=evidence.__getitem__,
        now=NOW + 1,
    )
    assert lineage is not None
    assert [entry["enrollment_revision"] for entry in lineage["entries"]] == [1, 2]
    assert [entry["comparison"] for entry in lineage["entries"]] == ["initial", "initial"]


@pytest.mark.asyncio
async def test_lineage_verifies_retired_issuer_key_history(tmp_path, monkeypatch):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    audit_id = "0000000000000001"
    retired_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(retired_key.private_bytes_raw(), "ed25519-seed"),
    )
    evidence = _evidence(audit_id, blocked=18, issued_at=NOW)

    current_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(current_key.private_bytes_raw(), "ed25519-seed"),
    )
    history = tmp_path / "issuer-history.json"
    history.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "retired-issuer",
                        "pub": b64u_encode(
                            retired_key.public_key().public_bytes_raw(),
                            "ed25519",
                        ),
                        "not_after": NOW,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WARDEN_ISSUER_HISTORY", str(history))

    await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(audit_id)]),
        evidence_resolver=lambda _audit_id: evidence,
        now=NOW,
    )

    lineage = shield.get_certification_lineage(
        state,
        "example-production",
        evidence_resolver=lambda _audit_id: evidence,
        now=NOW,
    )
    assert lineage is not None
    assert lineage["entries"][0]["verified"] is True

    monkeypatch.delenv("WARDEN_ISSUER_HISTORY")
    with pytest.raises(ValueError, match="failed issuer verification"):
        shield.get_certification_lineage(
            state,
            "example-production",
            evidence_resolver=lambda _audit_id: evidence,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_legacy_lineage_event_is_read_without_guessing_its_revision(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    audit_id = "0000000000000001"
    evidence = _evidence(audit_id, blocked=18, issued_at=NOW)
    await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(audit_id)]),
        evidence_resolver=lambda _audit_id: evidence,
        now=NOW,
    )
    lifecycle = _state(state)
    del lifecycle["events"][0]["enrollment_revision"]
    state.write_text(json.dumps(lifecycle), encoding="utf-8")

    lineage = shield.get_certification_lineage(
        state,
        "example-production",
        evidence_resolver=lambda _audit_id: evidence,
        now=NOW,
    )

    assert lineage is not None
    assert lineage["entries"][0]["enrollment_revision"] is None


@pytest.mark.asyncio
async def test_lineage_route_is_read_only_and_not_a_paid_route(tmp_path, monkeypatch):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    audit_id = "0000000000000001"
    evidence = _evidence(audit_id, blocked=18, issued_at=NOW)
    await shield.run_due_audits(
        config,
        state,
        auditor=_QueuedAuditor([_response(audit_id)]),
        evidence_resolver=lambda _audit_id: evidence,
        now=NOW,
    )
    monkeypatch.setattr(api, "SHIELD_STATE_PATH", state)
    monkeypatch.setattr(
        shield.protection_store,
        "get_audit_attestation_with_evidence",
        lambda _audit_id, *, record_validator: (
            evidence if record_validator(evidence["attestation"]) else None
        ),
    )

    response = TestClient(api.app).get("/api/shield/example-production/lineage")

    assert response.status_code == 200
    assert response.json()["entries"][0]["attestation"]["audit_id"] == audit_id
    assert "GET /api/shield/example-production/lineage" not in getattr(api, "_paid_routes", {})


@pytest.mark.asyncio
async def test_event_retention_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(shield, "MAX_EVENTS", 3)
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    ids = [f"{index:016x}" for index in range(1, 6)]
    auditor = _QueuedAuditor([_response(audit_id) for audit_id in ids])
    evidence = {
        audit_id: _evidence(
            audit_id,
            blocked=18,
            issued_at=NOW + (index * 86_400),
        )
        for index, audit_id in enumerate(ids)
    }

    for index in range(len(ids)):
        await shield.run_due_audits(
            config,
            state,
            auditor=auditor,
            evidence_resolver=evidence.__getitem__,
            now=NOW + (index * 86_400),
        )

    events = _state(state)["events"]
    assert len(events) == 3
    assert [event["observed_evidence"]["audit_id"] for event in events] == ids[-3:]


def test_state_lock_is_cross_process(tmp_path):
    state_path = str(tmp_path / "state.json")
    context = multiprocessing.get_context("spawn")
    first_acquired = context.Event()
    release_first = context.Event()
    second_acquired = context.Event()
    first = context.Process(
        target=_hold_state_lock,
        args=(state_path, first_acquired, release_first),
    )
    second = context.Process(
        target=_observe_state_lock,
        args=(state_path, second_acquired),
    )
    first.start()
    try:
        assert first_acquired.wait(10)
        second.start()
        assert not second_acquired.wait(0.2)
        release_first.set()
        assert second_acquired.wait(10)
    finally:
        release_first.set()
        first.join(10)
        if second.pid is not None:
            second.join(10)
        if first.is_alive():
            first.terminate()
        if second.pid is not None and second.is_alive():
            second.terminate()
    assert first.exitcode == 0
    assert second.exitcode == 0


def test_concurrent_runners_audit_one_due_target_once(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    audit_id = "0000000000000001"
    auditor = _SlowAuditor(_response(audit_id))
    evidence = _evidence(audit_id, blocked=18, issued_at=NOW)

    def run() -> dict[str, int]:
        return asyncio.run(
            shield.run_due_audits(
                config,
                state,
                auditor=auditor,
                evidence_resolver=lambda _audit_id: evidence,
                now=NOW,
            )
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        summaries = [future.result() for future in (executor.submit(run), executor.submit(run))]

    assert auditor.calls == 1
    assert sorted(summary["due"] for summary in summaries) == [0, 1]
    assert len(_state(state)["events"]) == 1


@pytest.mark.asyncio
async def test_https_notifier_sends_only_bounded_event_metadata():
    previous = {
        "audit_id": "0000000000000001",
        "battery_id": BATTERY_ID,
        "battery_version": BATTERY_VERSION,
        "battery_sha256": BATTERY_SHA256,
        "blocked": 18,
        "total": 20,
        "score": 90.0,
        "observed_on": "2030-03-17",
        "issued_at": NOW,
        "expires_at": NOW + audit_attestations.ATTESTATION_TTL_SECONDS,
    }
    observed = {**previous, "audit_id": "0000000000000002", "blocked": 16, "score": 80.0}
    event = shield._event(
        target_id="example-production",
        enrollment_revision=1,
        comparison="regressed",
        reason="same_battery_score_decreased",
        occurred_at=NOW + 86_400,
        previous=previous,
        observed=observed,
    )
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads((await request.aread()).decode())
        captured["idempotency"] = request.headers["Idempotency-Key"]
        return httpx.Response(204)

    notifier = shield.HttpsShieldNotifier(
        "https://alerts.example.com/warden",
        transport=httpx.MockTransport(handler),
    )
    await notifier.notify(event)

    body = captured["body"]
    assert isinstance(body, dict)
    serialized = json.dumps(body)
    assert captured["idempotency"] == event["event_id"]
    assert set(body) == {
        "schema_version",
        "event_id",
        "target_id",
        "comparison",
        "reason",
        "occurred_at",
        "previous_evidence",
        "observed_evidence",
        "action",
    }
    for forbidden in ("target_url", "owner_id", "payload", "signature", "recommendations"):
        assert forbidden not in serialized

    with pytest.raises(ValueError, match="must be HTTPS"):
        shield.HttpsShieldNotifier("http://alerts.example.com/warden")


@pytest.mark.asyncio
async def test_notifier_failure_is_persisted_and_returns_a_failed_service_outcome(tmp_path):
    config = _write_config(tmp_path / "targets.json")
    state = tmp_path / "state.json"
    initial_id = "0000000000000001"
    regressed_id = "0000000000000002"
    auditor = _QueuedAuditor([_response(initial_id), _response(regressed_id)])
    evidence = {
        initial_id: _evidence(initial_id, blocked=18, issued_at=NOW),
        regressed_id: _evidence(regressed_id, blocked=15, issued_at=NOW + 86_400),
    }

    await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        now=NOW,
    )
    summary = await shield.run_due_audits(
        config,
        state,
        auditor=auditor,
        evidence_resolver=evidence.__getitem__,
        notifier=_FailingNotifier(),
        now=NOW + 86_400,
    )

    assert summary["regressed"] == 1
    assert summary["notification_failures"] == 1
    assert shield.service_exit_code(summary) == 1
    assert _state(state)["events"][-1]["notification"] == "failed"


def test_default_evidence_resolution_reuses_badge_to_portable_publication_path(monkeypatch):
    audit_id = "0000000000000001"
    badge = {"audit_id": audit_id, "badge_version": 2}
    portable = {"audit_id": audit_id}
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(shield.badge_store, "get_badge", lambda value: badge)
    monkeypatch.setattr(shield, "verify_badge", lambda value: value is badge)

    def publish(value: object) -> dict[str, object]:
        calls.append(("publish", value))
        return portable

    def read(value: str, *, record_validator: object) -> dict[str, object]:
        calls.append(("read", (value, record_validator)))
        return {"attestation": portable, "status": "active", "revoked_at": None}

    monkeypatch.setattr(shield.audit_attestations, "publish_from_badge", publish)
    monkeypatch.setattr(
        shield.protection_store,
        "get_audit_attestation_with_evidence",
        read,
    )

    assert shield._resolve_published_evidence(audit_id)["attestation"] == portable
    assert calls == [
        ("publish", badge),
        ("read", (audit_id, shield.audit_attestations.verify_audit_attestation)),
    ]
