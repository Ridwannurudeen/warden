"""Badge issuance, verification, and lookup tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from warden import badge_store
from warden.api import app
from warden.badge_store import get_badge, record_badge
from warden.badges import issue_badge, verify_badge


@pytest.fixture(autouse=True)
def _badge_secret(monkeypatch):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "badge-test-secret")


def test_issue_badge_verify_round_trip():
    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )

    assert verify_badge(badge)


def test_tampered_badge_fails_verification():
    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    badge["score"] = 12.5

    assert not verify_badge(badge)


def test_audit_id_deterministic_for_same_inputs():
    first = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    second = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )

    assert first["audit_id"] == second["audit_id"]


def test_badge_store_round_trip(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    record_badge(badge)

    assert get_badge(badge["audit_id"]) == badge


def test_badge_store_append_is_atomic_and_durable(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    record_badge(badge)

    # Every persisted line must be a complete, parseable JSON object (no partial
    # write, and terminated with a newline) so a crash cannot leave a torn record.
    raw = store_path.read_bytes()
    assert raw.endswith(b"\n")
    lines = [line for line in raw.decode("utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0]) == badge


def test_badge_store_concurrent_writes_do_not_interleave(tmp_path, monkeypatch):
    import threading

    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badges = [
        issue_badge(
            target_host=f"api-{index}.example.org",
            score=90.0,
            grade="A",
            blocked=20,
            total=20,
            issued_at="2026-07-06",
        )
        for index in range(24)
    ]

    barrier = threading.Barrier(len(badges))

    def _writer(record):
        barrier.wait()
        record_badge(record)

    threads = [threading.Thread(target=_writer, args=(badge,)) for badge in badges]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    lines = [line for line in store_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    parsed = [json.loads(line) for line in lines]
    assert len(parsed) == len(badges)
    assert {record["audit_id"] for record in parsed} == {badge["audit_id"] for badge in badges}


def test_badge_lookup_route_returns_verified(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    badge = issue_badge(
        target_host="api.example.org",
        score=82.5,
        grade="B",
        blocked=16,
        total=20,
        issued_at="2026-07-06",
    )
    record_badge(badge)

    with TestClient(app) as client:
        response = client.get(f"/badge/{badge['audit_id']}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["verified"] is True
    assert payload["badge"]["audit_id"] == badge["audit_id"]


def test_badge_lookup_unknown_id_returns_404():
    with TestClient(app) as client:
        response = client.get("/badge/does-not-exist")

    assert response.status_code == 404
    assert response.json()["detail"] == "Badge not found"


def test_badge_registry_returns_empty_list_when_store_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("warden.badge_store._STORE_PATH", tmp_path / "missing.jsonl")

    with TestClient(app) as client:
        response = client.get("/api/badges")

    assert response.status_code == 200
    assert response.json() == {"badges": [], "total": 0}


def test_badge_registry_verifies_each_record_and_only_returns_public_fields(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    verified_badge = issue_badge(
        target_host="verified.acme-agents.io",
        score=90.0,
        grade="A",
        blocked=18,
        total=20,
        issued_at="2026-07-12",
    )
    record_badge(verified_badge)

    tampered_badge = issue_badge(
        target_host="tampered.acme-agents.io",
        score=75.0,
        grade="C",
        blocked=15,
        total=20,
        issued_at="2026-07-13",
    )
    tampered_badge["score"] = 10.0
    tampered_badge["internal_only"] = "redacted"
    record_badge(tampered_badge)

    with TestClient(app) as client:
        response = client.get("/api/badges")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["badges"][0]["verified"] is False
    assert "internal_only" not in payload["badges"][0]["badge"]
    assert payload["badges"][1] == {"badge": verified_badge, "verified": True}


def test_badge_store_retains_only_the_newest_bounded_records(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr(badge_store, "_STORE_PATH", store_path)
    monkeypatch.setattr(badge_store, "_MAX_RECORDS", 3)
    badges = [
        issue_badge(
            target_host=f"api-{index}.example.org",
            score=90.0,
            grade="A",
            blocked=20,
            total=20,
            issued_at=f"2026-07-{index + 1:02d}",
        )
        for index in range(5)
    ]

    for badge in badges:
        record_badge(badge)

    persisted = [
        json.loads(line) for line in store_path.read_text(encoding="utf-8").splitlines() if line
    ]
    assert persisted == badges[-3:]
    assert get_badge(str(badges[0]["audit_id"])) is None
    assert get_badge(str(badges[-1]["audit_id"])) == badges[-1]


def test_badge_store_failed_atomic_replace_preserves_previous_records(
    tmp_path,
    monkeypatch,
):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr(badge_store, "_STORE_PATH", store_path)
    first = issue_badge(
        target_host="first.example.org",
        score=90.0,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-18",
    )
    second = issue_badge(
        target_host="second.example.org",
        score=90.0,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-19",
    )
    record_badge(first)
    original = store_path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(badge_store.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failure"):
        record_badge(second)

    assert store_path.read_bytes() == original
    assert not list(tmp_path.glob(".issued.jsonl.*.tmp"))


def test_badge_store_serializes_writers_across_processes(tmp_path):
    store_path = tmp_path / "issued.jsonl"
    worker = """
import sys
from pathlib import Path
from warden import badge_store
from warden.badges import issue_badge

badge_store._STORE_PATH = Path(sys.argv[1])
offset = int(sys.argv[2])
for index in range(10):
    badge_store.record_badge(
        issue_badge(
            target_host=f"api-{offset + index}.example.org",
            score=90.0,
            grade="A",
            blocked=20,
            total=20,
            issued_at="2026-07-18",
        )
    )
"""
    environment = {**os.environ, "WARDEN_BADGE_SECRET": "badge-test-secret"}
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", worker, str(store_path), str(offset)],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for offset in range(0, 40, 10)
    ]

    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stdout + stderr

    records = [
        json.loads(line) for line in store_path.read_text(encoding="utf-8").splitlines() if line
    ]
    assert len(records) == 40
    assert len({record["audit_id"] for record in records}) == 40


def test_public_registry_excludes_reserved_test_domains_without_deleting_them(
    tmp_path, monkeypatch
):
    """Audits fired at RFC 2606 names are scaffolding, not evidence about anyone's
    endpoint, so they must not pad the public registry — but the store keeps them."""
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr("warden.badge_store._STORE_PATH", store_path)

    real = issue_badge(
        target_host="agents.acme-corp.io",
        score=90.0,
        grade="A",
        blocked=18,
        total=20,
        issued_at="2026-07-12",
    )
    record_badge(real)
    for reserved_host in (
        "example.com",
        "EXAMPLE.ORG.",
        "example.net:8443",
        "smoke.example.com",
        "localhost",
        "fixture.test",
        "nothing.invalid",
    ):
        record_badge(
            issue_badge(
                target_host=reserved_host,
                score=0.0,
                grade="F",
                blocked=0,
                total=20,
                issued_at="2026-07-13",
            )
        )

    # Nothing is destroyed: the raw store still holds every record.
    assert len(badge_store.list_badges()) == 8
    published = badge_store.list_public_badges()
    assert [record["target_host"] for record in published] == ["agents.acme-corp.io"]

    with TestClient(app) as client:
        response = client.get("/api/badges")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["badges"][0]["badge"]["target_host"] == "agents.acme-corp.io"
