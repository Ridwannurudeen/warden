"""Transactional idempotency coverage for the deterministic executor."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from warden.executor.config import DEFAULT_IDEMPOTENCY_STORE_PATH
from warden.executor.guardrails import IdempotencyStore


def test_concurrent_claims_have_exactly_one_winner(tmp_path: Path):
    path = tmp_path / "executor-idempotency.sqlite3"
    workers = 16
    barrier = threading.Barrier(workers)

    def claim() -> bool:
        store = IdempotencyStore(str(path))
        barrier.wait()
        return store.claim("job-concurrent")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _: claim(), range(workers)))

    assert results.count(True) == 1
    assert results.count(False) == workers - 1
    assert IdempotencyStore(str(path)).status("job-concurrent") == "pending"


def test_pending_and_delivered_states_survive_restarts(tmp_path: Path):
    path = tmp_path / "nested" / "executor-idempotency.sqlite3"
    first = IdempotencyStore(str(path))

    assert first.status("job-restart") is None
    assert first.claim("job-restart") is True
    assert first.status("job-restart") == "pending"
    assert first.already_delivered("job-restart") is False

    restarted = IdempotencyStore(str(path))
    assert restarted.status("job-restart") == "pending"
    assert restarted.claim("job-restart") is False
    restarted.mark_delivered("job-restart")

    delivered = IdempotencyStore(str(path))
    assert delivered.status("job-restart") == "delivered"
    assert delivered.already_delivered("job-restart") is True
    assert delivered.claim("job-restart") is False


def test_legacy_json_path_migrates_and_retains_its_projection(tmp_path: Path):
    legacy_path = tmp_path / "delivered.json"
    legacy_path.write_text(
        json.dumps({"delivered": ["job-legacy"]}, indent=2),
        encoding="utf-8",
    )

    store = IdempotencyStore(str(legacy_path))
    assert store.status("job-legacy") == "delivered"
    assert store.claim("job-legacy") is False
    assert store.claim("job-new") is True
    store.mark_delivered("job-new")

    assert json.loads(legacy_path.read_text(encoding="utf-8")) == {
        "delivered": ["job-legacy", "job-new"]
    }
    database_path = legacy_path.with_suffix(f"{legacy_path.suffix}.sqlite3")
    assert database_path.read_bytes().startswith(b"SQLite format 3")

    legacy_path.write_text(json.dumps({"delivered": []}), encoding="utf-8")
    assert IdempotencyStore(str(legacy_path)).status("job-new") == "delivered"


def test_default_store_path_names_a_sqlite_database():
    assert DEFAULT_IDEMPOTENCY_STORE_PATH == "data/executor-idempotency.sqlite3"
