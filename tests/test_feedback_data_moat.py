"""Opt-in feedback, aggregate threat intelligence, and human review boundaries."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import multiprocessing
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from scripts import build_threat_report, review_feedback
from warden import __version__, feedback_store, ratelimit, threat_intel
from warden.api import app
from warden.core.verdict import ReasonCode
from warden.models import FeedbackRequest


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


def _request(
    reproducer: str,
    *,
    outcome: str = "missed_attack",
    observed_verdict: str = "ALLOW",
    threat_class: str = "PROMPT_INJECTION",
) -> FeedbackRequest:
    return FeedbackRequest.model_validate(
        {
            "outcome": outcome,
            "observed_verdict": observed_verdict,
            "threat_class": threat_class,
            "redacted_reproducer": reproducer,
            "consent_to_retain": True,
            "redaction_confirmed": True,
        }
    )


def _record(
    request: FeedbackRequest,
    *,
    now: datetime = NOW,
) -> dict[str, object]:
    return feedback_store.record_feedback(
        request,
        scanner_version=__version__,
        corpus_fingerprint="sha256:" + "a" * 64,
        now=now,
    )


def _load_module_copy(name: str):
    spec = importlib.util.spec_from_file_location(name, feedback_store.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _submit_feedback_process(store_path, start, results) -> None:
    from warden import feedback_store as process_store

    process_store._STORE_PATH = Path(store_path)
    if not start.wait(10):
        raise RuntimeError("feedback process start signal timed out")
    request = FeedbackRequest.model_validate(
        {
            "outcome": "missed_attack",
            "observed_verdict": "ALLOW",
            "threat_class": "PROMPT_INJECTION",
            "redacted_reproducer": "Cross-process consented redacted reproducer.",
            "consent_to_retain": True,
            "redaction_confirmed": True,
        }
    )
    results.put(
        process_store.record_feedback(
            request,
            scanner_version=__version__,
            corpus_fingerprint="sha256:" + "a" * 64,
            now=NOW,
        )
    )


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    ratelimit._reset_state()
    yield
    ratelimit._reset_state()


def test_feedback_request_is_strict_and_requires_explicit_redaction_consent():
    valid = _request("Reviewer-safe authorization bypass [REDACTED].")
    assert valid.consent_to_retain is True
    assert valid.redaction_confirmed is True

    base = valid.model_dump()
    for mutation in (
        {**base, "payload": "raw private payload"},
        {**base, "consent_to_retain": False},
        {**base, "consent_to_retain": 1},
        {**base, "redaction_confirmed": False},
        {**base, "redaction_confirmed": 1},
        {**base, "redacted_reproducer": "   "},
        {**base, "redacted_reproducer": "x" * 4_001},
        {**base, "outcome": "missed_attack", "observed_verdict": "BLOCK"},
        {**base, "outcome": "false_positive", "observed_verdict": "ALLOW"},
    ):
        with pytest.raises(ValidationError):
            FeedbackRequest.model_validate(mutation)


def test_feedback_request_rejects_text_that_cannot_be_encoded_as_utf8():
    with pytest.raises(ValidationError, match="unicode"):
        _request("redacted lone surrogate \ud800")


def test_feedback_api_rejects_a_lone_surrogate_without_an_internal_error(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    body = (
        b'{"outcome":"missed_attack","observed_verdict":"ALLOW",'
        b'"threat_class":"PROMPT_INJECTION",'
        b'"redacted_reproducer":"redacted lone surrogate \\ud800",'
        b'"consent_to_retain":true,"redaction_confirmed":true}'
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/feedback",
            content=body,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 422
    assert not path.exists()


def test_store_suppresses_duplicates_and_retains_one_redacted_reproducer(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    request = _request("A consented redacted reproducer [REDACTED].")

    first = _record(request)
    duplicate = _record(request, now=NOW + timedelta(minutes=1))

    assert first["status"] == "pending"
    assert duplicate == {**first, "status": "duplicate"}
    [stored] = _jsonl(path)
    assert stored["feedback_id"] == first["feedback_id"]
    assert stored["redacted_reproducer"] == request.redacted_reproducer
    assert stored["consent_to_retain"] is True
    assert stored["redaction_confirmed"] is True
    assert "payload" not in stored
    assert "identity" not in stored
    assert "endpoint" not in stored


def test_store_prunes_expired_records_and_enforces_a_hard_record_cap(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    monkeypatch.setattr(feedback_store, "_MAX_RECORDS", 2)
    monkeypatch.setattr(feedback_store, "_RETENTION_DAYS", 30)

    _record(_request("expired redacted one"), now=NOW - timedelta(days=31))
    _record(_request("retained redacted two"), now=NOW - timedelta(days=2))
    _record(_request("retained redacted three"), now=NOW - timedelta(days=1))
    _record(_request("retained redacted four"), now=NOW)

    records = feedback_store.list_feedback(now=NOW)

    assert [record["redacted_reproducer"] for record in records] == [
        "retained redacted three",
        "retained redacted four",
    ]
    assert _jsonl(path) == records


def test_feedback_store_uses_the_persistent_writable_data_path(monkeypatch):
    monkeypatch.delenv("WARDEN_FEEDBACK_STORE", raising=False)
    production_path = feedback_store.ROOT / "data" / "feedback" / "pending.jsonl"

    assert feedback_store._configured_store_path() == production_path
    service = (feedback_store.ROOT / "deploy" / "warden.service").read_text(encoding="utf-8")
    assert "ReadWritePaths=/opt/warden/data " in service


def test_corpus_fingerprint_uses_packaged_provenance_without_source_corpus(tmp_path, monkeypatch):
    packaged = tmp_path / "corpus_fingerprint.txt"
    packaged.write_text("a" * 64 + "\n", encoding="ascii")
    monkeypatch.setattr(
        feedback_store,
        "_TRAINING_ATTACKS_PATH",
        tmp_path / "missing-attacks.jsonl",
    )
    monkeypatch.setattr(
        feedback_store,
        "_TRAINING_BENIGN_PATH",
        tmp_path / "missing-benign.jsonl",
    )
    monkeypatch.setattr(feedback_store, "_PACKAGED_CORPUS_FINGERPRINT_PATH", packaged)

    assert feedback_store.corpus_fingerprint() == "sha256:" + "a" * 64


def test_corpus_fingerprint_is_stable_across_source_line_endings(tmp_path, monkeypatch):
    attacks = tmp_path / "attacks.jsonl"
    benign = tmp_path / "benign.jsonl"
    attacks.write_bytes(b'{"payload":"attack one"}\r\n{"payload":"attack two"}\r\n')
    benign.write_bytes(b'{"payload":"benign"}\r\n')
    monkeypatch.setattr(feedback_store, "_TRAINING_ATTACKS_PATH", attacks)
    monkeypatch.setattr(feedback_store, "_TRAINING_BENIGN_PATH", benign)
    canonical = b'{"payload":"attack one"}\n{"payload":"attack two"}\n{"payload":"benign"}\n'

    assert feedback_store.corpus_fingerprint() == (
        "sha256:" + hashlib.sha256(canonical).hexdigest()
    )


def test_duplicate_submission_is_cross_process_serialized(tmp_path):
    first_module = _load_module_copy("feedback_writer_one")
    second_module = _load_module_copy("feedback_writer_two")
    path = tmp_path / "pending.jsonl"
    first_module._STORE_PATH = path
    second_module._STORE_PATH = path
    request = _request("Concurrent consented redacted reproducer.")
    barrier = threading.Barrier(8)
    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def submit(module) -> None:
        try:
            barrier.wait(timeout=2)
            results.append(
                module.record_feedback(
                    request,
                    scanner_version=__version__,
                    corpus_fingerprint="sha256:" + "a" * 64,
                    now=NOW,
                )
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(
            target=submit,
            args=(first_module if index % 2 else second_module,),
        )
        for index in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert len(_jsonl(path)) == 1
    assert sum(result["status"] == "pending" for result in results) == 1
    assert sum(result["status"] == "duplicate" for result in results) == 7
    assert len({result["feedback_id"] for result in results}) == 1


def test_duplicate_submission_is_serialized_across_spawned_processes(tmp_path):
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    path = tmp_path / "pending.jsonl"
    processes = [
        context.Process(
            target=_submit_feedback_process,
            args=(str(path), start, results),
        )
        for _ in range(4)
    ]

    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)

    assert all(not process.is_alive() for process in processes)
    assert [process.exitcode for process in processes] == [0, 0, 0, 0]
    submissions = [results.get(timeout=2) for _ in processes]
    assert len(_jsonl(path)) == 1
    assert sum(result["status"] == "pending" for result in submissions) == 1
    assert sum(result["status"] == "duplicate" for result in submissions) == 3
    assert len({result["feedback_id"] for result in submissions}) == 1


def test_feedback_api_is_additive_rate_limited_and_scan_never_records_feedback(
    tmp_path, monkeypatch
):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    monkeypatch.setenv("WARDEN_FEEDBACK_RATE_LIMIT_PER_MIN", "2")
    body = _request("API redacted reproducer one.").model_dump(mode="json")
    headers = {"x-real-ip": "203.0.113.44"}

    with TestClient(app) as client:
        scan = client.post("/scan", json={"payload": "normal settlement note"}, headers=headers)
        first = client.post("/api/feedback", json=body, headers=headers)
        duplicate = client.post("/api/feedback", json=body, headers=headers)
        limited = client.post(
            "/api/feedback",
            json=_request("API redacted reproducer two.").model_dump(mode="json"),
            headers=headers,
        )

    assert scan.status_code == 200
    assert first.status_code == 202
    assert duplicate.status_code == 202
    assert limited.status_code == 429
    assert limited.headers["Retry-After"]
    assert first.json()["status"] == "pending"
    assert duplicate.json() == {**first.json(), "status": "duplicate"}
    assert len(_jsonl(path)) == 1


def test_feedback_api_rejects_raw_payload_and_arbitrary_metadata(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    body = _request("Redacted reproducer.").model_dump(mode="json")
    body.update(
        {
            "payload": "raw payload",
            "wallet": "0x1111111111111111111111111111111111111111",
        }
    )

    with TestClient(app) as client:
        response = client.post("/api/feedback", json=body)

    assert response.status_code == 422
    assert not path.exists()


def test_threat_intel_route_exposes_only_k_anonymous_aggregates(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    private_reproducers: list[str] = []
    for index in range(5):
        reproducer = f"missed private redacted example {index}"
        private_reproducers.append(reproducer)
        _record(_request(reproducer), now=NOW + timedelta(minutes=index))
    for index in range(4):
        reproducer = f"false-positive private redacted example {index}"
        private_reproducers.append(reproducer)
        _record(
            _request(
                reproducer,
                outcome="false_positive",
                observed_verdict="BLOCK",
                threat_class="SECRET_EXFIL",
            ),
            now=NOW + timedelta(minutes=10 + index),
        )

    with TestClient(app) as client:
        response = client.get("/api/threat-intel/v1/summary")

    assert response.status_code == 200
    summary = response.json()
    assert set(summary) == {
        "schema_version",
        "generated_at",
        "window_start",
        "window_end",
        "k_anonymity",
        "included_records",
        "cells",
        "source",
        "limitations",
    }
    assert summary["k_anonymity"] == 5
    assert summary["included_records"] == 5
    assert summary["window_start"] == "2026-07-18T00:00:00Z"
    assert summary["cells"] == [
        {
            "outcome": "missed_attack",
            "threat_class": "PROMPT_INJECTION",
            "count": 5,
        }
    ]
    serialized = json.dumps(summary, sort_keys=True)
    for forbidden in (
        *private_reproducers,
        "feedback_id",
        "dedupe",
        "digest",
        "sha256",
        "wallet",
        "endpoint",
        "identity",
    ):
        assert forbidden not in serialized


def test_threat_intel_route_has_a_separate_read_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    monkeypatch.setenv("WARDEN_THREAT_INTEL_RATE_LIMIT_PER_MIN", "2")
    headers = {"x-real-ip": "203.0.113.45"}

    with TestClient(app) as client:
        assert client.get("/api/threat-intel/v1/summary", headers=headers).status_code == 200
        assert client.get("/api/threat-intel/v1/summary", headers=headers).status_code == 200
        limited = client.get("/api/threat-intel/v1/summary", headers=headers)

    assert limited.status_code == 429
    assert limited.headers["Retry-After"]


def _dataset_paths(tmp_path: Path) -> dict[str, Path]:
    paths = {
        "training_attacks_path": tmp_path / "corpus" / "attacks.jsonl",
        "training_benign_path": tmp_path / "corpus" / "benign.jsonl",
        "held_out_attacks_path": tmp_path / "benchmark" / "held_out_attacks.jsonl",
        "held_out_benign_path": tmp_path / "benchmark" / "held_out_benign.jsonl",
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    return paths


def test_human_review_promotes_to_exactly_one_dataset_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    paths = _dataset_paths(tmp_path)
    pending = _record(_request("Human-reviewed redacted attack reproducer."))

    with pytest.raises(ValueError, match="human reviewer"):
        feedback_store.promote_feedback(
            str(pending["feedback_id"]),
            destination="held-out",
            category=ReasonCode.PROMPT_INJECTION,
            reviewer_approved=False,
            reviewed_at=NOW,
            **paths,
        )

    first = feedback_store.promote_feedback(
        str(pending["feedback_id"]),
        destination="held-out",
        category=ReasonCode.PROMPT_INJECTION,
        reviewer_approved=True,
        reviewed_at=NOW,
        **paths,
    )
    second = feedback_store.promote_feedback(
        str(pending["feedback_id"]),
        destination="held-out",
        category=ReasonCode.PROMPT_INJECTION,
        reviewer_approved=True,
        reviewed_at=NOW + timedelta(minutes=1),
        **paths,
    )

    assert first == second
    assert len(_jsonl(paths["held_out_attacks_path"])) == 1
    assert _jsonl(paths["held_out_benign_path"]) == []
    assert _jsonl(paths["training_attacks_path"]) == []
    assert _jsonl(paths["training_benign_path"]) == []
    [stored] = _jsonl(tmp_path / "pending.jsonl")
    assert stored["status"] == "promoted"
    assert stored["promotion"]["destination"] == "held-out"
    with pytest.raises(ValueError, match="already promoted"):
        feedback_store.promote_feedback(
            str(pending["feedback_id"]),
            destination="training",
            category=ReasonCode.PROMPT_INJECTION,
            expected_verdict="BLOCK",
            reviewer_approved=True,
            reviewed_at=NOW,
            **paths,
        )


def test_concurrent_reviews_with_separate_queues_serialize_dataset_updates(
    tmp_path,
):
    first_module = _load_module_copy("feedback_review_writer_one")
    second_module = _load_module_copy("feedback_review_writer_two")
    first_module._STORE_PATH = tmp_path / "first-pending.jsonl"
    second_module._STORE_PATH = tmp_path / "second-pending.jsonl"
    paths = _dataset_paths(tmp_path)
    first = first_module.record_feedback(
        _request("First independently reviewed redacted reproducer."),
        scanner_version=__version__,
        corpus_fingerprint="sha256:" + "a" * 64,
        now=NOW,
    )
    second = second_module.record_feedback(
        _request("Second independently reviewed redacted reproducer."),
        scanner_version=__version__,
        corpus_fingerprint="sha256:" + "a" * 64,
        now=NOW,
    )

    first_inside_append = threading.Event()
    second_inside_append = threading.Event()
    release_first = threading.Event()
    first_append = first_module._append_jsonl_entry
    second_append = second_module._append_jsonl_entry

    def hold_first_append(path, entry) -> None:
        first_inside_append.set()
        if not release_first.wait(3):
            raise RuntimeError("first append release timed out")
        first_append(path, entry)

    def observe_second_append(path, entry) -> None:
        second_inside_append.set()
        second_append(path, entry)

    first_module._append_jsonl_entry = hold_first_append
    second_module._append_jsonl_entry = observe_second_append
    errors: list[BaseException] = []

    def promote(module, feedback_id: str) -> None:
        try:
            module.promote_feedback(
                feedback_id,
                destination="held-out",
                category=ReasonCode.PROMPT_INJECTION,
                reviewer_approved=True,
                reviewed_at=NOW,
                **paths,
            )
        except BaseException as exc:
            errors.append(exc)

    first_thread = threading.Thread(
        target=promote,
        args=(first_module, str(first["feedback_id"])),
    )
    second_thread = threading.Thread(
        target=promote,
        args=(second_module, str(second["feedback_id"])),
    )
    first_thread.start()
    assert first_inside_append.wait(2)
    second_thread.start()
    second_entered_before_first_finished = second_inside_append.wait(0.25)
    release_first.set()
    first_thread.join(timeout=3)
    second_thread.join(timeout=3)

    assert not errors
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered_before_first_finished is False
    assert {entry["payload"] for entry in _jsonl(paths["held_out_attacks_path"])} == {
        "First independently reviewed redacted reproducer.",
        "Second independently reviewed redacted reproducer.",
    }


def test_false_positive_promotes_only_to_benign_training(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    paths = _dataset_paths(tmp_path)
    pending = _record(
        _request(
            "Human-reviewed benign reproducer.",
            outcome="false_positive",
            observed_verdict="BLOCK",
            threat_class="SECRET_EXFIL",
        )
    )

    result = feedback_store.promote_feedback(
        str(pending["feedback_id"]),
        destination="training",
        category=ReasonCode.SECRET_EXFIL,
        reviewer_approved=True,
        reviewed_at=NOW,
        **paths,
    )

    assert result["dataset"] == "training-benign"
    [entry] = _jsonl(paths["training_benign_path"])
    assert entry["payload"] == "Human-reviewed benign reproducer."
    assert entry["expected_verdict"] == "ALLOW"
    assert _jsonl(paths["training_attacks_path"]) == []
    assert _jsonl(paths["held_out_attacks_path"]) == []
    assert _jsonl(paths["held_out_benign_path"]) == []


def test_review_rejects_cross_dataset_payload_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    paths = _dataset_paths(tmp_path)
    reproducer = "Already used normalized reproducer."
    paths["training_attacks_path"].write_text(
        json.dumps(
            {
                "id": "existing",
                "category": "PROMPT_INJECTION",
                "payload": reproducer,
                "expected_verdict": "BLOCK",
                "expected_classes": ["PROMPT_INJECTION"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    pending = _record(_request("  already   used NORMALIZED reproducer.  "))

    with pytest.raises(ValueError, match="existing training or held-out"):
        feedback_store.promote_feedback(
            str(pending["feedback_id"]),
            destination="held-out",
            category=ReasonCode.PROMPT_INJECTION,
            reviewer_approved=True,
            reviewed_at=NOW,
            **paths,
        )


@pytest.mark.parametrize(
    "variant",
    [
        "Already used N\u200bFKC reproducer.",
        "Already used \uff2e\uff26\uff2b\uff23 reproducer.",
    ],
)
def test_review_rejects_scanner_equivalent_unicode_overlap(variant, tmp_path, monkeypatch):
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    paths = _dataset_paths(tmp_path)
    paths["training_attacks_path"].write_text(
        json.dumps(
            {
                "id": "existing",
                "category": "PROMPT_INJECTION",
                "payload": "Already used NFKC reproducer.",
                "expected_verdict": "BLOCK",
                "expected_classes": ["PROMPT_INJECTION"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    pending = _record(_request(variant))

    with pytest.raises(ValueError, match="existing training or held-out"):
        feedback_store.promote_feedback(
            str(pending["feedback_id"]),
            destination="held-out",
            category=ReasonCode.PROMPT_INJECTION,
            reviewer_approved=True,
            reviewed_at=NOW,
            **paths,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 999),
        ("outcome", "invalid"),
        ("dedupe_key", "0" * 64),
        ("reproducer_sha256", "0" * 64),
        ("scanner_version", "\ud800"),
    ],
)
def test_review_rejects_corrupt_or_forged_persisted_records(field, value, tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    paths = _dataset_paths(tmp_path)
    pending = _record(_request("Human-reviewed persisted redacted reproducer."))
    [stored] = _jsonl(path)
    stored[field] = value
    path.write_text(json.dumps(stored) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not found|expired|invalid"):
        feedback_store.promote_feedback(
            str(pending["feedback_id"]),
            destination="held-out",
            category=ReasonCode.PROMPT_INJECTION,
            reviewer_approved=True,
            reviewed_at=NOW,
            **paths,
        )
    assert _jsonl(paths["held_out_attacks_path"]) == []


def test_review_cli_refuses_to_run_without_explicit_human_confirmation():
    with pytest.raises(SystemExit, match="--confirm-human-review"):
        review_feedback.main(
            [
                "0" * 32,
                "held-out",
                "PROMPT_INJECTION",
            ]
        )


def _report_records(count: int, *, first_at: datetime) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for index in range(count):
        submitted_at = first_at + timedelta(minutes=index)
        request = _request(f"private report reproducer {index}")
        dedupe_key = feedback_store.feedback_dedupe_key(request)
        feedback_id = feedback_store.feedback_id_for_dedupe_key(dedupe_key)
        records.append(
            {
                "schema_version": 1,
                "feedback_id": feedback_id,
                "dedupe_key": dedupe_key,
                "submitted_at": submitted_at.isoformat().replace("+00:00", "Z"),
                "expires_at": (submitted_at + timedelta(days=90))
                .isoformat()
                .replace("+00:00", "Z"),
                "status": "pending",
                "outcome": request.outcome,
                "observed_verdict": request.observed_verdict,
                "threat_class": request.threat_class.value,
                "redacted_reproducer": request.redacted_reproducer,
                "reproducer_sha256": feedback_store.reproducer_sha256(request.redacted_reproducer),
                "consent_to_retain": True,
                "redaction_confirmed": True,
                "scanner_version": __version__,
                "corpus_fingerprint": "sha256:" + "a" * 64,
            }
        )
    return records


def _refresh_record_integrity(record: dict[str, object]) -> None:
    request = FeedbackRequest.model_validate(
        {
            "outcome": record["outcome"],
            "observed_verdict": record["observed_verdict"],
            "threat_class": record["threat_class"],
            "redacted_reproducer": record["redacted_reproducer"],
            "consent_to_retain": record["consent_to_retain"],
            "redaction_confirmed": record["redaction_confirmed"],
        }
    )
    record["reproducer_sha256"] = feedback_store.reproducer_sha256(request.redacted_reproducer)
    record["dedupe_key"] = feedback_store.feedback_dedupe_key(request)
    record["feedback_id"] = feedback_store.feedback_id_for_dedupe_key(str(record["dedupe_key"]))


def test_store_rejects_a_persisted_record_with_extended_retention(tmp_path, monkeypatch):
    path = tmp_path / "pending.jsonl"
    monkeypatch.setattr(feedback_store, "_STORE_PATH", path)
    [record] = _report_records(1, first_at=NOW - timedelta(days=1))
    record["expires_at"] = (NOW + timedelta(days=365)).isoformat().replace("+00:00", "Z")
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    assert feedback_store.list_feedback(now=NOW) == []
    assert _jsonl(path) == []


def test_report_is_deterministic_and_honestly_marks_insufficient_data():
    records = _report_records(24, first_at=NOW - timedelta(days=31))

    first = threat_intel.build_report(records, generated_at=NOW)
    second = threat_intel.build_report(records, generated_at=NOW)

    assert first == second
    assert first["status"] == "insufficient-data"
    assert first["requirements"] == {
        "minimum_records": 25,
        "minimum_window_days": 30,
        "publishable_cells_required": True,
        "records_met": False,
        "window_met": True,
        "publishable_cells_met": True,
    }


def test_report_stays_insufficient_when_every_cell_is_suppressed():
    records = _report_records(25, first_at=NOW - timedelta(days=31))
    threat_classes = [reason.value for reason in list(ReasonCode)[:7]]
    for index, record in enumerate(records):
        record["threat_class"] = threat_classes[index % len(threat_classes)]
        _refresh_record_integrity(record)

    report = threat_intel.build_report(records, generated_at=NOW)

    assert report["included_records"] == 0
    assert report["cells"] == []
    assert report["status"] == "insufficient-data"
    assert report["requirements"]["publishable_cells_met"] is False


def test_summary_deduplicates_and_ignores_invalid_or_out_of_window_records():
    records = _report_records(5, first_at=NOW - timedelta(days=2))
    duplicate = {
        **records[0],
        "feedback_id": "f" * 32,
        "redacted_reproducer": "duplicate private material",
    }
    inconsistent = {
        **records[0],
        "feedback_id": "e" * 32,
        "dedupe_key": "e" * 64,
        "outcome": "false_positive",
        "observed_verdict": "ALLOW",
    }
    expired = {
        **records[0],
        "feedback_id": "d" * 32,
        "dedupe_key": "d" * 64,
        "expires_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    future = {
        **records[0],
        "feedback_id": "c" * 32,
        "dedupe_key": "c" * 64,
        "submitted_at": (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=91)).isoformat().replace("+00:00", "Z"),
    }

    summary = threat_intel.build_summary(
        [*records, duplicate, inconsistent, expired, future],
        generated_at=NOW,
    )

    assert summary["included_records"] == 5
    assert summary["cells"] == [
        {
            "outcome": "missed_attack",
            "threat_class": "PROMPT_INJECTION",
            "count": 5,
        }
    ]


def test_summary_does_not_expose_sub_k_counts_or_record_timestamps():
    [record] = _report_records(1, first_at=NOW - timedelta(minutes=17))

    summary = threat_intel.build_summary([record], generated_at=NOW)

    assert summary["included_records"] == 0
    assert summary["window_start"] is None
    assert summary["cells"] == []
    assert "accepted_records" not in summary
    assert "suppressed_records" not in summary
    assert record["submitted_at"] not in json.dumps(summary, sort_keys=True)


def test_report_generator_writes_aggregate_only_ready_outputs(tmp_path, monkeypatch, capsys):
    private_records = _report_records(25, first_at=NOW - timedelta(days=31))
    json_output = tmp_path / "threat-report.json"
    markdown_output = tmp_path / "threat-report.md"
    monkeypatch.setattr(
        build_threat_report.feedback_store,
        "list_feedback",
        lambda **kwargs: private_records,
    )

    build_threat_report.main(
        [
            "--generated-at",
            "2026-07-18T12:00:00Z",
            "--json-output",
            str(json_output),
            "--markdown-output",
            str(markdown_output),
        ]
    )

    report = json.loads(json_output.read_text(encoding="utf-8"))
    markdown = markdown_output.read_text(encoding="utf-8")
    assert report["status"] == "ready"
    assert report["requirements"]["records_met"] is True
    assert report["requirements"]["window_met"] is True
    assert report["requirements"]["publishable_cells_met"] is True
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
    serialized = json.dumps(report, sort_keys=True) + markdown
    for forbidden in (
        "private report reproducer",
        "feedback_id",
        "dedupe",
        "digest",
        "sha256",
        "identity",
        "endpoint",
    ):
        assert forbidden not in serialized


def test_report_generator_uses_the_requested_time_without_pruning_against_wall_clock(
    tmp_path, monkeypatch
):
    private_records = _report_records(25, first_at=NOW - timedelta(days=31))
    observed: list[dict[str, object]] = []

    def list_at_requested_time(**kwargs):
        observed.append(kwargs)
        return private_records

    monkeypatch.setattr(build_threat_report.feedback_store, "list_feedback", list_at_requested_time)
    build_threat_report.main(
        [
            "--generated-at",
            "2026-07-18T12:00:00Z",
            "--json-output",
            str(tmp_path / "report.json"),
            "--markdown-output",
            str(tmp_path / "report.md"),
        ]
    )

    assert observed == [{"now": NOW, "compact": False}]


def test_report_generator_rejects_the_same_json_and_markdown_output(tmp_path):
    output = tmp_path / "report"

    with pytest.raises(SystemExit, match="different"):
        build_threat_report.main(
            [
                "--generated-at",
                "2026-07-18T12:00:00Z",
                "--json-output",
                str(output),
                "--markdown-output",
                str(output),
            ]
        )


def test_report_generator_rolls_back_json_when_markdown_publication_fails(tmp_path, monkeypatch):
    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"
    json_output.write_text('{"previous":true}\n', encoding="utf-8")
    markdown_output.write_text("previous markdown\n", encoding="utf-8")
    monkeypatch.setattr(
        build_threat_report.feedback_store,
        "list_feedback",
        lambda **kwargs: _report_records(25, first_at=NOW - timedelta(days=31)),
    )
    replace = build_threat_report.os.replace

    def fail_markdown(source, destination) -> None:
        if Path(destination) == markdown_output:
            raise OSError("simulated Markdown publication failure")
        replace(source, destination)

    monkeypatch.setattr(build_threat_report.os, "replace", fail_markdown)

    with pytest.raises(OSError, match="Markdown publication failure"):
        build_threat_report.main(
            [
                "--generated-at",
                "2026-07-18T12:00:00Z",
                "--json-output",
                str(json_output),
                "--markdown-output",
                str(markdown_output),
            ]
        )

    assert json_output.read_text(encoding="utf-8") == '{"previous":true}\n'
    assert markdown_output.read_text(encoding="utf-8") == "previous markdown\n"
    assert not list(tmp_path.glob(".*.tmp"))


def test_public_docs_state_the_feedback_privacy_and_publication_boundaries():
    readme = (feedback_store.ROOT / "README.md").read_text(encoding="utf-8")
    privacy = " ".join(
        (feedback_store.ROOT / "site" / "privacy.html").read_text(encoding="utf-8").split()
    )
    terms = " ".join(
        (feedback_store.ROOT / "site" / "terms.html").read_text(encoding="utf-8").split()
    )

    assert "Scans do not create feedback implicitly" in readme
    assert "25 records are included in k=5 cells" in readme
    assert "shares one promotion lock with Gauntlet review" in readme
    assert "Warden cannot establish" in privacy
    assert "assigned a 90-day expiry" in privacy
    assert "does not expose their exact size or timing" in privacy
    assert "published as part of that dataset" in privacy
    assert "There is no automatic learning path" in terms
    assert "exactly one training or held-out dataset" in terms
