import hashlib
import importlib.util
import json
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import __version__, feedback_store, gauntlet_store
from warden.badges import b64u_encode
from warden.core.verdict import ReasonCode
from warden.models import FeedbackRequest, GauntletRequest, ScanResponse


def _load_store_copy(name):
    spec = importlib.util.spec_from_file_location(name, gauntlet_store.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _response(verdict):
    return ScanResponse(
        verdict=verdict,
        risk_level="NONE" if verdict == "ALLOW" else "HIGH",
        threat_classes=[] if verdict == "ALLOW" else ["PROMPT_INJECTION"],
        detections=[],
        sanitized_payload="safe",
        recommendation="test",
        checks={},
        latency_ms=0.1,
    )


def test_review_and_submission_are_cross_process_serialized(tmp_path, monkeypatch):
    reviewer = _load_store_copy("gauntlet_reviewer_copy")
    writer = _load_store_copy("gauntlet_writer_copy")
    store_path = tmp_path / "attempts.jsonl"
    benchmark_path = tmp_path / "held_out.jsonl"
    reviewer._STORE_PATH = store_path
    writer._STORE_PATH = store_path
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))

    _, claim_id = reviewer.record_attempt(
        GauntletRequest(
            intent="indirect authorization bypass",
            payload="An unusual authorization note with alpha delta wording.",
        ),
        _response("ALLOW"),
    )
    assert claim_id is not None

    review_read = threading.Event()
    release_review = threading.Event()
    original_read = reviewer._read_records_locked

    def paused_read():
        records = original_read()
        review_read.set()
        assert release_review.wait(timeout=2)
        return records

    reviewer._read_records_locked = paused_read
    errors = []

    def confirm():
        try:
            reviewer.confirm_bypass(
                claim_id,
                ReasonCode.PROMPT_INJECTION,
                reviewed_payload="An unusual authorization note with alpha delta wording.",
                finder=None,
                reviewer_approved=True,
                benchmark_path=benchmark_path,
                confirmed_at="2026-07-16T16:31:00Z",
            )
        except Exception as exc:
            errors.append(exc)

    second_payload = "A second concurrent submission that must survive review."

    def submit():
        try:
            writer.record_attempt(
                GauntletRequest(intent="routine", payload=second_payload),
                _response("BLOCK"),
            )
        except Exception as exc:
            errors.append(exc)

    review_thread = threading.Thread(target=confirm)
    review_thread.start()
    assert review_read.wait(timeout=2)
    writer_thread = threading.Thread(target=submit)
    writer_thread.start()
    writer_thread.join(timeout=0.1)
    release_review.set()
    review_thread.join(timeout=2)
    writer_thread.join(timeout=2)

    assert not errors
    records = [
        json.loads(line)
        for line in Path(store_path).read_text(encoding="utf-8").splitlines()
        if line
    ]
    second_hash = hashlib.sha256(second_payload.encode("utf-8")).hexdigest()
    assert any(record.get("payload_hash") == second_hash for record in records)


def test_gauntlet_and_feedback_reviews_share_the_dataset_lock(tmp_path, monkeypatch):
    reviewer = _load_store_copy("gauntlet_dataset_reviewer")
    reviewer._STORE_PATH = tmp_path / "attempts.jsonl"
    benchmark_path = tmp_path / "benchmark" / "held_out_attacks.jsonl"
    benign_benchmark_path = tmp_path / "benchmark" / "held_out_benign.jsonl"
    training_attacks_path = tmp_path / "corpus" / "attacks.jsonl"
    training_benign_path = tmp_path / "corpus" / "benign.jsonl"
    for path in (
        benchmark_path,
        benign_benchmark_path,
        training_attacks_path,
        training_benign_path,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    monkeypatch.setattr(feedback_store, "_STORE_PATH", tmp_path / "pending.jsonl")
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))

    _, claim_id = reviewer.record_attempt(
        GauntletRequest(
            intent="indirect authorization bypass",
            payload="An unusual authorization note with alpha delta wording.",
        ),
        _response("ALLOW"),
    )
    assert claim_id is not None
    feedback = feedback_store.record_feedback(
        FeedbackRequest.model_validate(
            {
                "outcome": "missed_attack",
                "observed_verdict": "ALLOW",
                "threat_class": "PROMPT_INJECTION",
                "redacted_reproducer": "A second independently reviewed reproducer.",
                "consent_to_retain": True,
                "redaction_confirmed": True,
            }
        ),
        scanner_version=__version__,
        corpus_fingerprint="sha256:" + "a" * 64,
    )

    gauntlet_inside_append = threading.Event()
    feedback_inside_append = threading.Event()
    release_gauntlet = threading.Event()
    gauntlet_append = reviewer._append_benchmark_case
    feedback_append = feedback_store._append_jsonl_entry

    def hold_gauntlet_append(path, entry) -> None:
        gauntlet_inside_append.set()
        if not release_gauntlet.wait(3):
            raise RuntimeError("Gauntlet append release timed out")
        gauntlet_append(path, entry)

    def observe_feedback_append(path, entry) -> None:
        feedback_inside_append.set()
        feedback_append(path, entry)

    reviewer._append_benchmark_case = hold_gauntlet_append
    monkeypatch.setattr(feedback_store, "_append_jsonl_entry", observe_feedback_append)
    errors: list[BaseException] = []

    def confirm() -> None:
        try:
            reviewer.confirm_bypass(
                claim_id,
                ReasonCode.PROMPT_INJECTION,
                reviewed_payload="An unusual authorization note with alpha delta wording.",
                finder=None,
                reviewer_approved=True,
                benchmark_path=benchmark_path,
                benign_benchmark_path=benign_benchmark_path,
                confirmed_at="2026-07-16T16:31:00Z",
            )
        except BaseException as exc:
            errors.append(exc)

    def promote() -> None:
        try:
            feedback_store.promote_feedback(
                str(feedback["feedback_id"]),
                destination="held-out",
                category=ReasonCode.PROMPT_INJECTION,
                reviewer_approved=True,
                training_attacks_path=training_attacks_path,
                training_benign_path=training_benign_path,
                held_out_attacks_path=benchmark_path,
                held_out_benign_path=benign_benchmark_path,
            )
        except BaseException as exc:
            errors.append(exc)

    gauntlet_thread = threading.Thread(target=confirm)
    feedback_thread = threading.Thread(target=promote)
    gauntlet_thread.start()
    assert gauntlet_inside_append.wait(2)
    feedback_thread.start()
    feedback_entered_before_gauntlet_finished = feedback_inside_append.wait(0.25)
    release_gauntlet.set()
    gauntlet_thread.join(timeout=3)
    feedback_thread.join(timeout=3)

    assert not errors
    assert not gauntlet_thread.is_alive()
    assert not feedback_thread.is_alive()
    assert feedback_entered_before_gauntlet_finished is False
    assert {
        entry["payload"]
        for entry in (
            json.loads(line)
            for line in benchmark_path.read_text(encoding="utf-8").splitlines()
            if line
        )
    } == {
        "An unusual authorization note with alpha delta wording.",
        "A second independently reviewed reproducer.",
    }
