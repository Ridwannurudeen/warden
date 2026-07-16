import hashlib
import importlib.util
import json
import threading
from pathlib import Path

from warden import gauntlet_store
from warden.core.verdict import ReasonCode
from warden.models import GauntletRequest, ScanResponse


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


def test_review_and_submission_are_cross_process_serialized(tmp_path):
    reviewer = _load_store_copy("gauntlet_reviewer_copy")
    writer = _load_store_copy("gauntlet_writer_copy")
    store_path = tmp_path / "attempts.jsonl"
    benchmark_path = tmp_path / "held_out.jsonl"
    reviewer._STORE_PATH = store_path
    writer._STORE_PATH = store_path

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
