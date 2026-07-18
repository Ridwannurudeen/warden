"""Regression coverage for independently published transparency-log checkpoints."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import publish_log_checkpoint
from warden import anchor_history, protection, protection_store
from warden.badges import _canonical_json, b64u_encode


@pytest.fixture(autouse=True)
def _apa_env(tmp_path, monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))


def _record(attestation_id: str) -> dict[str, object]:
    return {
        "attestation_id": attestation_id,
        "endpoint_host": "asp.example.org",
        "status": "active",
    }


def _write_history_sentinel(path: Path) -> None:
    path.write_text(
        json.dumps(anchor_history.empty_anchor_history(), indent=2) + "\n",
        encoding="utf-8",
    )


def test_historical_checkpoint_accepts_append_and_rejects_rewrite_or_truncation():
    protection_store.commit_attestation_events([("issued", _record("first"))])
    checkpoint = protection_store.read_log_checkpoint()
    protection_store.commit_attestation_events([("issued", _record("second"))])
    entries = protection_store.read_log()

    assert protection_store.verify_log_prefix(entries, checkpoint) is True
    assert protection_store.verify_log_prefix([], checkpoint) is False

    rewritten = [dict(entry) for entry in entries]
    rewritten[0]["endpoint_host"] = "rewritten.example.org"
    rewritten[1]["prev_hash"] = hashlib.sha256(
        _canonical_json(rewritten[0]).encode("utf-8")
    ).hexdigest()
    assert protection_store.verify_log_chain(rewritten) is False
    assert protection_store.verify_log_prefix(rewritten, checkpoint) is False


def test_checkpoint_export_is_atomic_public_and_never_loads_private_key(tmp_path, monkeypatch):
    protection_store.commit_attestation_events([("issued", _record("first"))])
    checkpoint = protection_store.read_log_checkpoint()
    output = tmp_path / "public" / "apa-log-anchor.json"
    output.parent.mkdir()
    history_output = output.with_name("apa-log-anchor-history.json")
    _write_history_sentinel(history_output)
    chmod_calls: list[tuple[os.PathLike[str] | str, int]] = []
    replace_calls: list[tuple[os.PathLike[str] | str, os.PathLike[str] | str]] = []
    real_chmod = publish_log_checkpoint.os.chmod
    real_replace = publish_log_checkpoint.os.replace

    def record_chmod(path, mode):
        chmod_calls.append((path, mode))
        real_chmod(path, mode)

    def record_replace(source, destination):
        replace_calls.append((source, destination))
        real_replace(source, destination)

    def private_key_forbidden():
        raise AssertionError("checkpoint publication must not load the private issuer key")

    monkeypatch.delenv("WARDEN_ISSUER_KEY")
    monkeypatch.setattr(protection, "issuer_private_key", private_key_forbidden)
    monkeypatch.setattr(publish_log_checkpoint.os, "chmod", record_chmod)
    monkeypatch.setattr(publish_log_checkpoint.os, "replace", record_replace)

    publish_log_checkpoint.publish_checkpoint(output, history_output)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "status": "published",
        "checkpoint": checkpoint,
    }
    history = json.loads(history_output.read_text(encoding="utf-8"))
    assert anchor_history.validate_anchor_history(
        history,
        protection_store.read_log(),
        verify_signatures=False,
    )
    assert [mode for _, mode in chmod_calls] == [0o644, 0o644]
    assert [destination for _, destination in replace_calls] == [
        history_output.resolve(),
        output.resolve(),
    ]
    assert not output.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o644


def test_checkpoint_export_refuses_a_symlink_target(tmp_path, monkeypatch):
    protection_store.commit_attestation_events([("issued", _record("first"))])
    output = tmp_path / "apa-log-anchor.json"
    output.write_text('{"untouched":true}\n', encoding="utf-8")
    _write_history_sentinel(output.with_name("apa-log-anchor-history.json"))
    real_is_symlink = Path.is_symlink

    def report_output_as_symlink(path: Path) -> bool:
        return path == output or real_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_output_as_symlink)

    with pytest.raises(ValueError, match="symbolic link"):
        publish_log_checkpoint.publish_checkpoint(output)

    assert output.read_text(encoding="utf-8") == '{"untouched":true}\n'


def test_checkpoint_export_replace_failure_preserves_existing_file(tmp_path, monkeypatch):
    protection_store.commit_attestation_events([("issued", _record("first"))])
    output = tmp_path / "apa-log-anchor.json"
    output.write_text('{"status":"unpublished"}\n', encoding="utf-8")
    history_output = output.with_name("apa-log-anchor-history.json")
    _write_history_sentinel(history_output)

    def fail_replace(source, destination):
        raise OSError("simulated atomic promotion failure")

    monkeypatch.setattr(publish_log_checkpoint.os, "replace", fail_replace)

    with pytest.raises(OSError, match="atomic promotion failure"):
        publish_log_checkpoint.publish_checkpoint(output, history_output)

    assert output.read_text(encoding="utf-8") == '{"status":"unpublished"}\n'
    assert not list(tmp_path.glob(".apa-log-anchor.json.*.tmp"))


def test_history_first_publication_converges_after_current_anchor_write_failure(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "apa-log-anchor.json"
    output.write_text('{"status":"unpublished"}\n', encoding="utf-8")
    history_output = tmp_path / "apa-log-anchor-history.json"
    _write_history_sentinel(history_output)
    protection_store.commit_attestation_events([("issued", _record("first"))])
    real_replace = publish_log_checkpoint.os.replace

    def fail_current_anchor(source, destination):
        if Path(destination) == output.resolve():
            raise OSError("simulated current-anchor promotion failure")
        real_replace(source, destination)

    monkeypatch.setattr(
        publish_log_checkpoint.os,
        "replace",
        fail_current_anchor,
    )
    with pytest.raises(OSError, match="current-anchor promotion failure"):
        publish_log_checkpoint.publish_checkpoint(output, history_output)

    published_history = history_output.read_bytes()
    assert len(json.loads(published_history)["anchors"]) == 1
    assert output.read_text(encoding="utf-8") == '{"status":"unpublished"}\n'

    monkeypatch.setattr(publish_log_checkpoint.os, "replace", real_replace)
    publish_log_checkpoint.publish_checkpoint(output, history_output)
    assert history_output.read_bytes() == published_history
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "published"


def test_anchor_history_appends_without_rewriting_a_pinned_prefix(tmp_path):
    output = tmp_path / "apa-log-anchor.json"
    history_output = tmp_path / "apa-log-anchor-history.json"
    _write_history_sentinel(history_output)

    protection_store.commit_attestation_events([("issued", _record("first"))])
    publish_log_checkpoint.publish_checkpoint(output, history_output)
    first_history = json.loads(history_output.read_text(encoding="utf-8"))
    first_anchor = first_history["anchors"][0]
    pinned_head = first_history["history_head_hash"]

    protection_store.commit_attestation_events([("issued", _record("second"))])
    publish_log_checkpoint.publish_checkpoint(
        output,
        history_output,
        pinned_history_head=pinned_head,
    )
    appended = json.loads(history_output.read_text(encoding="utf-8"))

    assert appended["anchors"][0] == first_anchor
    assert appended["anchors"][1]["previous_anchor_hash"] == pinned_head
    assert anchor_history.validate_anchor_history(
        appended,
        protection_store.read_log(),
        pinned_history_head=pinned_head,
    )


def test_anchor_history_pin_rejects_coherent_history_truncation(tmp_path):
    output = tmp_path / "apa-log-anchor.json"
    history_output = tmp_path / "apa-log-anchor-history.json"
    _write_history_sentinel(history_output)

    protection_store.commit_attestation_events([("issued", _record("first"))])
    publish_log_checkpoint.publish_checkpoint(output, history_output)
    pinned_head = json.loads(history_output.read_text(encoding="utf-8"))["history_head_hash"]
    protection_store.commit_attestation_events([("issued", _record("second"))])
    publish_log_checkpoint.publish_checkpoint(output, history_output)
    history = json.loads(history_output.read_text(encoding="utf-8"))

    replacement = anchor_history.empty_anchor_history()
    replacement = anchor_history.append_checkpoint(
        replacement,
        history["anchors"][-1]["checkpoint"],
        protection_store.read_log(),
    )
    assert anchor_history.validate_anchor_history(
        replacement,
        protection_store.read_log(),
    )
    with pytest.raises(anchor_history.AnchorHistoryError, match="pinned history head"):
        anchor_history.validate_anchor_history(
            replacement,
            protection_store.read_log(),
            pinned_history_head=pinned_head,
        )


def test_anchor_history_publication_is_idempotent(tmp_path):
    output = tmp_path / "apa-log-anchor.json"
    history_output = tmp_path / "apa-log-anchor-history.json"
    _write_history_sentinel(history_output)
    protection_store.commit_attestation_events([("issued", _record("first"))])

    publish_log_checkpoint.publish_checkpoint(output, history_output)
    original = history_output.read_bytes()
    publish_log_checkpoint.publish_checkpoint(output, history_output)

    assert history_output.read_bytes() == original
    assert len(json.loads(original)["anchors"]) == 1


def test_checkpoint_publication_requires_an_existing_history(tmp_path):
    output = tmp_path / "apa-log-anchor.json"
    protection_store.commit_attestation_events([("issued", _record("first"))])

    with pytest.raises(FileNotFoundError, match="anchor history"):
        publish_log_checkpoint.publish_checkpoint(
            output,
            tmp_path / "missing-history.json",
        )


def test_public_anchor_sentinel_is_explicitly_unpublished():
    root = Path(__file__).resolve().parents[1]
    sentinel = json.loads(
        (root / "site" / "data" / "apa-log-anchor.json").read_text(encoding="utf-8")
    )

    assert sentinel == {
        "schema_version": 1,
        "status": "unpublished",
        "checkpoint": None,
    }
    history = json.loads(
        (root / "site" / "data" / "apa-log-anchor-history.json").read_text(encoding="utf-8")
    )
    assert history == anchor_history.empty_anchor_history()

    page = (root / "site" / "log.html").read_text(encoding="utf-8")
    script = (root / "site" / "log.js").read_text(encoding="utf-8")
    assert "data-apa-log-anchor" in page
    assert "says explicitly when it is unpublished" in page
    assert 'fetchImpl("/data/apa-log-anchor.json"' in script
