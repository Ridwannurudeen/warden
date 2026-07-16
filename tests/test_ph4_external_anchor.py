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
from warden import protection, protection_store
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

    publish_log_checkpoint.publish_checkpoint(output)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "status": "published",
        "checkpoint": checkpoint,
    }
    assert [mode for _, mode in chmod_calls] == [0o644]
    assert len(replace_calls) == 1
    assert replace_calls[0][1] == output.resolve()
    assert not output.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o644


def test_checkpoint_export_refuses_a_symlink_target(tmp_path, monkeypatch):
    protection_store.commit_attestation_events([("issued", _record("first"))])
    output = tmp_path / "apa-log-anchor.json"
    output.write_text('{"untouched":true}\n', encoding="utf-8")
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

    def fail_replace(source, destination):
        raise OSError("simulated atomic promotion failure")

    monkeypatch.setattr(publish_log_checkpoint.os, "replace", fail_replace)

    with pytest.raises(OSError, match="atomic promotion failure"):
        publish_log_checkpoint.publish_checkpoint(output)

    assert output.read_text(encoding="utf-8") == '{"status":"unpublished"}\n'
    assert not list(tmp_path.glob(".apa-log-anchor.json.*.tmp"))


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

    page = (root / "site" / "log.html").read_text(encoding="utf-8")
    script = (root / "site" / "log.js").read_text(encoding="utf-8")
    assert "data-apa-log-anchor" in page
    assert "says explicitly when it is unpublished" in page
    assert 'fetchImpl("/data/apa-log-anchor.json"' in script
