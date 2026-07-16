"""Regression coverage for the two production permission fixes."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from scripts import build_index


def test_atomic_index_writer_sets_public_mode_before_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "data" / "marketplace-summary.json"
    events: list[tuple[str, int | None]] = []
    original_chmod = os.chmod
    original_replace = os.replace

    def chmod(path: str | os.PathLike[str], mode: int) -> None:
        original_chmod(path, mode)
        events.append(("chmod", mode))

    def replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        events.append(("replace", None))
        original_replace(source, destination)

    monkeypatch.setattr(build_index.os, "chmod", chmod)
    monkeypatch.setattr(build_index.os, "replace", replace)

    build_index._write_json_atomic(target, {"schemaVersion": 2})

    assert events == [("chmod", 0o644), ("replace", None)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are required")
def test_generated_index_json_is_atomically_published_world_readable(tmp_path: Path) -> None:
    target = tmp_path / "data" / "warden-services.json"

    build_index._write_json_atomic(target, {"schemaVersion": 1})

    assert json.loads(target.read_text(encoding="utf-8")) == {"schemaVersion": 1}
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_deploy_locks_fallback_issuer_key_and_requires_environment_seed() -> None:
    runbook = (Path(__file__).resolve().parents[1] / "deploy" / "DEPLOY.md").read_text(
        encoding="utf-8"
    )

    assert "reject_symlink /opt/warden/data/apa_issuer.key" in runbook
    assert "chmod 0600 /opt/warden/data/apa_issuer.key" in runbook
    assert (
        'chmod 0644 "$candidate_index_release/data/marketplace-summary.json" '
        '"$candidate_index_release/data/warden-services.json"'
        in runbook
    )
    assert (
        "WARDEN_ISSUER_KEY=(ed25519-seed:)?[A-Za-z0-9_-]{43}"
        in runbook
    )
