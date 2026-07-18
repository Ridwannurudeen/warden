"""Candidate-only issuer rotation orchestration regressions."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.rotate_issuer_key import (
    format_rotation_summary,
    parse_args,
    rotate_issuer_key,
)
from scripts.reprobe_protections import RotationIncomplete
from warden import protection, protection_store
from warden.badges import b64u_encode, ed25519_verify_record


def _seed(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.private_bytes_raw(), "ed25519-seed")


def _pub(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.public_key().public_bytes_raw(), "ed25519")


def _stored_record(path: Path, attestation_id: str) -> dict[str, object]:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        row = connection.execute(
            "SELECT record_json FROM attestations WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
    assert row is not None
    record = json.loads(row[0])
    assert isinstance(record, dict)
    return record


@pytest.mark.asyncio
async def test_rotation_orchestrator_resigns_only_a_candidate_and_preserves_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    endpoint_key = Ed25519PrivateKey.generate()
    endpoint_host = "rotation.example.org"
    endpoint_pub = _pub(endpoint_key)
    source = tmp_path / "source.db"
    candidate = tmp_path / "candidate.db"

    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(source))
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(old_key))
    record = protection.issue_attestation(endpoint_host, endpoint_pub, 11)
    protection_store.commit_attestation_events(
        [("issued", record)],
        new_binding=(endpoint_host, endpoint_pub),
    )
    source_before = source.read_bytes()

    cutoff = int(record["verified_at"]) + 120
    history = tmp_path / "issuer-history.json"
    history.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "retired-before-rotation",
                        "pub": _pub(old_key),
                        "not_after": cutoff,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    history_before = history.read_bytes()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(new_key))
    monkeypatch.setenv("WARDEN_ISSUER_KID", "current-after-rotation")
    monkeypatch.setenv("WARDEN_ISSUER_HISTORY", str(history))

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        assert endpoint == f"https://{endpoint_host}"
        return endpoint_host, endpoint_pub, 19

    summary = await rotate_issuer_key(
        source_db=source,
        candidate_db=candidate,
        probe_guard=probe_guard,
        now=cutoff,
    )

    assert source.read_bytes() == source_before
    assert history.read_bytes() == history_before
    assert candidate.is_file() and not candidate.is_symlink()
    source_record = _stored_record(source, str(record["attestation_id"]))
    candidate_record = _stored_record(candidate, str(record["attestation_id"]))
    assert ed25519_verify_record(source_record, _pub(old_key), "issuer_sig") is True
    assert ed25519_verify_record(source_record, _pub(new_key), "issuer_sig") is False
    assert protection.verify_attestation_record(source_record) is True
    assert ed25519_verify_record(candidate_record, _pub(new_key), "issuer_sig") is True
    assert ed25519_verify_record(candidate_record, _pub(old_key), "issuer_sig") is False
    assert summary.targets == 1
    assert summary.resigned == 1
    assert summary.skipped == 0
    assert summary.dry_run is False

    before_dry_run = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    dry_run = await rotate_issuer_key(
        source_db=source,
        dry_run=True,
        probe_guard=probe_guard,
        now=cutoff,
    )

    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before_dry_run
    assert dry_run.targets == 1
    assert dry_run.resigned == 1
    assert dry_run.skipped == 0
    assert dry_run.dry_run is True
    output = format_rotation_summary(dry_run)
    for key_material in (_seed(old_key), _seed(new_key), _pub(old_key), _pub(new_key)):
        assert key_material not in output
    assert output == "mode=dry-run targets=1 resigned=1 skipped=0"

    failed_candidate = tmp_path / "failed-candidate.db"

    async def concurrent_revocation(endpoint: str) -> tuple[str, str, int | None]:
        assert endpoint == f"https://{endpoint_host}"
        current = protection_store.get_attestation(str(record["attestation_id"]))
        assert current is not None
        revoked = protection.resign_attestation_status(current, "revoked")
        protection_store.commit_attestation_events([("revoked", revoked)])
        return endpoint_host, endpoint_pub, 19

    with pytest.raises(RotationIncomplete, match="zero skipped"):
        await rotate_issuer_key(
            source_db=source,
            candidate_db=failed_candidate,
            probe_guard=concurrent_revocation,
            now=cutoff,
        )
    assert failed_candidate.exists() is False
    assert source.read_bytes() == source_before
    assert history.read_bytes() == history_before


def test_rotation_cli_has_no_private_key_argument() -> None:
    args = parse_args(["--source-db", "source.db", "--dry-run"])

    assert args.source_db == Path("source.db")
    assert args.candidate_db is None
    assert args.dry_run is True
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--source-db",
                "source.db",
                "--dry-run",
                "--issuer-key",
                "must-not-be-accepted",
            ]
        )
