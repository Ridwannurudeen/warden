"""Fail-closed issuer-key rotation regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.reprobe_protections import (
    RotationIncomplete,
    parse_args,
    reprobe_protections,
)
from warden import protection, protection_store
from warden.badges import b64u_encode, ed25519_verify_record

ROOT = Path(__file__).resolve().parents[1]


def _seed(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.private_bytes_raw(), "ed25519-seed")


def _pub(key: Ed25519PrivateKey) -> str:
    return b64u_encode(key.public_key().public_bytes_raw(), "ed25519")


def _store_record(endpoint_host: str, endpoint_pub: str, *, bind: bool) -> dict[str, object]:
    record = protection.issue_attestation(endpoint_host, endpoint_pub, 11)
    protection_store.commit_attestation_events(
        [("issued", record)],
        new_binding=(endpoint_host, endpoint_pub) if bind else None,
    )
    return record


def _activate_rotated_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    old_key: Ed25519PrivateKey,
    new_key: Ed25519PrivateKey,
    cutoff: int,
) -> None:
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
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(new_key))
    monkeypatch.setenv("WARDEN_ISSUER_KID", "current-after-rotation")
    monkeypatch.setenv("WARDEN_ISSUER_HISTORY", str(history))


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)


@pytest.mark.asyncio
async def test_rotation_mode_resigns_every_eligible_record_with_current_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    endpoint_host = "guard.example.org"
    endpoint_pub = _pub(Ed25519PrivateKey.generate())
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(old_key))
    records = (
        _store_record(endpoint_host, endpoint_pub, bind=True),
        _store_record(endpoint_host, endpoint_pub, bind=False),
    )
    cutoff = max(int(record["verified_at"]) for record in records) + 60
    _activate_rotated_issuer(tmp_path, monkeypatch, old_key, new_key, cutoff)

    async def probe_guard(endpoint: str) -> tuple[str, str, int | None]:
        assert endpoint == f"https://{endpoint_host}"
        return endpoint_host, endpoint_pub, 19

    summary = await reprobe_protections(
        probe_guard=probe_guard,
        now=cutoff,
        require_complete_current_issuer=True,
    )

    assert summary["targets"] == 2
    assert summary["active"] == 2
    assert summary["skipped"] == 0
    for original in records:
        stored = protection_store.get_attestation(str(original["attestation_id"]))
        assert stored is not None
        assert ed25519_verify_record(stored, _pub(new_key), "issuer_sig") is True
        assert ed25519_verify_record(stored, _pub(old_key), "issuer_sig") is False


@pytest.mark.asyncio
async def test_rotation_mode_fails_if_an_initial_target_is_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    endpoint_host = "racing.example.org"
    endpoint_pub = _pub(Ed25519PrivateKey.generate())
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(old_key))
    record = _store_record(endpoint_host, endpoint_pub, bind=True)
    cutoff = int(record["verified_at"]) + 60
    _activate_rotated_issuer(tmp_path, monkeypatch, old_key, new_key, cutoff)

    async def concurrent_revocation(endpoint: str) -> tuple[str, str, int | None]:
        assert endpoint == f"https://{endpoint_host}"
        revoked = protection.resign_attestation_status(record, "revoked")
        protection_store.commit_attestation_events([("revoked", revoked)])
        return endpoint_host, endpoint_pub, 19

    with pytest.raises(RotationIncomplete, match="zero skipped"):
        await reprobe_protections(
            probe_guard=concurrent_revocation,
            now=cutoff,
            require_complete_current_issuer=True,
        )


@pytest.mark.asyncio
async def test_rotation_mode_rejects_a_corrupt_initial_record_without_probing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    endpoint_host = "corrupt.example.org"
    endpoint_pub = _pub(Ed25519PrivateKey.generate())
    monkeypatch.setenv("WARDEN_ISSUER_KEY", _seed(old_key))
    record = _store_record(endpoint_host, endpoint_pub, bind=True)
    corrupt = dict(record)
    corrupt["scans_24h"] = 999_999
    protection_store.store_attestation(corrupt)
    cutoff = int(record["verified_at"]) + 60
    _activate_rotated_issuer(tmp_path, monkeypatch, old_key, new_key, cutoff)

    async def unexpected_probe(endpoint: str) -> tuple[str, str, int | None]:
        raise AssertionError(f"corrupt record must fail before probing: {endpoint}")

    with pytest.raises(RotationIncomplete, match="zero skipped"):
        await reprobe_protections(
            probe_guard=unexpected_probe,
            now=cutoff,
            require_complete_current_issuer=True,
        )


def test_rotation_flag_and_runbook_require_candidate_database_before_promotion() -> None:
    args = parse_args(["--require-complete-current-issuer"])
    assert args.require_complete_current_issuer is True

    runbook = (ROOT / "docs" / "ISSUER_KEY_ROTATION.md").read_text(encoding="utf-8")
    backup = runbook.index("## 2. Quiesce and back up")
    candidate = runbook.index("## 3. Build the isolated database candidate")
    gate = runbook.index("--require-complete-current-issuer")
    promotion = runbook.index("## 5. Promote only after the gate passes")
    rollback = runbook.index("## Rollback")

    assert backup < candidate < gate < promotion < rollback
    assert 'CANDIDATE_DB="$candidate_db"' in runbook
    assert 'export WARDEN_PROTECTION_DB="$CANDIDATE_DB"' in runbook
    assert "Do not print, log, or pass the issuer seed" in runbook
    assert "docs/ISSUER_KEY_ROTATION.md" in (ROOT / "deploy" / "DEPLOY.md").read_text(
        encoding="utf-8"
    )
