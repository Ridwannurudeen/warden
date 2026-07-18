"""Build and verify an isolated APA issuer-rotation database candidate."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.reprobe_protections import (  # noqa: E402
    ProbeGuard,
    RotationIncomplete,
    reprobe_protections,
)
from warden import protection, protection_store  # noqa: E402
from warden.badges import ed25519_verify_record  # noqa: E402

_REQUIRED_ENVIRONMENT = (
    "WARDEN_ISSUER_KEY",
    "WARDEN_ISSUER_KID",
    "WARDEN_ISSUER_HISTORY",
)
_SQLITE_SIDECARS = ("-journal", "-shm", "-wal")


class RotationRefused(RuntimeError):
    """The isolated candidate failed an issuer-rotation safety gate."""


@dataclass(frozen=True)
class RotationSummary:
    dry_run: bool
    targets: int
    resigned: int
    skipped: int


def _file_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    resolved = Path(os.path.abspath(path))
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise RotationRefused(f"{label} must be an existing regular file") from exc
    if resolved.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RotationRefused(f"{label} must be an existing regular non-symlink file")
    return resolved


def _require_no_sqlite_sidecars(path: Path) -> None:
    sidecars = (Path(f"{path}{suffix}") for suffix in _SQLITE_SIDECARS)
    if any(sidecar.exists() or sidecar.is_symlink() for sidecar in sidecars):
        raise RotationRefused("database has a SQLite sidecar; quiesce every writer first")


def _candidate_path(path: Path, source: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.exists() or candidate.is_symlink():
        raise RotationRefused("candidate database must not already exist")
    if candidate == source:
        raise RotationRefused("candidate database must differ from the source database")
    _require_no_sqlite_sidecars(candidate)
    parent = candidate.parent
    if parent.is_symlink() or not parent.is_dir():
        raise RotationRefused("candidate parent must be an existing non-symlink directory")
    if parent.stat().st_dev != source.stat().st_dev:
        raise RotationRefused("candidate database must be on the source filesystem")
    return candidate


def _copy_database(source: Path, destination: Path) -> None:
    source_uri = f"{source.resolve().as_uri()}?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source_connection:
            if source_connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise RotationRefused("source database failed SQLite quick_check")
            with closing(sqlite3.connect(destination)) as candidate_connection:
                source_connection.backup(candidate_connection)
                if candidate_connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise RotationRefused("candidate database failed SQLite quick_check")
    except sqlite3.Error as exc:
        raise RotationRefused("database candidate could not be copied safely") from exc


def _validate_rotation_environment() -> tuple[Path, str, tuple[str, ...]]:
    missing = [name for name in _REQUIRED_ENVIRONMENT if not os.getenv(name, "").strip()]
    if missing:
        raise RotationRefused(
            "rotation requires WARDEN_ISSUER_KEY, WARDEN_ISSUER_KID, "
            "and WARDEN_ISSUER_HISTORY in the process environment"
        )
    history = _regular_file(
        Path(os.environ["WARDEN_ISSUER_HISTORY"]),
        "issuer history",
    )
    keys = protection.issuer_keys()
    if len(keys) < 2:
        raise RotationRefused("issuer history must preserve at least one retired public key")
    current_pub = str(keys[0]["pub"])
    retired_pubs = tuple(str(key["pub"]) for key in keys[1:])
    return history, current_pub, retired_pubs


def _verify_retired_records(
    targets: list[dict[str, object]],
    current_pub: str,
    retired_pubs: tuple[str, ...],
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for target in targets:
        record = target.get("record")
        if not isinstance(record, dict) or not protection.verify_attestation_record(record):
            raise RotationRefused(
                "eligible source attestation is not verifiable under the retired-key history"
            )
        if ed25519_verify_record(record, current_pub, "issuer_sig"):
            raise RotationRefused(
                "eligible source attestation is already signed by the candidate issuer"
            )
        if not any(
            ed25519_verify_record(record, retired_pub, "issuer_sig")
            for retired_pub in retired_pubs
        ):
            raise RotationRefused(
                "eligible source attestation is not signed by a retired issuer key"
            )
        records.append(record)
    return records


def _verify_current_records(records: list[dict[str, object]], current_pub: str) -> None:
    for original in records:
        attestation_id = original.get("attestation_id")
        stored = (
            protection_store.get_attestation(attestation_id)
            if isinstance(attestation_id, str)
            else None
        )
        if (
            not isinstance(stored, dict)
            or not protection.verify_attestation_record(stored)
            or not ed25519_verify_record(stored, current_pub, "issuer_sig")
            or ed25519_verify_record(original, current_pub, "issuer_sig")
            or not protection.verify_attestation_record(original)
        ):
            raise RotationRefused(
                "candidate did not preserve history and re-sign every eligible attestation"
            )


def _remove_staging(path: Path) -> None:
    for candidate in (path, *(Path(f"{path}{suffix}") for suffix in _SQLITE_SIDECARS)):
        if candidate.exists() and not candidate.is_symlink():
            candidate.unlink()


async def rotate_issuer_key(
    *,
    source_db: Path,
    candidate_db: Path | None = None,
    dry_run: bool = False,
    probe_guard: ProbeGuard | None = None,
    now: int | None = None,
) -> RotationSummary:
    """Build and prove a new-key database candidate without mutating source state."""
    if dry_run and candidate_db is not None:
        raise RotationRefused("--candidate-db must be omitted with --dry-run")
    if not dry_run and candidate_db is None:
        raise RotationRefused("--candidate-db is required unless --dry-run is set")

    source = _regular_file(source_db, "source database")
    _require_no_sqlite_sidecars(source)
    history, current_pub, retired_pubs = _validate_rotation_environment()
    source_digest = _file_digest(source)
    history_digest = _file_digest(history)
    destination = (
        _candidate_path(candidate_db, source)
        if candidate_db is not None
        else source.parent / ".issuer-rotation-dry-run.db"
    )
    if dry_run and (destination.exists() or destination.is_symlink()):
        raise RotationRefused("dry-run staging database already exists")

    descriptor, staging_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    staging = Path(staging_name)
    prior_database = os.environ.get("WARDEN_PROTECTION_DB")
    try:
        _copy_database(source, staging)
        os.environ["WARDEN_PROTECTION_DB"] = str(staging)
        targets = protection_store.list_reprobe_targets()
        records = _verify_retired_records(targets, current_pub, retired_pubs)
        if protection_store.read_log():
            protection_store.read_log_checkpoint()

        reprobe_summary = await reprobe_protections(
            probe_guard=probe_guard,
            now=now,
            require_complete_current_issuer=True,
        )
        resigned = sum(
            reprobe_summary[field] for field in ("active", "stale", "invalid", "key_changed")
        )
        _verify_current_records(records, current_pub)
        if protection_store.read_log():
            protection_store.read_log_checkpoint()
        if (
            reprobe_summary["targets"] != len(records)
            or resigned != len(records)
            or reprobe_summary["skipped"]
        ):
            raise RotationRefused(
                "candidate did not re-sign every eligible attestation with zero skips"
            )
        if _file_digest(source) != source_digest:
            raise RotationRefused("source database changed during candidate construction")
        if _file_digest(history) != history_digest:
            raise RotationRefused("issuer history changed during candidate construction")
        _require_no_sqlite_sidecars(staging)
        os.chmod(staging, 0o600)

        if not dry_run:
            try:
                os.link(staging, destination)
            except FileExistsError as exc:
                raise RotationRefused("candidate database appeared during rotation") from exc
        return RotationSummary(
            dry_run=dry_run,
            targets=len(records),
            resigned=resigned,
            skipped=int(reprobe_summary["skipped"]),
        )
    finally:
        if prior_database is None:
            os.environ.pop("WARDEN_PROTECTION_DB", None)
        else:
            os.environ["WARDEN_PROTECTION_DB"] = prior_database
        _remove_staging(staging)


def format_rotation_summary(summary: RotationSummary) -> str:
    mode = "dry-run" if summary.dry_run else "candidate"
    return (
        f"mode={mode} targets={summary.targets} "
        f"resigned={summary.resigned} skipped={summary.skipped}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a verified issuer-rotation database candidate. "
            "Signing material is read only from the process environment."
        )
    )
    parser.add_argument("--source-db", type=Path, required=True)
    parser.add_argument("--candidate-db", type=Path)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="prove the full rotation against an ephemeral candidate and remove it",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        summary = asyncio.run(
            rotate_issuer_key(
                source_db=args.source_db,
                candidate_db=args.candidate_db,
                dry_run=args.dry_run,
            )
        )
    except (OSError, RotationIncomplete, RotationRefused, ValueError) as exc:
        raise SystemExit(f"issuer rotation refused: {exc}") from exc
    print(format_rotation_summary(summary))


if __name__ == "__main__":
    main()
