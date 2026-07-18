"""Atomic live marketplace-index refresh tests."""

from __future__ import annotations

import json
import multiprocessing
import os
from multiprocessing.synchronize import Event as EventType
from pathlib import Path

import pytest

from scripts.refresh_safety_index import (
    _PROCESS_LOCK_NAME,
    _RefreshLock,
    format_summary_log,
    main,
    refresh_safety_index,
    validate_release,
)


CAPTURED_AT = "2026-07-16T03:04:05Z"
ROOT = Path(__file__).resolve().parents[1]
COMMITTED_SNAPSHOT = ROOT / "data" / "marketplace" / "agents-v1.jsonl"
SUMMARY = {
    "schemaVersion": 2,
    "capturedAt": CAPTURED_AT,
    "query": "a",
    "sampled": 2,
    "expected": 2,
    "dropped": 0,
    "matchedCount": 1,
    "auditedCount": 0,
}


def _argument(command: list[str], flag: str) -> Path:
    return Path(command[command.index(flag) + 1])


def _write_release(release: Path, summary: dict[str, object] | None = None) -> None:
    public_summary = summary or SUMMARY
    agents = (
        {"kind": "agent", "agent": {"agentId": "7"}},
        {"kind": "agent", "agent": {"agentId": "3808"}},
    )
    snapshot = release / "data" / "marketplace" / "agents-v1.jsonl"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    records = (
        {
            "kind": "snapshot",
            "schema_version": 2,
            "captured_at": CAPTURED_AT,
            "query": "a",
            "page_size": 100,
            "sampled": public_summary["sampled"],
            "expected": public_summary["expected"],
            "dropped": public_summary["dropped"],
        },
        *agents,
    )
    snapshot.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )

    output = release / "agents"
    output.mkdir(parents=True, exist_ok=True)
    (output / "index.html").write_text("marketplace index", encoding="utf-8")
    for agent_id in ("7", "3808"):
        (output / f"{agent_id}.html").write_text(agent_id, encoding="utf-8")

    data = release / "data"
    (data / "marketplace-summary.json").write_text(
        json.dumps(public_summary),
        encoding="utf-8",
    )
    (data / "warden-services.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "snapshotFetchedAt": CAPTURED_AT,
                "services": [],
            }
        ),
        encoding="utf-8",
    )


def _build_runner(calls: list[list[str]], summary: dict[str, object] | None = None):
    def run(command: list[str], cwd: Path) -> None:
        calls.append(command)
        assert cwd == ROOT
        release = _argument(command, "--snapshot").parents[2]
        _write_release(release, summary)

    return run


def _fake_symlink(target: Path, link: Path, target_is_directory: bool) -> None:
    assert target_is_directory is True
    link.write_text(target.as_posix(), encoding="utf-8")


def _seed_current(index_root: Path) -> Path:
    old_release = index_root / "releases" / "old"
    old_release.mkdir(parents=True)
    (old_release / "marker").write_text("prior", encoding="utf-8")
    current = index_root / "current"
    current.write_text("releases/old", encoding="utf-8")
    return current


def _hold_refresh_lock(lock_path: str, ready: EventType, release: EventType) -> None:
    with _RefreshLock(Path(lock_path)):
        ready.set()
        if not release.wait(10):
            raise TimeoutError("test did not release the refresh lock")


def test_refresh_builds_from_public_snapshot_and_atomically_promotes(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)
    calls: list[list[str]] = []

    summary = refresh_safety_index(
        index_root,
        snapshot_path=COMMITTED_SNAPSHOT,
        command_runner=_build_runner(calls),
        symlink_creator=_fake_symlink,
    )

    assert summary == SUMMARY
    assert len(calls) == 1
    command = calls[0]
    assert Path(command[1]).parts[-2:] == ("scripts", "build_index.py")
    assert "--refresh" not in command
    assert "--query" not in command
    assert "--page-size" not in command
    assert _argument(command, "--snapshot").parts[-3:] == (
        "data",
        "marketplace",
        "agents-v1.jsonl",
    )
    assert _argument(command, "--output").name == "agents"
    assert _argument(command, "--hire-catalog").parts[-2:] == (
        "data",
        "warden-services.json",
    )
    assert _argument(command, "--marketplace-summary").parts[-2:] == (
        "data",
        "marketplace-summary.json",
    )

    promoted = index_root / "releases" / "20260716T030405Z"
    assert promoted.is_dir()
    assert current.read_text(encoding="utf-8") == "releases/20260716T030405Z"
    assert (promoted / "agents" / "index.html").is_file()
    assert not list((index_root / "releases").glob(".staging-*"))
    assert not list(index_root.glob(".current-*"))
    assert format_summary_log(summary) == (
        'capturedAt=2026-07-16T03:04:05Z query="a" sampled=2 expected=2 '
        "dropped=0 matched=1 audited=0"
    )


def test_secret_bearing_builder_consumes_completed_snapshot_without_live_cli(tmp_path):
    index_root = tmp_path / "index"
    public_snapshot = tmp_path / "public-snapshot" / "agents-v1.jsonl"
    public_snapshot.parent.mkdir()
    public_snapshot.write_bytes((ROOT / "data" / "marketplace" / "agents-v1.jsonl").read_bytes())
    calls: list[list[str]] = []

    def build_from_snapshot(command: list[str], cwd: Path) -> None:
        calls.append(command)
        staged_snapshot = _argument(command, "--snapshot")
        assert staged_snapshot.read_bytes() == public_snapshot.read_bytes()
        _write_release(staged_snapshot.parents[2])

    refresh_safety_index(
        index_root,
        snapshot_path=public_snapshot,
        command_runner=build_from_snapshot,
        symlink_creator=_fake_symlink,
    )

    assert len(calls) == 1
    assert "--refresh" not in calls[0]
    assert "--query" not in calls[0]
    assert "--page-size" not in calls[0]
    assert all("onchainos" not in argument for argument in calls[0])


def test_committed_snapshot_seed_builds_without_live_refresh_and_promotes(tmp_path):
    index_root = tmp_path / "index"
    calls: list[list[str]] = []

    def build_seed(command: list[str], cwd: Path) -> None:
        calls.append(command)
        snapshot = _argument(command, "--snapshot")
        assert snapshot.read_bytes() == COMMITTED_SNAPSHOT.read_bytes()
        _write_release(snapshot.parents[2])

    refresh_safety_index(
        index_root,
        from_committed_snapshot=True,
        command_runner=build_seed,
        symlink_creator=_fake_symlink,
    )

    assert len(calls) == 1
    assert "--refresh" not in calls[0]
    assert (index_root / "current").read_text(encoding="utf-8") == ("releases/20260716T030405Z")


def test_build_failure_preserves_current_and_cleans_staging(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)

    def fail_build(command: list[str], cwd: Path) -> None:
        raise RuntimeError("read-only marketplace fetch failed")

    with pytest.raises(RuntimeError, match="fetch failed"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=fail_build,
            symlink_creator=_fake_symlink,
        )

    assert current.read_text(encoding="utf-8") == "releases/old"
    assert {path.name for path in (index_root / "releases").iterdir()} == {"old"}
    assert not list(index_root.glob(".current-*"))


def test_validation_failure_preserves_current_and_cleans_staging(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)
    invalid = {**SUMMARY, "expected": 3}

    with pytest.raises(RuntimeError, match="dropped must equal"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner([], invalid),
            symlink_creator=_fake_symlink,
        )

    assert current.read_text(encoding="utf-8") == "releases/old"
    assert {path.name for path in (index_root / "releases").iterdir()} == {"old"}


def test_promotion_failure_preserves_current_and_removes_candidate_release(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)

    def fail_current_replace(source: Path, destination: Path) -> None:
        if Path(destination) == current:
            raise OSError("current switch failed")
        os.replace(source, destination)

    with pytest.raises(OSError, match="current switch failed"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner([]),
            symlink_creator=_fake_symlink,
            replacer=fail_current_replace,
        )

    assert current.read_text(encoding="utf-8") == "releases/old"
    assert {path.name for path in (index_root / "releases").iterdir()} == {"old"}
    assert not list(index_root.glob(".current-*"))


def test_existing_capture_is_never_deleted_or_replaced(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)
    existing = index_root / "releases" / "20260716T030405Z"
    existing.mkdir()
    (existing / "marker").write_text("existing capture", encoding="utf-8")

    with pytest.raises(RuntimeError, match="already exists"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner([]),
            symlink_creator=_fake_symlink,
        )

    assert current.read_text(encoding="utf-8") == "releases/old"
    assert (existing / "marker").read_text(encoding="utf-8") == "existing capture"
    assert not list((index_root / "releases").glob(".staging-*"))


def test_promotion_collision_never_deletes_another_runs_release(tmp_path):
    index_root = tmp_path / "index"
    current = _seed_current(index_root)
    collision = index_root / "releases" / "20260716T030405Z"

    def collide_during_promotion(source: Path, destination: Path) -> None:
        if Path(destination) == collision:
            collision.mkdir()
            (collision / "marker").write_text("other run", encoding="utf-8")
            raise FileExistsError("capture collision")
        os.replace(source, destination)

    with pytest.raises(FileExistsError, match="capture collision"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner([]),
            symlink_creator=_fake_symlink,
            replacer=collide_during_promotion,
        )

    assert current.read_text(encoding="utf-8") == "releases/old"
    assert (collision / "marker").read_text(encoding="utf-8") == "other run"
    assert not list((index_root / "releases").glob(".staging-*"))


def test_refresh_lock_rejects_another_process_without_breaking_holder(tmp_path):
    index_root = tmp_path / "index"
    index_root.mkdir()
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_refresh_lock,
        args=(str(index_root / _PROCESS_LOCK_NAME), ready, release),
    )
    calls: list[list[str]] = []

    holder.start()
    try:
        assert ready.wait(10)
        with pytest.raises(RuntimeError, match="another marketplace index refresh"):
            refresh_safety_index(
                index_root,
                snapshot_path=COMMITTED_SNAPSHOT,
                command_runner=_build_runner(calls),
                symlink_creator=_fake_symlink,
            )
        assert calls == []
        assert holder.is_alive()
    finally:
        release.set()
        holder.join(timeout=10)

    assert holder.exitcode == 0
    assert (index_root / _PROCESS_LOCK_NAME).is_file()
    assert (
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner(calls),
            symlink_creator=_fake_symlink,
        )
        == SUMMARY
    )


def test_refresh_rejects_a_symlinked_release_root_before_build(tmp_path, monkeypatch):
    index_root = tmp_path / "index"
    releases = index_root / "releases"
    releases.mkdir(parents=True)
    original_is_symlink = Path.is_symlink

    def report_release_symlink(path: Path) -> bool:
        return path == releases or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_release_symlink)

    with pytest.raises(RuntimeError, match="releases directory must not be a symlink"):
        refresh_safety_index(
            index_root,
            snapshot_path=COMMITTED_SNAPSHOT,
            command_runner=_build_runner([]),
        )


def test_refresh_rejects_a_symlinked_public_snapshot_before_build(tmp_path, monkeypatch):
    public_snapshot = tmp_path / "agents-v1.jsonl"
    public_snapshot.write_bytes(COMMITTED_SNAPSHOT.read_bytes())
    original_is_symlink = Path.is_symlink

    def report_snapshot_symlink(path: Path) -> bool:
        return path == public_snapshot or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_snapshot_symlink)
    calls: list[list[str]] = []

    with pytest.raises(RuntimeError, match="snapshot must be a regular non-symlink file"):
        refresh_safety_index(
            tmp_path / "index",
            snapshot_path=public_snapshot,
            command_runner=_build_runner(calls),
        )

    assert calls == []


def test_validate_release_rejects_schema_drift_and_incomplete_pages(tmp_path):
    release = tmp_path / "release"
    _write_release(release, {**SUMMARY, "unexpected": True})

    with pytest.raises(RuntimeError, match="exactly the v2 fields"):
        validate_release(release)

    _write_release(release)
    (release / "agents" / "3808.html").unlink()

    with pytest.raises(RuntimeError, match="generated agent pages"):
        validate_release(release)


def test_validate_release_rejects_mismatched_service_catalog_capture(tmp_path):
    release = tmp_path / "release"
    _write_release(release)
    catalog = release / "data" / "warden-services.json"
    document = json.loads(catalog.read_text(encoding="utf-8"))
    document["snapshotFetchedAt"] = "2026-07-15T03:04:05Z"
    catalog.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(RuntimeError, match="snapshotFetchedAt does not match"):
        validate_release(release)


def test_validate_release_rejects_summary_query_mismatch(tmp_path):
    release = tmp_path / "release"
    _write_release(release, {**SUMMARY, "query": "Warden"})

    with pytest.raises(RuntimeError, match="query does not match"):
        validate_release(release)


def test_validate_release_accepts_sample_above_inconsistent_reported_total(tmp_path):
    release = tmp_path / "release"
    _write_release(release, {**SUMMARY, "expected": 1, "dropped": 0})

    summary = validate_release(release)

    assert summary["sampled"] == 2
    assert summary["expected"] == 1
    assert summary["dropped"] == 0


def test_validate_release_cli_checks_existing_capture_without_building(tmp_path, capsys):
    release = tmp_path / "release"
    _write_release(release)

    main(["--validate-release", str(release)])

    assert capsys.readouterr().out.strip() == (
        'capturedAt=2026-07-16T03:04:05Z query="a" sampled=2 expected=2 '
        "dropped=0 matched=1 audited=0"
    )
