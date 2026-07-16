"""Build and atomically promote a live Warden marketplace-index release."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX_ROOT = Path("/opt/warden-index")
DEFAULT_PUBLIC_SNAPSHOT = Path("/opt/warden-snapshot/agents-v1.jsonl")
COMMITTED_SNAPSHOT = ROOT / "data" / "marketplace" / "agents-v1.jsonl"
_PROCESS_LOCK_NAME = ".refresh-process.lock"
SUMMARY_FIELDS = {
    "schemaVersion",
    "capturedAt",
    "query",
    "sampled",
    "expected",
    "dropped",
    "matchedCount",
    "auditedCount",
}
COUNT_FIELDS = (
    "sampled",
    "expected",
    "dropped",
    "matchedCount",
    "auditedCount",
)

CommandRunner = Callable[[list[str], Path], None]
SymlinkCreator = Callable[[Path, Path, bool], None]
Replacer = Callable[[Path, Path], None]


class _RefreshLock:
    """Cross-platform process lock that is released if its holder exits."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> "_RefreshLock":
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name == "nt" and os.fstat(self.fd).st_size == 0:
                os.write(self.fd, b"\0")
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError("another marketplace index refresh is already running") from exc
        return self

    def __exit__(self, *exc: object) -> None:
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is missing or invalid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return document


def _capture_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError("marketplace summary capturedAt must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RuntimeError("marketplace summary capturedAt must be a UTC timestamp") from exc


def _validated_count(document: Mapping[str, object], field: str, label: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"{label} {field} must be a non-negative integer")
    return value


def _read_snapshot(snapshot_path: Path) -> tuple[dict[str, object], set[str]]:
    try:
        lines = snapshot_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError("marketplace snapshot is missing") from exc
    records: list[dict[str, object]] = []
    try:
        for line in lines:
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise RuntimeError("marketplace snapshot records must be JSON objects")
            records.append(record)
    except json.JSONDecodeError as exc:
        raise RuntimeError("marketplace snapshot contains invalid JSON") from exc
    if not records or records[0].get("kind") != "snapshot":
        raise RuntimeError("marketplace snapshot metadata record is missing")

    agent_ids: set[str] = set()
    for record in records[1:]:
        if record.get("kind") != "agent" or not isinstance(record.get("agent"), dict):
            raise RuntimeError("marketplace snapshot contains an invalid agent record")
        agent_id = record["agent"].get("agentId")
        if not isinstance(agent_id, str) or not agent_id.isdecimal():
            raise RuntimeError("marketplace snapshot contains an invalid agent ID")
        if agent_id in agent_ids:
            raise RuntimeError("marketplace snapshot contains a duplicate agent ID")
        agent_ids.add(agent_id)
    return records[0], agent_ids


def validate_release(release: Path) -> dict[str, object]:
    """Validate the public artifacts and count relationships in one candidate release."""
    summary = _load_json_object(
        release / "data" / "marketplace-summary.json",
        "marketplace summary",
    )
    if set(summary) != SUMMARY_FIELDS or summary.get("schemaVersion") != 2:
        raise RuntimeError("marketplace summary must contain exactly the v2 fields")

    captured_at = summary["capturedAt"]
    _capture_datetime(captured_at)
    query = summary["query"]
    if not isinstance(query, str) or not query or query != query.strip():
        raise RuntimeError("marketplace summary query must be a non-empty trimmed string")
    counts = {
        field: _validated_count(summary, field, "marketplace summary") for field in COUNT_FIELDS
    }
    if counts["sampled"] == 0:
        raise RuntimeError("marketplace summary sampled must be greater than zero")
    expected_dropped = max(counts["expected"] - counts["sampled"], 0)
    if counts["dropped"] != expected_dropped:
        raise RuntimeError(
            "marketplace summary dropped must equal max(expected minus sampled, zero)"
        )
    if counts["matchedCount"] > counts["sampled"]:
        raise RuntimeError("marketplace summary matchedCount cannot exceed sampled")
    if counts["auditedCount"] > counts["sampled"]:
        raise RuntimeError("marketplace summary auditedCount cannot exceed sampled")

    snapshot, agent_ids = _read_snapshot(release / "data" / "marketplace" / "agents-v1.jsonl")
    required_snapshot_fields = {
        "schema_version",
        "captured_at",
        "query",
        "sampled",
        "expected",
        "dropped",
    }
    if not required_snapshot_fields <= snapshot.keys() or snapshot.get("schema_version") != 2:
        raise RuntimeError("marketplace snapshot metadata must use schema version 2")
    for field in ("sampled", "expected", "dropped"):
        if _validated_count(snapshot, field, "marketplace snapshot") != counts[field]:
            raise RuntimeError(f"marketplace snapshot {field} does not match summary")
    if snapshot.get("captured_at") != captured_at:
        raise RuntimeError("marketplace snapshot captured_at does not match summary")
    if snapshot.get("query") != query:
        raise RuntimeError("marketplace snapshot query does not match summary")
    if len(agent_ids) != counts["sampled"]:
        raise RuntimeError("marketplace snapshot agent records do not match sampled")

    agents_directory = release / "agents"
    if not (agents_directory / "index.html").is_file():
        raise RuntimeError("generated agents/index.html is missing")
    generated_ids = {
        path.stem
        for path in agents_directory.glob("*.html")
        if path.name != "index.html" and path.stem.isdecimal()
    }
    if generated_ids != agent_ids:
        raise RuntimeError("generated agent pages do not match the marketplace snapshot")

    catalog = _load_json_object(
        release / "data" / "warden-services.json",
        "warden services catalog",
    )
    if catalog.get("schemaVersion") != 1 or not isinstance(catalog.get("services"), list):
        raise RuntimeError("warden services catalog must use schema version 1 with a services list")
    if catalog.get("snapshotFetchedAt") != captured_at:
        raise RuntimeError("warden services catalog snapshotFetchedAt does not match summary")
    return summary


def format_summary_log(summary: Mapping[str, object]) -> str:
    """Return the single journal line emitted after a successful promotion."""
    return (
        f"capturedAt={summary['capturedAt']} "
        f"query={json.dumps(summary['query'], ensure_ascii=False)} "
        f"sampled={summary['sampled']} "
        f"expected={summary['expected']} "
        f"dropped={summary['dropped']} "
        f"matched={summary['matchedCount']} "
        f"audited={summary['auditedCount']}"
    )


def _run_build_index(command: list[str], cwd: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if completed.returncode != 0:
        details = []
        if completed.stdout.strip():
            details.append(f"stdout: {completed.stdout.strip()}")
        if completed.stderr.strip():
            details.append(f"stderr: {completed.stderr.strip()}")
        suffix = f" ({'; '.join(details)})" if details else ""
        raise RuntimeError(
            f"marketplace index build failed with exit code {completed.returncode}{suffix}"
        )


def _build_command(staging: Path) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "scripts" / "build_index.py"),
        "--snapshot",
        str(staging / "data" / "marketplace" / "agents-v1.jsonl"),
        "--output",
        str(staging / "agents"),
        "--hire-catalog",
        str(staging / "data" / "warden-services.json"),
        "--marketplace-summary",
        str(staging / "data" / "marketplace-summary.json"),
        "--badge-store",
        str(ROOT / "badges" / "issued.jsonl"),
        "--badge-links",
        str(ROOT / "data" / "marketplace" / "badge-links-v1.json"),
    ]


def _prepare_index_paths(index_root: Path) -> tuple[Path, Path]:
    root_path = Path(index_root)
    if root_path.is_symlink():
        raise RuntimeError("index root must not be a symlink")
    if root_path.exists() and not root_path.is_dir():
        raise RuntimeError("index root must be a directory")
    root_path.mkdir(parents=True, exist_ok=True)
    root = root_path.resolve()

    releases_path = root / "releases"
    if releases_path.is_symlink():
        raise RuntimeError("releases directory must not be a symlink")
    if releases_path.exists() and not releases_path.is_dir():
        raise RuntimeError("releases path must be a directory")
    releases_path.mkdir(exist_ok=True)
    releases = releases_path.resolve()
    if releases.parent != root:
        raise RuntimeError("releases directory must stay inside the index root")
    return root, releases


def _remove_generated_path(path: Path, releases: Path) -> None:
    if path.parent.resolve() != releases:
        raise RuntimeError("refusing to clean a path outside the releases directory")
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if path.resolve().parent != releases:
            raise RuntimeError("refusing to clean a directory outside the releases directory")
        shutil.rmtree(path)


def _copy_completed_snapshot(source: Path, destination: Path, owner: str | None) -> None:
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise RuntimeError("public marketplace snapshot is missing") from exc
    if source.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
        raise RuntimeError("public marketplace snapshot must be a regular non-symlink file")

    expected_uid: int | None = None
    if owner is not None:
        if os.name == "nt":
            raise RuntimeError("snapshot owner validation requires a POSIX host")
        import pwd

        try:
            expected_uid = pwd.getpwnam(owner).pw_uid
        except KeyError as exc:
            raise RuntimeError(f"snapshot owner does not exist: {owner}") from exc

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise RuntimeError("public marketplace snapshot could not be opened safely") from exc
    try:
        opened_stat = os.fstat(source_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise RuntimeError("public marketplace snapshot must be a regular non-symlink file")
        if expected_uid is not None and opened_stat.st_uid != expected_uid:
            raise RuntimeError("public marketplace snapshot has an unexpected owner")
        if os.name != "nt" and opened_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError("public marketplace snapshot must not be group- or world-writable")
        with os.fdopen(source_fd, "rb", closefd=False) as source_handle:
            with destination.open("xb") as destination_handle:
                shutil.copyfileobj(source_handle, destination_handle)
        os.chmod(destination, 0o644)
    finally:
        os.close(source_fd)


def refresh_safety_index(
    index_root: Path,
    *,
    snapshot_path: Path = DEFAULT_PUBLIC_SNAPSHOT,
    snapshot_owner: str | None = None,
    expected_query: str = "a",
    from_committed_snapshot: bool = False,
    command_runner: CommandRunner = _run_build_index,
    symlink_creator: SymlinkCreator = os.symlink,
    replacer: Replacer = os.replace,
) -> dict[str, object]:
    """Build, validate, and atomically make one release current."""
    root, releases = _prepare_index_paths(index_root)
    with _RefreshLock(root / _PROCESS_LOCK_NAME):
        token = uuid.uuid4().hex
        staging = releases / f".staging-{token}"
        temporary_current = root / f".current-{token}"
        candidate_release: Path | None = None
        staging.mkdir()

        try:
            source_snapshot = COMMITTED_SNAPSHOT if from_committed_snapshot else snapshot_path
            snapshot = staging / "data" / "marketplace" / "agents-v1.jsonl"
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            _copy_completed_snapshot(
                source_snapshot,
                snapshot,
                None if from_committed_snapshot else snapshot_owner,
            )
            command_runner(
                _build_command(staging),
                ROOT,
            )
            summary = validate_release(staging)
            if summary["query"] != expected_query:
                raise RuntimeError(
                    "marketplace release query does not match the configured discovery query"
                )
            capture_name = _capture_datetime(summary["capturedAt"]).strftime("%Y%m%dT%H%M%SZ")
            release_path = releases / capture_name
            if os.path.lexists(release_path):
                raise RuntimeError(f"marketplace release {capture_name} already exists")

            replacer(staging, release_path)
            candidate_release = release_path
            relative_target = Path("releases") / capture_name
            symlink_creator(relative_target, temporary_current, True)
            replacer(temporary_current, root / "current")
            return summary
        except BaseException:
            if os.path.lexists(temporary_current):
                temporary_current.unlink()
            if candidate_release is not None and os.path.lexists(candidate_release):
                _remove_generated_path(candidate_release, releases)
            elif os.path.lexists(staging):
                _remove_generated_path(staging, releases)
            raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Refresh the live Warden Safety Index atomically.")
    parser.add_argument("--index-root", type=Path, default=DEFAULT_INDEX_ROOT)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_PUBLIC_SNAPSHOT)
    parser.add_argument("--snapshot-owner")
    parser.add_argument("--expected-query", default="a")
    parser.add_argument(
        "--validate-release",
        type=Path,
        help="Validate an existing immutable release without fetching, building, or promoting.",
    )
    parser.add_argument(
        "--from-committed-snapshot",
        action="store_true",
        help="Seed a release from the committed snapshot without a live CLI refresh.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if args.validate_release is not None:
        summary = validate_release(args.validate_release)
    else:
        summary = refresh_safety_index(
            args.index_root,
            snapshot_path=args.snapshot,
            snapshot_owner=args.snapshot_owner,
            expected_query=args.expected_query,
            from_committed_snapshot=args.from_committed_snapshot,
        )
    print(format_summary_log(summary))


if __name__ == "__main__":
    main()
