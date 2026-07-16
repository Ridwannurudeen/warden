"""Atomically publish the current signed APA log checkpoint as static data."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden import protection_store  # noqa: E402

DEFAULT_OUTPUT = ROOT / "site" / "data" / "apa-log-anchor.json"


def _safe_output_path(path: Path) -> Path:
    output = Path(os.path.abspath(path))
    if output.is_symlink():
        raise ValueError("checkpoint output must not be a symbolic link")
    for parent in (output.parent, *output.parent.parents):
        if parent.is_symlink():
            raise ValueError("checkpoint output parent must not be a symbolic link")
    if not output.parent.is_dir():
        raise ValueError("checkpoint output parent must be an existing directory")
    if output.exists() and not stat.S_ISREG(output.lstat().st_mode):
        raise ValueError("checkpoint output must be a regular file")
    return output


def _write_json_atomic(path: Path, document: dict[str, object]) -> None:
    serialized = json.dumps(document, indent=2) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def publish_checkpoint(path: Path) -> None:
    output = _safe_output_path(path)
    checkpoint = protection_store.read_log_checkpoint_for_external_publish()
    _write_json_atomic(
        output,
        {
            "schema_version": 1,
            "status": "published",
            "checkpoint": checkpoint,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish the current signed APA log checkpoint without loading its signing key."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    publish_checkpoint(args.output)
    print(f"Published checkpoint to {Path(os.path.abspath(args.output))}")


if __name__ == "__main__":
    main()
