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

from warden import anchor_history, protection_store  # noqa: E402

DEFAULT_OUTPUT = ROOT / "site" / "data" / "apa-log-anchor.json"
DEFAULT_HISTORY_OUTPUT = ROOT / "site" / "data" / "apa-log-anchor-history.json"


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


def publish_checkpoint(
    path: Path,
    history_path: Path | None = None,
    *,
    pinned_history_head: str | None = None,
) -> None:
    output = _safe_output_path(path)
    history_output = _safe_output_path(
        output.with_name("apa-log-anchor-history.json") if history_path is None else history_path
    )
    if output == history_output or (
        output.exists() and history_output.exists() and os.path.samefile(output, history_output)
    ):
        raise ValueError("checkpoint and history outputs must be different files")
    if not history_output.exists():
        raise FileNotFoundError(
            f"anchor history is missing: {history_output}; restore the committed lineage"
        )
    try:
        history = json.loads(history_output.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("anchor history must contain valid JSON") from exc

    checkpoint = protection_store.read_log_checkpoint_for_external_publish()
    entries = protection_store.read_log()
    updated_history = anchor_history.append_checkpoint(
        history,
        checkpoint,
        entries,
        pinned_history_head=pinned_history_head,
        # The external-publish read verifies the local anchor without loading a
        # signing key; public verifiers perform the cryptographic check.
        verify_signatures=False,
    )
    if updated_history != history:
        _write_json_atomic(history_output, updated_history)
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
    parser.add_argument("--history-output", type=Path, default=DEFAULT_HISTORY_OUTPUT)
    parser.add_argument(
        "--pinned-history-head",
        help="Previously retained history head that must remain in the verified chain",
    )
    args = parser.parse_args()
    publish_checkpoint(
        args.output,
        args.history_output,
        pinned_history_head=args.pinned_history_head,
    )
    print(f"Published checkpoint to {Path(os.path.abspath(args.output))}")


if __name__ == "__main__":
    main()
