"""Render aggregate-only threat-intelligence JSON and Markdown."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden import feedback_store, threat_intel  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a privacy-safe aggregate threat-intelligence report."
    )
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument(
        "--generated-at",
        help="Exact UTC timestamp for a reproducible report; defaults to current UTC.",
    )
    return parser.parse_args(argv)


def _stage_output(path: Path, content: bytes) -> Path:
    if path.exists() and path.is_symlink():
        raise SystemExit(f"output path must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    with temporary.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def _restore_output(path: Path, original: bytes | None) -> None:
    if original is None:
        path.unlink(missing_ok=True)
        return
    temporary = _stage_output(path, original)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_report_pair(
    json_path: Path,
    json_content: str,
    markdown_path: Path,
    markdown_content: str,
) -> None:
    if json_path.resolve() == markdown_path.resolve():
        raise SystemExit("JSON and Markdown outputs must use different paths")
    for path in (json_path, markdown_path):
        if path.exists() and path.is_symlink():
            raise SystemExit(f"output path must not be a symlink: {path}")
    originals = {
        json_path: json_path.read_bytes() if json_path.exists() else None,
        markdown_path: markdown_path.read_bytes() if markdown_path.exists() else None,
    }
    staged: dict[Path, Path] = {}
    json_replaced = False
    try:
        staged[json_path] = _stage_output(json_path, json_content.encode("utf-8"))
        staged[markdown_path] = _stage_output(
            markdown_path,
            markdown_content.encode("utf-8"),
        )
        os.replace(staged[json_path], json_path)
        json_replaced = True
        os.replace(staged[markdown_path], markdown_path)
    except BaseException:
        if json_replaced:
            _restore_output(json_path, originals[json_path])
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    generated_at = threat_intel.normalize_utc_time(
        threat_intel.parse_utc_timestamp(args.generated_at) if args.generated_at else None
    )
    report = threat_intel.build_report(
        feedback_store.list_feedback(now=generated_at, compact=False),
        generated_at=generated_at,
    )
    _write_report_pair(
        args.json_output,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        args.markdown_output,
        threat_intel.render_report_markdown(report),
    )
    print(
        json.dumps(
            {
                "included_records": report["included_records"],
                "status": report["status"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
