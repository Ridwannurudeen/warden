"""Capture payload-free model scores for an independently reviewed calibration set."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.model_calibration import (  # noqa: E402
    build_capture,
    capture_embedding_scores,
    capture_semantic_scores,
    load_calibration_cases,
    write_artifact,
)
from warden.scanner.embedding import build_embedding_analyzer_from_env  # noqa: E402
from warden.scanner.patterns import KNOWN_INJECTIONS  # noqa: E402
from warden.scanner.semantic import build_semantic_analyzer_from_env  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("embedding", "semantic"), required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--captured-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


async def _capture(args: argparse.Namespace) -> dict[str, object]:
    cases, dataset_sha256 = load_calibration_cases(args.dataset)
    if args.tier == "semantic":
        analyzer = build_semantic_analyzer_from_env()
        model = os.environ.get("WARDEN_SEMANTIC_MODEL", "").strip()
        if analyzer is None or not model:
            raise ValueError("semantic calibration requires the enabled provider configuration")
        scored = await capture_semantic_scores(cases, analyzer)
    else:
        analyzer = build_embedding_analyzer_from_env()
        model = os.environ.get("WARDEN_EMBEDDING_MODEL", "").strip()
        if analyzer is None or not model:
            raise ValueError("embedding calibration requires the enabled provider configuration")
        scored = await capture_embedding_scores(cases, analyzer, tuple(KNOWN_INJECTIONS))
    return build_capture(
        tier=args.tier,
        dataset_id=args.dataset_id,
        dataset_sha256=dataset_sha256,
        provider=args.provider,
        model=model,
        captured_at=args.captured_at,
        scored_cases=scored,
    )


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        capture = asyncio.run(_capture(args))
        write_artifact(args.output, capture)
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
