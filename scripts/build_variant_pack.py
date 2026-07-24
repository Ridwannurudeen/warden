"""Build deterministic adversarial variants from the training corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.adversarial_variants import build_variant_pack, write_variant_pack  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic adversarial evaluation pack from training rows only. "
            "This command performs no network or model calls."
        )
    )
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--training-attacks",
        type=Path,
        default=ROOT / "corpus" / "attacks.jsonl",
    )
    parser.add_argument(
        "--training-benign",
        type=Path,
        default=ROOT / "corpus" / "benign.jsonl",
    )
    parser.add_argument(
        "--held-out-attacks",
        type=Path,
        default=ROOT / "benchmark" / "held_out_attacks.jsonl",
    )
    parser.add_argument(
        "--held-out-benign",
        type=Path,
        default=ROOT / "benchmark" / "held_out_benign.jsonl",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_paths = {
        args.training_attacks.resolve(),
        args.training_benign.resolve(),
        args.held_out_attacks.resolve(),
        args.held_out_benign.resolve(),
    }
    if args.output.resolve() in source_paths:
        raise ValueError("variant pack output must not alias a source dataset")
    pack = build_variant_pack(
        training_attacks_path=args.training_attacks,
        training_benign_path=args.training_benign,
        held_out_attacks_path=args.held_out_attacks,
        held_out_benign_path=args.held_out_benign,
    )
    write_variant_pack(args.output, pack)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "variants": len(pack["variants"]),
                "corpus_fingerprint": pack["corpus_fingerprint"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
