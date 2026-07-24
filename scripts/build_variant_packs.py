"""Build deterministic per-class adversarial variant packs from the training corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.adversarial_variants import (  # noqa: E402
    HELD_OUT_ATTACKS_PATH,
    HELD_OUT_BENIGN_PATH,
    TRAINING_ATTACKS_PATH,
    TRAINING_BENIGN_PATH,
    build_variant_packs,
    write_variant_packs,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build deterministic per-threat-class adversarial evaluation packs from training "
            "rows only. This command performs no network or model calls."
        )
    )
    parser.add_argument("output_directory", type=Path)
    parser.add_argument(
        "--training-attacks",
        type=Path,
        default=TRAINING_ATTACKS_PATH,
        help="Canonical corpus/attacks.jsonl path.",
    )
    parser.add_argument(
        "--training-benign",
        type=Path,
        default=TRAINING_BENIGN_PATH,
        help="Canonical corpus/benign.jsonl path.",
    )
    parser.add_argument(
        "--held-out-attacks",
        type=Path,
        default=HELD_OUT_ATTACKS_PATH,
        help="Canonical benchmark/held_out_attacks.jsonl exclusion path.",
    )
    parser.add_argument(
        "--held-out-benign",
        type=Path,
        default=HELD_OUT_BENIGN_PATH,
        help="Canonical benchmark/held_out_benign.jsonl exclusion path.",
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
    output_directory = args.output_directory.resolve()
    if any(path == output_directory or path.parent == output_directory for path in source_paths):
        raise ValueError("variant pack output directory must not contain a source dataset")
    packs = build_variant_packs(
        training_attacks_path=args.training_attacks,
        training_benign_path=args.training_benign,
        held_out_attacks_path=args.held_out_attacks,
        held_out_benign_path=args.held_out_benign,
    )
    index = write_variant_packs(args.output_directory, packs)
    print(
        json.dumps(
            {
                "output_directory": str(output_directory),
                "total_variants": index["total_variants"],
                "corpus_fingerprint": index["corpus_fingerprint"],
                "classes": {
                    str(entry["threat_class"]): entry["variants"] for entry in index["classes"]
                },
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
