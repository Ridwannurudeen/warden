"""Build generated Warden documentation pages."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.site_docs import render_docs  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Warden's generated static pages.")
    parser.add_argument("--docs-output", type=Path, default=ROOT / "site" / "docs")
    parser.add_argument(
        "--spec-output",
        type=Path,
        default=ROOT / "site" / "spec" / "APA-SPEC.md",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    render_docs(ROOT, args.docs_output)
    args.spec_output.parent.mkdir(parents=True, exist_ok=True)
    args.spec_output.write_bytes((ROOT / "spec" / "APA-SPEC.md").read_bytes())
    print("Built 11 reason-code pages, the documentation index, and the public APA spec.")


if __name__ == "__main__":
    main()
