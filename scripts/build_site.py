"""Build generated Warden documentation pages."""

from __future__ import annotations

import argparse
import hashlib
import re
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


def version_static_assets(site: Path) -> int:
    """Append a content-hash query to styles.css/app.js references for cache busting."""
    versions = {
        asset: hashlib.sha256((site / asset).read_bytes()).hexdigest()[:8]
        for asset in ("styles.css", "app.js")
    }
    pattern = re.compile(r'((?:href|src)=")(/(?:styles\.css|app\.js))(?:\?v=[0-9a-f]{8})?(")')

    def replace(match: re.Match[str]) -> str:
        asset = match.group(2).lstrip("/")
        return f"{match.group(1)}{match.group(2)}?v={versions[asset]}{match.group(3)}"

    updated = 0
    for page in sorted(site.rglob("*.html")):
        source = page.read_text(encoding="utf-8")
        versioned = pattern.sub(replace, source)
        if versioned != source:
            page.write_text(versioned, encoding="utf-8", newline="\n")
            updated += 1
    return updated


def main() -> None:
    args = parse_args()
    render_docs(ROOT, args.docs_output)
    args.spec_output.parent.mkdir(parents=True, exist_ok=True)
    args.spec_output.write_bytes((ROOT / "spec" / "APA-SPEC.md").read_bytes())
    versioned = version_static_assets(ROOT / "site")
    print("Built 11 reason-code pages, the documentation index, and the public APA spec.")
    print(f"Versioned styles.css/app.js references on {versioned} page(s).")


if __name__ == "__main__":
    main()
