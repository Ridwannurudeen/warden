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
from warden.sitemap import write_crawler_files  # noqa: E402

DEFAULT_DOCS_OUTPUT = ROOT / "site" / "docs"
DEFAULT_SPEC_OUTPUT = ROOT / "site" / "spec" / "APA-SPEC.md"
DEFAULT_SITE_ROOT = ROOT / "site"
PUBLIC_SPEC_FILES = (
    "ASP-PAYLOAD-SECURITY-STANDARD.md",
    "CONFORMANCE.md",
    "payload-security-profile-v0.1.json",
)
PUBLIC_SPEC_SCHEMA_FILES = ("apa-endpoint-audit-v0.1.schema.json",)
PUBLIC_AUDIT_FILES = ("warden-core-http-2026-07.json",)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Warden's generated static pages.")
    parser.add_argument("--docs-output", type=Path, default=DEFAULT_DOCS_OUTPUT)
    parser.add_argument(
        "--spec-output",
        type=Path,
        default=DEFAULT_SPEC_OUTPUT,
    )
    parser.add_argument(
        "--site-root",
        type=Path,
        help="Complete public site tree whose assets and crawler files should be regenerated.",
    )
    return parser.parse_args()


def _crawler_site_root(args: argparse.Namespace) -> Path | None:
    if args.site_root is not None:
        return args.site_root
    if args.docs_output == DEFAULT_DOCS_OUTPUT and args.spec_output == DEFAULT_SPEC_OUTPUT:
        return DEFAULT_SITE_ROOT
    return None


def version_static_assets(site: Path) -> int:
    """Append content hashes to local stylesheet and script references."""
    versions = {
        path.relative_to(site).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()[:8]
        for path in site.rglob("*")
        if path.is_file() and path.suffix in {".css", ".js"}
    }
    pattern = re.compile(r'((?:href|src)=")(/[A-Za-z0-9._/-]+\.(?:css|js))(?:\?v=[0-9a-f]{8})?(")')

    def replace(match: re.Match[str]) -> str:
        asset = match.group(2).lstrip("/")
        version = versions.get(asset)
        if version is None:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}?v={version}{match.group(3)}"

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
    for name in PUBLIC_SPEC_FILES:
        (args.spec_output.parent / name).write_bytes((ROOT / "spec" / name).read_bytes())
    public_schema_dir = args.spec_output.parent / "schemas"
    public_schema_dir.mkdir(parents=True, exist_ok=True)
    for name in PUBLIC_SPEC_SCHEMA_FILES:
        (public_schema_dir / name).write_bytes((ROOT / "spec" / "schemas" / name).read_bytes())
    public_audit_dir = args.spec_output.parent.parent / "audit"
    public_audit_dir.mkdir(parents=True, exist_ok=True)
    for name in PUBLIC_AUDIT_FILES:
        (public_audit_dir / name).write_bytes((ROOT / "audit" / name).read_bytes())
    print(
        "Built 11 reason-code pages, the documentation index, the public APA spec, "
        "the ASP payload-security standard, and its linked conformance assets."
    )
    site_root = _crawler_site_root(args)
    if site_root is not None:
        versioned = version_static_assets(site_root)
        routes = write_crawler_files(site_root)
        print(f"Versioned local CSS/JavaScript references on {versioned} page(s).")
        print(f"Generated crawler files for {len(routes)} canonical public routes.")


if __name__ == "__main__":
    main()
