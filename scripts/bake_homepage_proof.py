"""Bake the dated homepage proof values into Warden's static markup.

The homepage fetches its evaluation, product-proof, and catalog snapshots at
runtime. Without this step the shipped markup asserts that none of them exist,
so a crawler, a no-JavaScript reader, or a failed fetch sees Warden claim it has
no evidence. Baking the committed snapshot makes the default state the last
known good value, stamped DATED rather than LIVE.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SITE_ROOT = ROOT / "site"

SERVICE_CARD_PATTERN = re.compile(
    r'<article data-service-key="(?P<key>[a-z-]+)">.*?</article>',
    re.DOTALL,
)


def _text_slot(tag: str, marker: str) -> re.Pattern[str]:
    """Match the text node of the single element carrying ``marker``."""
    return re.compile(rf"(<{tag}[^>]*{re.escape(marker)}[^>]*>\s*)[^<]*?(\s*</{tag})")


RECALL_SLOT = _text_slot("strong", 'data-eval-stat="recall"')
FP_RATE_SLOT = _text_slot("strong", 'data-eval-stat="fp-rate"')
BENIGN_CASES_SLOT = _text_slot("small", 'data-eval-stat="benign-cases"')
LATENCY_SLOT = _text_slot("strong", 'data-proof-field="latency"')
LATENCY_SAMPLE_SLOT = _text_slot("small", 'data-proof-field="latency-sample"')
PROOF_STATUS_SLOT = _text_slot("p", "data-product-proof-status")
SERVICE_SNAPSHOT_SLOT = _text_slot("p", "data-service-snapshot")
SERVICE_ID_SLOT = _text_slot("span", 'data-service-field="id"')
SERVICE_PRICE_SLOT = _text_slot("strong", "data-service-price")
FALLBACK_SNAPSHOT_ATTRIBUTE = re.compile(r'(data-fallback-snapshot=")[^"]*(")')


def _number(value: float | int) -> str:
    """Render a JSON number the way the browser template literals in app.js do."""
    return str(int(value)) if float(value).is_integer() else str(value)


def _fill(source: str, slot: re.Pattern[str], text: str) -> str:
    updated, count = slot.subn(lambda match: f"{match.group(1)}{text}{match.group(2)}", source)
    if count != 1:
        raise ValueError(f"{slot.pattern} matched {count} homepage slots; expected exactly one")
    return updated


def _service(catalog: dict, key: str) -> dict:
    for service in catalog["services"]:
        if service["key"] == key:
            return service
    raise ValueError(f"{key} is not published in the generated service catalog")


def baked_homepage(site: Path = DEFAULT_SITE_ROOT) -> str:
    """Return the homepage with every dated value refreshed from its source file."""
    data = site / "data"
    evaluation = json.loads((data / "evaluation.json").read_text(encoding="utf-8"))["current"]
    proof = json.loads((data / "product-proof.json").read_text(encoding="utf-8"))
    catalog = json.loads((data / "warden-services.json").read_text(encoding="utf-8"))
    benchmark = proof["checkoutBenchmark"]
    snapshot = catalog["snapshotFetchedAt"]

    page = (site / "index.html").read_text(encoding="utf-8")
    page = _fill(page, RECALL_SLOT, f"{_number(evaluation['attack_recall_percent'])}%")
    page = _fill(page, FP_RATE_SLOT, f"{_number(evaluation['false_positive_rate_percent'])}%")
    page = _fill(
        page,
        BENIGN_CASES_SLOT,
        f"{evaluation['benign_cases']:,} held-out benign cases",
    )
    page = _fill(page, LATENCY_SLOT, f"{_number(benchmark['p50Ms'])} ms")
    page = _fill(page, LATENCY_SAMPLE_SLOT, f"{benchmark['payloadCount']:,} payloads")
    page = _fill(
        page,
        PROOF_STATUS_SLOT,
        f"DATED · evaluation {evaluation['measured_at'][:10]} · "
        f"product proof {proof['verifiedAt']}",
    )
    page = _fill(page, SERVICE_SNAPSHOT_SLOT, f"Committed catalog snapshot {snapshot}")
    page = FALLBACK_SNAPSHOT_ATTRIBUTE.sub(rf"\g<1>{snapshot}\g<2>", page)

    def bake_card(match: re.Match[str]) -> str:
        service = _service(catalog, match.group("key"))
        card = _fill(match.group(0), SERVICE_ID_SLOT, f"#{service['serviceId']}")
        return _fill(card, SERVICE_PRICE_SLOT, f"{service['feeAmount']} USDT")

    return SERVICE_CARD_PATTERN.sub(bake_card, page)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--site-root", type=Path, default=DEFAULT_SITE_ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when the committed homepage is out of date instead of rewriting it.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    homepage = args.site_root / "index.html"
    baked = baked_homepage(args.site_root)
    if baked == homepage.read_text(encoding="utf-8"):
        print("Homepage proof values already match their dated snapshots.")
        return
    if args.check:
        print(f"{homepage} is stale; run python scripts/bake_homepage_proof.py", file=sys.stderr)
        raise SystemExit(1)
    homepage.write_text(baked, encoding="utf-8", newline="\n")
    print("Baked the dated evaluation, product-proof, and catalog values into the homepage.")


if __name__ == "__main__":
    main()
