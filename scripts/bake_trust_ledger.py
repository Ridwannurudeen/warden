"""Bake Warden's published evidence ledger into the trust page.

Every ledger row names a record the site already serves, the date that record
was produced, and what it holds. Hand-written rows go stale the moment a
snapshot is refreshed, so the row bodies and the detection-limit figures are
generated from the same committed files the site serves.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SITE_ROOT = ROOT / "site"
BENCHMARK_RESULTS = ROOT / "benchmark" / "results.json"
BATTERY_FILE = "warden-core-http-2026-07.json"

ROW_INDENT = " " * 14
CELL_INDENT = " " * 16
TBODY_CLOSE_INDENT = " " * 12
STAMP_INDENT = 10
DETECTION_LIMIT_INDENT = 14


def _inner(tag: str, marker: str) -> re.Pattern[str]:
    """Match the inner content of the single element carrying ``marker``."""
    return re.compile(rf"(<{tag}[^>]*\b{re.escape(marker)}\b[^>]*>).*?(</{tag}>)", re.DOTALL)


LEDGER_BODY = _inner("tbody", "data-evidence-ledger")
LEDGER_STAMP = _inner("p", "data-ledger-stamp")
DETECTION_LIMIT = _inner("p", "data-detection-limit")


def _fill(source: str, slot: re.Pattern[str], body: str) -> str:
    updated, count = slot.subn(lambda match: f"{match.group(1)}{body}{match.group(2)}", source)
    if count != 1:
        raise ValueError(f"{slot.pattern} matched {count} trust-page slots; expected exactly one")
    return updated


def _number(value: float | int) -> str:
    """Render a JSON number without a trailing ``.0``."""
    return str(int(value)) if float(value).is_integer() else str(value)


def _row(artifact: str, produced: str, method: str, holds: str, record: str) -> str:
    cells = (
        f'<th scope="row">{artifact}</th>',
        f"<td>{produced}</td>",
        f"<td>{method}</td>",
        f"<td>{holds}</td>",
        f"<td>{record}</td>",
    )
    body = "".join(f"\n{CELL_INDENT}{cell}" for cell in cells)
    return f"{ROW_INDENT}<tr>{body}\n{ROW_INDENT}</tr>"


def _link(href: str, text: str) -> str:
    return f'<a href="{href}">{html.escape(text)}</a>'


def _ledger_rows(site: Path) -> list[str]:
    data = site / "data"
    evaluation = json.loads((data / "evaluation.json").read_text(encoding="utf-8"))["current"]
    marketplace = json.loads((data / "marketplace-summary.json").read_text(encoding="utf-8"))
    proof = json.loads((data / "product-proof.json").read_text(encoding="utf-8"))
    status = json.loads((data / "site-status.json").read_text(encoding="utf-8"))
    catalog = json.loads((data / "warden-services.json").read_text(encoding="utf-8"))
    anchor = json.loads((data / "apa-log-anchor.json").read_text(encoding="utf-8"))
    monitor = json.loads((data / "service-monitor.json").read_text(encoding="utf-8"))
    battery = json.loads((site / "audit" / BATTERY_FILE).read_text(encoding="utf-8"))
    index_data = json.loads((site / "agents" / "index-data.json").read_text(encoding="utf-8"))

    benchmark = proof["checkoutBenchmark"]
    corpus = proof["evaluationCorpus"]
    classes = len({probe["category"] for probe in battery["probes"]})
    services = ", ".join(
        f"#{service['serviceId']} {html.escape(service['serviceName'])}"
        for service in catalog["services"]
    )
    fees = sorted({service["feeAmount"] for service in catalog["services"]})

    return [
        _row(
            "Held-out detection evaluation",
            evaluation["measured_at"],
            f"{html.escape(evaluation['benchmark'])} · {html.escape(evaluation['mode'])}",
            f"{evaluation['detected_attacks']} of {evaluation['attack_cases']} attacks detected "
            f"({_number(evaluation['attack_recall_percent'])}%); "
            f"{evaluation['false_positives']} of {evaluation['benign_cases']} benign false "
            f"positives; result <code>sha256:{evaluation['result_sha256'][:16]}…</code>",
            _link("/data/evaluation.json", "evaluation.json"),
        ),
        _row(
            "Endpoint audit probe battery",
            f"{html.escape(battery['battery_id'])} {html.escape(battery['version'])}",
            html.escape(battery["methodology"]),
            f"{len(battery['probes'])} fixed probes across {classes} threat classes and "
            f"{len(battery['benign_controls'])} benign controls",
            _link(f"/audit/{BATTERY_FILE}", BATTERY_FILE),
        ),
        _row(
            "Marketplace evidence index",
            index_data["capturedAt"],
            "Fast-depth scan of public listing text only; no endpoint is called",
            f"{index_data['sampled']} agent records with a verdict and scanned-field count; "
            f"linked endpoint audits: {'some' if index_data['hasAudits'] else 'none'}; "
            f"linked attestations: {'some' if index_data['hasAttestations'] else 'none'}",
            f"{_link('/agents', 'index')} · {_link('/agents/index-data.json', 'index-data.json')}",
        ),
        _row(
            "Marketplace capture summary",
            marketplace["capturedAt"],
            f"Listing search for query “{html.escape(marketplace['query'])}”",
            f"{marketplace['sampled']} of {marketplace['expected']} listed agents captured, "
            f"{marketplace['dropped']} dropped; {marketplace['matchedCount']} public-text "
            f"matches; {marketplace['auditedCount']} audited",
            _link("/data/marketplace-summary.json", "marketplace-summary.json"),
        ),
        _row(
            "Checkout benchmark and corpus snapshot",
            benchmark["measuredAt"],
            html.escape(benchmark["method"]),
            f"p50 {_number(benchmark['p50Ms'])} ms over {benchmark['payloadCount']} payloads; "
            f"corpus {corpus['total']} cases ({corpus['attacks']} attack, "
            f"{corpus['benign']} benign)",
            _link("/data/product-proof.json", "product-proof.json"),
        ),
        _row(
            "Repository and listing status",
            status["verifiedAt"],
            html.escape(status["repositoryTestsNote"]),
            f"{status['repositoryTests']} tests recorded; corpus {status['corpusCount']} cases "
            f"fingerprinted <code>{html.escape(status['corpusFingerprint'][:23])}…</code>; "
            f"listing {html.escape(status['listingStatus'].lower())} "
            f"{status['listingVerifiedAt']}",
            _link("/data/site-status.json", "site-status.json"),
        ),
        _row(
            "Published service catalogue",
            catalog["snapshotFetchedAt"],
            f"Marketplace snapshot for provider agent #{catalog['providerAgentId']}",
            f"{services}; {' and '.join(fees)} USDT each",
            _link("/data/warden-services.json", "warden-services.json"),
        ),
        _row(
            "APA transparency-log anchor",
            "Not produced",
            "Independently anchored checkpoint over the signed log",
            f"status <code>{html.escape(anchor['status'])}</code>; no checkpoint exists in this "
            "build, so log continuity has no external timestamp",
            _link("/data/apa-log-anchor.json", "apa-log-anchor.json"),
        ),
        _row(
            "Service availability monitor",
            "Not produced",
            "Independently scheduled readiness probes over a 30-day window",
            f"status <code>{html.escape(monitor['status'])}</code>; "
            f"{len(monitor['samples'])} retained samples, so no availability is measured",
            _link("/data/service-monitor.json", "service-monitor.json"),
        ),
    ]


def _paragraph(text: str, indent: int) -> str:
    wrapped = textwrap.fill(
        text,
        width=80,
        initial_indent=" " * indent,
        subsequent_indent=" " * indent,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return f"\n{wrapped}\n{' ' * (indent - 2)}"


def _newest_record(site: Path) -> str:
    catalog = json.loads((site / "data" / "warden-services.json").read_text(encoding="utf-8"))
    evaluation = json.loads((site / "data" / "evaluation.json").read_text(encoding="utf-8"))
    index_data = json.loads((site / "agents" / "index-data.json").read_text(encoding="utf-8"))
    return max(
        catalog["snapshotFetchedAt"],
        evaluation["current"]["measured_at"],
        index_data["capturedAt"],
    )


def baked_trust_page(site: Path = DEFAULT_SITE_ROOT) -> str:
    """Return the trust page with the ledger and detection limit regenerated."""
    page = (site / "trust.html").read_text(encoding="utf-8")
    rows = "\n".join(_ledger_rows(site))
    page = _fill(page, LEDGER_BODY, f"\n{rows}\n{TBODY_CLOSE_INDENT}")
    page = _fill(
        page,
        LEDGER_STAMP,
        _paragraph(f"DATED · newest committed record {_newest_record(site)}", STAMP_INDENT),
    )

    evaluation = json.loads((site / "data" / "evaluation.json").read_text(encoding="utf-8"))[
        "current"
    ]
    misses = json.loads(BENCHMARK_RESULTS.read_text(encoding="utf-8"))["attack_misses"]
    return _fill(
        page,
        DETECTION_LIMIT,
        _paragraph(
            "ALLOW means no implemented detector fired, not that the payload is safe. The "
            f"committed held-out baseline is {_number(evaluation['attack_recall_percent'])}% "
            f"recall ({evaluation['detected_attacks']} of {evaluation['attack_cases']} attacks) "
            f"at {evaluation['false_positives']} of {evaluation['benign_cases']} benign false "
            f"positives, so {evaluation['attack_cases'] - evaluation['detected_attacks']} known "
            f"attacks are not detected. Their case ids stay published rather than trained away: "
            f"{', '.join(misses)}. The optional semantic and embedding tiers are disabled by "
            "default and their thresholds are uncalibrated.",
            DETECTION_LIMIT_INDENT,
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--site-root", type=Path, default=DEFAULT_SITE_ROOT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when the committed trust page is out of date instead of rewriting it.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    trust = args.site_root / "trust.html"
    baked = baked_trust_page(args.site_root)
    if baked == trust.read_text(encoding="utf-8"):
        print("Trust ledger already matches its committed records.")
        return
    if args.check:
        print(f"{trust} is stale; run python scripts/bake_trust_ledger.py", file=sys.stderr)
        raise SystemExit(1)
    trust.write_text(baked, encoding="utf-8", newline="\n")
    print("Baked the published evidence ledger and detection limit into the trust page.")


if __name__ == "__main__":
    main()
