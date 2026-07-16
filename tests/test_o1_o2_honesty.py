"""O1/O2 scanner-description and Attack Theater honesty regressions."""

import json
from pathlib import Path

import pytest

import warden.scanner.scanner as scanner_module

ROOT = Path(__file__).resolve().parents[1]
THEATER_CASES = json.loads(
    (ROOT / "tests" / "fixtures" / "theater_attacks.json").read_text(encoding="utf-8")
)


def test_scanner_module_describes_the_layers_that_run_in_production():
    description = (scanner_module.__doc__ or "").lower()

    assert "deterministic" in description
    assert "regex" in description
    assert "heuristic" in description
    assert "tf-idf" in description
    assert "4-layer" not in description
    assert "haiku" not in description


def test_public_copy_separates_known_pattern_and_semantic_coverage():
    homepage = " ".join(
        (ROOT / "site" / "index.html").read_text(encoding="utf-8").lower().split()
    )
    theater = " ".join(
        (ROOT / "site" / "theater.html").read_text(encoding="utf-8").lower().split()
    )

    for page in (homepage, theater):
        assert "known patterns" in page
        assert "novel phrasing" in page
        assert "semantic" in page
    assert "classic prompt injections return sanitize" in theater


@pytest.mark.asyncio
async def test_theater_drain_case_blocks_without_expected_address_context(engine):
    attack = next(case for case in THEATER_CASES if case["id"] == "drain-address")

    verdict = await engine.scan(attack["request"]["payload"])

    assert verdict.verdict == "BLOCK"
    assert "DRAIN_ADDRESS" in {reason.value for reason in verdict.threat_classes}


@pytest.mark.asyncio
async def test_classic_theater_prompt_injection_sanitizes_instead_of_claiming_block(engine):
    attack = next(case for case in THEATER_CASES if case["id"] == "prompt-injection")

    verdict = await engine.scan(attack["request"]["payload"])

    assert verdict.verdict == "SANITIZE"
    assert verdict.sanitized_payload != attack["request"]["payload"]
    assert (await engine.scan(verdict.sanitized_payload)).verdict == "ALLOW"
