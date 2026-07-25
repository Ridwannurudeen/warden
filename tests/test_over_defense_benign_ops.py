"""Over-defence regression gate for the first-party benign operations corpus.

Recall says how much Warden catches. This module says how much ordinary text it wrongly
flags, which is the other half of the same claim and the half the published benchmark
cannot support: 45 benign held-out rows with zero observed false positives are consistent
with a true rate as high as 6.4% (one-sided Wilson 95%).

Two kinds of test live here:

* Passing gates pin what is true today — the corpus schema, its disjointness from every
  shipped dataset, and a ceiling on the measured false-positive count so the number can
  only move down.
* `xfail(strict=True)` gates pin the over-defence that is real right now. Each one names
  the exact file and line that has to change, and each one turns into a hard CI failure
  the moment that fix lands, so nobody has to remember to delete it.
"""

from pathlib import Path

import pytest

from scripts.measure_benign_fp import load_jsonl, measure, wilson_upper_bound

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus" / "benign_ops_v1.jsonl"
HELD_OUT_BENIGN = ROOT / "benchmark" / "held_out_benign.jsonl"

ROWS = {row["id"]: row for row in load_jsonl(CORPUS)}

# Measured on 2026-07-25 against this corpus with `python scripts/measure_benign_fp.py`.
# These are ceilings, not targets: a change may lower them, never raise them.
MEASURED_FALSE_POSITIVES = {"fast": 17, "thorough": 26}

EXPECTED_FIELDS = {"id", "category", "payload", "expected_verdict", "expected_classes", "note"}


def payload(row_id: str) -> str:
    return ROWS[row_id]["payload"]


def held_out_payload(row_id: str) -> str:
    for row in load_jsonl(HELD_OUT_BENIGN):
        if row["id"] == row_id:
            return row["payload"]
    raise AssertionError(f"{row_id} is not in {HELD_OUT_BENIGN.name}")


# ── The corpus itself ───────────────────────────────────────────────────────


def test_corpus_is_large_enough_to_support_a_sub_one_percent_claim():
    rows = load_jsonl(CORPUS)
    assert len(rows) >= 300, "a <1% false-positive claim needs ~300 benign rows"
    assert wilson_upper_bound(0, len(rows)) < 0.01


def test_corpus_schema_matches_the_training_benign_schema():
    for row in load_jsonl(CORPUS):
        assert set(row) == EXPECTED_FIELDS, row.get("id")
        assert row["id"].startswith("benign-ops-"), row["id"]
        assert row["payload"].strip(), row["id"]
        assert row["expected_verdict"] == "ALLOW", row["id"]
        assert row["expected_classes"] == [], row["id"]
        assert row["note"].strip(), row["id"]

    ids = [row["id"] for row in load_jsonl(CORPUS)]
    assert len(ids) == len(set(ids))


def test_corpus_is_disjoint_from_every_shipped_dataset():
    mine = {row["payload"] for row in load_jsonl(CORPUS)}
    for name in (
        ROOT / "corpus" / "attacks.jsonl",
        ROOT / "corpus" / "benign.jsonl",
        ROOT / "benchmark" / "held_out_attacks.jsonl",
        ROOT / "benchmark" / "held_out_benign.jsonl",
    ):
        overlap = mine & {row["payload"] for row in load_jsonl(name)}
        assert not overlap, (name.name, sorted(overlap)[:3])


def test_hard_negative_classes_are_actually_present():
    categories = [row["category"] for row in load_jsonl(CORPUS)]
    assert categories.count("hard_negative_secdoc") >= 40
    assert categories.count("hard_negative_trigger") >= 45
    assert len(set(categories)) >= 10


def test_wilson_bound_reproduces_the_published_small_sample_arithmetic():
    # 45 benign rows with zero observed failures is what benchmark/README.md rests on.
    # Wilson puts the one-sided 95% bound at 5.67%; the exact Clopper-Pearson bound on the
    # same data is 6.44%. Either way, "0 false positives" at n=45 permits roughly 1 in 17.
    assert wilson_upper_bound(0, 45) == pytest.approx(0.0567, abs=5e-4)
    # At this corpus size a clean sweep would finally license a sub-1% claim.
    assert wilson_upper_bound(0, len(ROWS)) < 0.01


# ── What the engine does today ──────────────────────────────────────────────


async def test_measured_false_positive_count_does_not_regress():
    report = await measure(load_jsonl(CORPUS))
    for depth, ceiling in MEASURED_FALSE_POSITIVES.items():
        observed = report["depths"][depth]["false_positives"]
        assert observed <= ceiling, (
            depth,
            observed,
            [row["id"] for row in report["depths"][depth]["rows"]],
        )


async def test_security_documentation_is_not_flagged(engine):
    """Prose that discusses injection, drains, and exfiltration stays clean today."""
    rows = [row for row in load_jsonl(CORPUS) if row["category"] == "hard_negative_secdoc"]
    flagged = []
    for row in rows:
        for depth in ("fast", "thorough"):
            verdict = await engine.scan(row["payload"], depth=depth)
            if verdict.verdict != "ALLOW":
                flagged.append((row["id"], depth, verdict.verdict))
    assert not flagged


# ── Over-defence: each xfail names the file:line that must change ───────────


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:16 matches 'forget everything you know' with no "
        "requirement that the object be instructions, rules, or context, so ordinary "
        "business English is scored PROMPT_INJECTION at confidence 0.95"
    ),
)
@pytest.mark.parametrize("row_id", ["benign-ops-trigger-001", "benign-ops-trigger-002"])
@pytest.mark.parametrize("depth", ["fast", "thorough"])
async def test_forget_everything_about_a_business_topic_is_allowed(engine, row_id, depth):
    verdict = await engine.scan(payload(row_id), depth=depth)
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:11-15 matches 'ignore the previous instructions' even "
        "when the instructions are a retired onboarding document rather than the model's"
    ),
)
async def test_ignoring_a_stale_onboarding_document_is_allowed(engine):
    verdict = await engine.scan(payload("benign-ops-trigger-005"), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:17-18 matches 'set aside what you were told' with no "
        "instruction-override object"
    ),
)
async def test_set_aside_what_you_were_told_at_onboarding_is_allowed(engine):
    verdict = await engine.scan(payload("benign-ops-trigger-020"), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:27 is the bare prefix r'act\\s+as\\s+(?:if\\s+)?"
        "(?:you\\s+are\\s+)?' with nothing after it, so it matches the literal words "
        "'Act as ' in any sentence"
    ),
)
@pytest.mark.parametrize("row_id", ["benign-ops-trigger-013", "benign-ops-trigger-038"])
async def test_act_as_in_ordinary_delegation_is_allowed(engine, row_id):
    verdict = await engine.scan(payload(row_id), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:29 matches 'your new role is' in a job handover, "
        "because the pattern has no notion of who the addressee is"
    ),
)
async def test_handing_a_colleague_a_new_role_is_allowed(engine):
    verdict = await engine.scan(payload("benign-ops-trigger-015"), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:37-38 matches 'move all funds' in a treasury note that "
        "names a bank account rather than a chain address"
    ),
)
async def test_treasury_note_about_moving_funds_is_allowed(engine):
    verdict = await engine.scan(payload("benign-ops-trigger-029"), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/analyzers/exfiltration.py:53 matches 'reveal the system prompt' anywhere, "
        "including a support-FAQ sentence that quotes the request in order to refuse it; "
        "warden/scanner/patterns.py:20 fires on the same words"
    ),
)
async def test_support_faq_quoting_a_request_phrase_is_allowed(engine):
    verdict = await engine.scan(payload("benign-ops-trigger-026"), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/analyzers/tool_hijack.py:150-157 treats any JSON carrying a 'method' or "
        "'params' key (TOOL_KEYS, tool_hijack.py:10-18) as tool-shaped, and the read-only "
        "escape at tool_hijack.py:318-328 allowlists exactly two hard-coded shapes, so "
        "every other JSON-RPC request BLOCKs via warden/core/verdict.py:228-247"
    ),
)
@pytest.mark.parametrize(
    "row_id",
    [
        "benign-ops-rpc-002",
        "benign-ops-rpc-007",
        "benign-ops-rpc-010",
        "benign-ops-rpc-014",
        "benign-ops-rpc-018",
        "benign-ops-rpc-026",
    ],
)
async def test_ordinary_json_rpc_requests_are_allowed(engine, row_id):
    verdict = await engine.scan(payload(row_id), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/analyzers/drain_address.py:152-158 scores any address within 80 characters "
        "of transfer wording at 0.80 when no expected_addresses context is supplied, so a "
        "past-tense explorer row and decoded calldata are both read as redirection"
    ),
)
@pytest.mark.parametrize("row_id", ["benign-ops-call-024", "benign-ops-exp-002"])
async def test_reporting_a_transfer_that_already_happened_is_allowed(engine, row_id):
    verdict = await engine.scan(payload(row_id), depth="fast")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "warden/scanner/patterns.py:229 sets SIMILARITY_THRESHOLD = 0.52 on the claim at "
        "patterns.py:224-228 that benign text peaks at 0.506. On this corpus benign text "
        "reaches 0.7544, so Layer 3 fires on ordinary sentences that merely share "
        "vocabulary with a KNOWN_INJECTIONS row"
    ),
)
@pytest.mark.parametrize(
    "row_id",
    [
        "benign-ops-code-001",
        "benign-ops-code-002",
        "benign-ops-call-029",
        "benign-ops-trigger-043",
        "benign-ops-trigger-045",
        "benign-ops-trigger-046",
        "benign-ops-trigger-047",
        "benign-ops-trigger-048",
        "benign-ops-trigger-050",
    ],
)
async def test_thorough_depth_does_not_flag_vocabulary_overlap(engine, row_id):
    verdict = await engine.scan(payload(row_id), depth="thorough")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the published held-out benign row itself fails at thorough depth: "
        "warden/scanner/patterns.py:203 puts 'base64 decode: <blob>' in KNOWN_INJECTIONS, "
        "and at the patterns.py:229 threshold a developer's b64decode call scores 0.6477 "
        "against it. benchmark/README.md reports 0.00% false positives because "
        "scripts/benchmark_recall.py runs benign rows at fast depth only"
    ),
)
async def test_published_held_out_benign_row_survives_thorough_depth(engine):
    verdict = await engine.scan(held_out_payload("held-benign-enc-016"), depth="thorough")
    assert verdict.verdict == "ALLOW", verdict.detections


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the goal state. Fixing patterns.py:16/27/29/37, patterns.py:229, "
        "warden/analyzers/tool_hijack.py:318-328, warden/analyzers/drain_address.py:152-158 "
        "and warden/analyzers/exfiltration.py:53 is what gets this under 1%"
    ),
)
async def test_false_positive_rate_is_under_one_percent_at_both_depths():
    report = await measure(load_jsonl(CORPUS))
    for depth in ("fast", "thorough"):
        assert report["depths"][depth]["rate"] < 0.01, (
            depth,
            report["depths"][depth]["false_positives"],
        )
