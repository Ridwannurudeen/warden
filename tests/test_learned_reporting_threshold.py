"""The advisory scorer must publish a probability only when it means something.

`WARDEN_LEARNED_EVIDENCE_THRESHOLD` was documented as "Advisory reporting
threshold (default 0.5)" but was parsed, stored, exposed as a property and then
never read: every scan published a probability regardless. Measured over every
row this repo ships (188 attacks, 453 benign) the model reaches AUC 0.8105, and
at 0.5 some 135 of the 453 benign rows (29.8%) cleared the bar — so roughly a
third of ordinary business text carried a number a reader could mistake for a
finding. At 0.90 that falls to 6 rows (1.3%).

The threshold governs REPORTING only. Enforcement reads the raw score, and the
test below pins that, because tying the two together would mean raising the
reporting bar silently weakened enforcement.
"""

from warden.core.verdict import VerdictEngine
from warden.scanner.learned import (
    DEFAULT_EVIDENCE_THRESHOLD,
    LearnedScorer,
    build_learned_scorer_from_env,
    features,
)


def _scorer(**kwargs) -> LearnedScorer:
    """A scorer whose probability is driven by the bias alone, so it is exact."""
    return LearnedScorer(
        weights=[0.0] * features.FEATURE_DIMENSION,
        bias=kwargs.pop("bias"),
        model_digest="0" * 64,
        **kwargs,
    )


def _evaluate(scorer: LearnedScorer) -> dict:
    return scorer.evaluate(
        "any content",
        regex_hits=[],
        heuristic={"score": 0.0, "flagged": False, "detail": "", "subscores": {}},
        similarity={"flagged": False, "similarity": 0.0, "closest_match": ""},
    )


def test_the_shipped_default_is_the_measured_operating_point_not_the_midpoint():
    assert DEFAULT_EVIDENCE_THRESHOLD == 0.9


def test_a_threshold_of_zero_is_honoured_rather_than_folded_into_the_default():
    """`x or DEFAULT` silently swallowed 0.0, because zero is falsy.

    0.0 means "publish everything", which is exactly what an operator debugging
    the scorer reaches for — and they would have got 0.9 instead, with no
    indication the setting had been ignored.
    """
    scorer = build_learned_scorer_from_env(
        {"WARDEN_LEARNED_SCORER_ENABLED": "1", "WARDEN_LEARNED_EVIDENCE_THRESHOLD": "0.0"}
    )
    assert scorer is not None
    assert scorer.evidence_threshold == 0.0


def test_an_unset_or_unusable_threshold_still_falls_back_to_the_default():
    for value in ("", "bogus", "1.5", "-0.2"):
        env = {"WARDEN_LEARNED_SCORER_ENABLED": "1"}
        if value:
            env["WARDEN_LEARNED_EVIDENCE_THRESHOLD"] = value
        scorer = build_learned_scorer_from_env(env)
        assert scorer is not None
        assert scorer.evidence_threshold == DEFAULT_EVIDENCE_THRESHOLD, value


def test_a_score_over_the_threshold_is_published():
    block = _evaluate(_scorer(bias=5.0, evidence_threshold=0.9))  # sigmoid(5) ~ 0.993
    assert block["attack_probability"] is not None
    assert block["attack_probability"] >= 0.9


def test_a_score_under_the_threshold_is_withheld_but_the_scan_is_still_marked_scored():
    block = _evaluate(_scorer(bias=0.0, evidence_threshold=0.9))  # sigmoid(0) = 0.5
    assert block["attack_probability"] is None
    assert block["scored"] is True
    assert block["evidence_threshold"] == 0.9


def test_a_withheld_score_reads_as_scored_not_as_an_absent_model():
    """The distinction the old bare-null field could not express."""
    verdict = VerdictEngine().decide(
        "any content",
        {
            "clean": True,
            "risk_level": "NONE",
            "layers_triggered": [],
            "detections": [],
            "sanitized_content": "any content",
            "recommendation": "",
            "semantic_consulted": False,
            "learned": _evaluate(_scorer(bias=0.0, evidence_threshold=0.9)),
        },
        [],
    )
    assert verdict.attack_probability is None
    assert (
        verdict.checks["learned_scorer"] == "advisory - scored below the 0.90 reporting threshold"
    )


def test_no_scorer_at_all_says_nothing_here_rather_than_claiming_a_low_score():
    verdict = VerdictEngine().decide(
        "any content",
        {
            "clean": True,
            "risk_level": "NONE",
            "layers_triggered": [],
            "detections": [],
            "sanitized_content": "any content",
            "recommendation": "",
            "semantic_consulted": False,
            "learned": None,
        },
        [],
    )
    # The engine layer owns the "not loaded" wording; the verdict engine must not
    # invent a reporting-threshold message when nothing scored.
    assert "learned_scorer" not in verdict.checks


def test_raising_the_reporting_bar_does_not_weaken_enforcement():
    """The invariant: reporting and enforcement read the threshold separately."""
    block = _evaluate(
        _scorer(bias=1.0, evidence_threshold=0.99, enforce_threshold=0.5)  # sigmoid(1) ~ 0.731
    )
    assert block["attack_probability"] is None, "0.73 is below the 0.99 reporting bar"
    assert block["enforced_verdict"] == "SANITIZE", "but it still clears the 0.5 enforcement bar"


def test_a_published_score_still_carries_its_enforcement_request():
    block = _evaluate(_scorer(bias=5.0, evidence_threshold=0.9, enforce_threshold=0.5))
    assert block["attack_probability"] is not None
    assert block["enforced_verdict"] == "SANITIZE"
