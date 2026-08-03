"""The offline trainer has to stay runnable, and it has to label frames honestly.

`scripts/train_learned_scorer.py` had silently stopped working: it unpacks the
transform table from `warden.adversarial_variants`, and when the Gauntlet upgrade
widened that table from `(chain, callable)` to `(family, chain, callable)` the
script began raising `ValueError: too many values to unpack`. Nothing caught it
because the trainer is offline and no test ran it, so the shipped model could no
longer be reproduced or audited at all.

These tests do not train anything — that needs scikit-learn, which is
deliberately not a runtime dependency. They pin the two contracts between the
trainer and the runtime that broke, and the labelling rule that a naive repair
would have got wrong.
"""

import ast
from pathlib import Path

from warden.adversarial_variants import CONTAINING_FAMILIES, _transforms

ROOT = Path(__file__).resolve().parents[1]
TRAINER = ROOT / "scripts" / "train_learned_scorer.py"
SOURCE = TRAINER.read_text(encoding="utf-8")


def test_the_trainer_parses():
    ast.parse(SOURCE)


def test_every_transform_row_is_a_family_chain_callable_triple():
    """The shape the trainer unpacks. Widening it again must fail here first."""
    rows = _transforms()
    assert rows
    for row in rows:
        assert len(row) == 3, row
        family, chain, transform = row
        assert isinstance(family, str)
        assert isinstance(chain, tuple)
        assert callable(transform)


def test_the_trainer_unpacks_transforms_with_the_current_arity():
    """The exact regression: a two-name unpack over a three-tuple."""
    unpacks = [
        node
        for node in ast.walk(ast.parse(SOURCE))
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and node.iter.func.id == "_transforms"
    ]
    assert unpacks, "the trainer no longer iterates _transforms(); update this test"
    for node in unpacks:
        assert isinstance(node.target, ast.Tuple)
        assert len(node.target.elts) == 3, "unpack must match the (family, chain, transform) triple"


def test_containing_frames_are_never_applied_to_benign_training_rows():
    """A containing frame IS the attack, whatever text it wraps.

    `semantic:nullification` turns any payload into "disregard the previous
    instruction ... <payload>". Applying that to a benign row and filing it under
    label 0 would teach the model that the commonest evasion shape is benign, so
    the benign loop must skip containing families.
    """
    assert "CONTAINING_FAMILIES" in SOURCE
    assert "if family in CONTAINING_FAMILIES:" in SOURCE
    # And the runtime still marks semantic frames as containing.
    assert "semantic" in CONTAINING_FAMILIES


def test_the_camouflage_frame_is_excluded_from_training_positives():
    """benign-preamble adds camouflage, not attack signal.

    It prepends ordinary ticket-desk wording to an attack. Labelling that 1
    teaches a bag-of-features model that ordinary business vocabulary is evidence
    of an attack: measured over corpus + held-out it moved the benign median from
    0.363 to 0.494 and cost 0.03 ROC-AUC, while grouped-CV PR-AUC still rose.
    It stays in the shipped variant packs, because it is a real evasion worth
    auditing against — it is only excluded from the fit.
    """
    assert 'EXCLUDED_TRAINING_CHAINS = frozenset({"semantic:benign-preamble"})' in SOURCE
    assert "EXCLUDED_TRAINING_CHAINS.intersection" in SOURCE
    chains = {name for _family, chain, _fn in _transforms() for name in chain}
    assert "semantic:benign-preamble" in chains, "the excluded chain must still exist upstream"


def test_held_out_absence_is_still_asserted_rather_than_trusted():
    assert "def assert_held_out_is_absent" in SOURCE
    assert "assert_held_out_is_absent(rows)" in SOURCE


def test_the_over_defence_measurement_set_is_never_training_data():
    """benign_ops_v1 measures over-defence; training on it would void that claim."""
    assert "benign_ops_v1" not in SOURCE
