"""An owner signs `policy_sha256`, so the caller has to be able to reproduce it.

Reported by an external integrator (Argus #5246) whose first binding attempt
failed on his own side: his policy omitted `allowed_selectors` and used a
checksummed destination, so the digest he hashed from his request body was not
the digest the server computes, and his wallet signed a commitment to a policy
that does not exist. Registration correctly rejected the signature.

Nothing was wrong with the server. What was wrong is that the spec described
sorting and destination normalization without saying that *defaults are applied
before hashing* — and `allowed_selectors` is optional on the wire but always
present in the hashed object. These tests pin both halves of that: the
normalization behaviour, and the sentence in the spec that warns about it.
"""

from pathlib import Path

from warden.action_guard import policy_sha256
from warden.models import ActionPolicy

SPEC = (Path(__file__).resolve().parents[1] / "spec" / "ACTION-DECISION-SPEC.md").read_text(
    encoding="utf-8"
)

CHECKSUMMED = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
LOWERCASE = "0xabcdef0123456789abcdef0123456789abcdef01"


def _policy(**overrides: object) -> ActionPolicy:
    values: dict[str, object] = {
        "allowed_actions": ["transfer"],
        "allowed_tools": ["wallet.transfer"],
        "allowed_destinations": [CHECKSUMMED],
        "max_amount_atomic_by_asset": {"USDT": 100000},
    }
    return ActionPolicy(**{**values, **overrides})


def test_an_omitted_allowed_selectors_hashes_as_an_explicit_empty_list():
    """The exact shape that cost the integrator an attempt."""
    assert policy_sha256(_policy()) == policy_sha256(_policy(allowed_selectors=[]))


def test_a_checksummed_destination_hashes_as_its_lowercase_form():
    assert policy_sha256(_policy(allowed_destinations=[CHECKSUMMED])) == policy_sha256(
        _policy(allowed_destinations=[LOWERCASE])
    )


def test_both_traps_together_reproduce_the_reported_case():
    written_as_sent = _policy(allowed_destinations=[CHECKSUMMED])
    fully_normalized = _policy(allowed_destinations=[LOWERCASE], allowed_selectors=[])
    assert policy_sha256(written_as_sent) == policy_sha256(fully_normalized)


def test_a_real_selector_still_changes_the_digest():
    """Guard against the above passing for the wrong reason."""
    assert policy_sha256(_policy()) != policy_sha256(_policy(allowed_selectors=["0x095ea7b3"]))


def test_ordering_and_duplication_do_not_change_the_digest():
    spread = _policy(allowed_actions=["tool_call", "transfer", "transfer"])
    tidy = _policy(allowed_actions=["transfer", "tool_call"])
    assert policy_sha256(spread) == policy_sha256(tidy)


def test_the_spec_warns_that_defaults_are_applied_before_hashing():
    """Without this sentence the next integrator repeats the same failed attempt."""
    assert "Hash the canonical object, never your request body." in SPEC
    assert "defaults" in SPEC.lower()
    assert "allowed_selectors" in SPEC
    assert "Normalize\nfirst, then hash, then sign." in SPEC or "then hash, then sign" in SPEC
