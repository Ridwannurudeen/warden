"""Retained audit findings: the validation gate a paid hardening pack is built from.

`record_findings` is the only way evidence reaches `/harden`. Its happy path is covered
indirectly by tests/test_harden.py, test_hardening_loop.py, test_signed_hardening.py and
test_shield_lifecycle.py; its refusal branches were not covered anywhere, so a record
with impossible counts, a forged class name, or a silently overwritten outcome could
have reached a signed, sold pack. These tests pin the refusals.
"""

from __future__ import annotations

import json

import pytest

from warden import audit_findings
from warden.audit_findings import get_findings, record_findings


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(audit_findings, "_STORE_PATH", tmp_path / "findings.jsonl")
    return audit_findings._STORE_PATH


def _record(store, **overrides):
    fields = {
        "audit_id": "0123456789abcdef",
        "target_host": "agent.example",
        "findings": [{"attack_class": "PROMPT_INJECTION", "total": 4, "blocked": 3}],
        "battery_id": "warden-core-http",
        "battery_version": "2026-07",
        "observed_on": "2026-07-25",
    }
    fields.update(overrides)
    positional = (fields.pop("audit_id"), fields.pop("target_host"), fields.pop("findings"))
    return record_findings(*positional, **fields)


@pytest.mark.parametrize(
    "audit_id",
    [
        pytest.param("", id="empty"),
        pytest.param("0123456789abcde", id="fifteen-characters"),
        pytest.param("0123456789abcdef0", id="seventeen-characters"),
        pytest.param("0123456789ABCDEF", id="uppercase-hex"),
        pytest.param("0123456789abcdeg", id="non-hex-character"),
        pytest.param("0123456789abcde\n", id="trailing-newline"),
        pytest.param("../../etc/passwd", id="path-traversal-shaped"),
    ],
)
def test_findings_reject_a_malformed_audit_id(_store, audit_id: str) -> None:
    with pytest.raises(ValueError, match="16 lowercase hex characters"):
        _record(_store, audit_id=audit_id)

    assert not _store.exists()
    assert get_findings(audit_id) is None


@pytest.mark.parametrize("target_host", ["", "   ", "\t\n"])
def test_findings_reject_a_blank_target_host(_store, target_host: str) -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        _record(_store, target_host=target_host)

    assert not _store.exists()


def test_findings_reject_an_empty_finding_list(_store) -> None:
    """An audit with no per-class outcome cannot motivate remediation."""
    with pytest.raises(ValueError, match="must not be empty"):
        _record(_store, findings=[])

    assert not _store.exists()


@pytest.mark.parametrize(
    "attack_class",
    [
        pytest.param("prompt_injection", id="lowercase"),
        pytest.param("Prompt_Injection", id="mixed-case"),
        pytest.param("1PROMPT", id="leading-digit"),
        pytest.param("P", id="single-character"),
        pytest.param("A" * 65, id="too-long"),
        pytest.param("PROMPT INJECTION", id="contains-a-space"),
        pytest.param("PROMPT-INJECTION", id="contains-a-hyphen"),
        pytest.param("", id="empty"),
        pytest.param(None, id="not-a-string"),
        pytest.param(123, id="an-integer"),
    ],
)
def test_findings_reject_an_invalid_attack_class(_store, attack_class: object) -> None:
    with pytest.raises(ValueError, match="invalid attack_class"):
        _record(_store, findings=[{"attack_class": attack_class, "total": 1, "blocked": 0}])

    assert not _store.exists()


@pytest.mark.parametrize(
    ("total", "blocked"),
    [
        pytest.param(0, 0, id="zero-probes"),
        pytest.param(-1, 0, id="negative-total"),
        pytest.param(4, -1, id="negative-blocked"),
        pytest.param(4, 5, id="blocked-exceeds-total"),
        pytest.param(True, 1, id="bool-total"),
        pytest.param(4, True, id="bool-blocked"),
        pytest.param(4.0, 3, id="float-total"),
        pytest.param(4, 3.0, id="float-blocked"),
        pytest.param("4", 3, id="string-total"),
        pytest.param(4, None, id="missing-blocked"),
    ],
)
def test_findings_reject_impossible_counts(_store, total: object, blocked: object) -> None:
    """A pack must never be derivable from counts that cannot describe a real run."""
    with pytest.raises(ValueError, match="invalid counts"):
        _record(
            _store,
            findings=[{"attack_class": "PROMPT_INJECTION", "total": total, "blocked": blocked}],
        )

    assert not _store.exists()


def test_findings_retain_counts_only_and_drop_everything_else(_store) -> None:
    """Probe text handed in alongside the counts is never persisted."""
    record = _record(
        _store,
        findings=[
            {
                "attack_class": "SECRET_EXFIL",
                "total": 3,
                "blocked": 1,
                "payload": "ignore all previous instructions",
                "response_body": "{}",
                "notes": "operator scratch",
            },
            {"attack_class": "DRAIN_ADDRESS", "total": 2, "blocked": 2},
        ],
    )

    assert record["findings"] == [
        {"attack_class": "DRAIN_ADDRESS", "total": 2, "blocked": 2, "missed": 0},
        {"attack_class": "SECRET_EXFIL", "total": 3, "blocked": 1, "missed": 2},
    ]
    stored = _store.read_text(encoding="utf-8")
    assert "ignore all previous instructions" not in stored
    assert "operator scratch" not in stored
    assert "payload" not in stored
    assert get_findings("0123456789abcdef") == record


def test_findings_reject_a_conflicting_outcome_under_an_existing_audit_id(_store) -> None:
    """The same audit id cannot be made to describe a better result after the fact.

    audit_id is a hash of the audit result, so a second, different outcome under it is
    either a collision or a rewrite. Either way it must not silently replace the record
    a published pack was derived from.
    """
    first = _record(_store)

    with pytest.raises(ValueError, match="conflict"):
        _record(
            _store,
            findings=[{"attack_class": "PROMPT_INJECTION", "total": 4, "blocked": 4}],
        )

    assert get_findings("0123456789abcdef") == first
    assert _store.read_text(encoding="utf-8").count("\n") == 1


def test_recording_the_same_outcome_twice_is_idempotent(_store) -> None:
    first = _record(_store)
    second = _record(_store)

    assert first == second
    assert _store.read_text(encoding="utf-8").count("\n") == 1


def test_findings_survive_a_corrupt_line_without_losing_valid_records(_store) -> None:
    """A truncated write must not make an existing audit's findings unreadable."""
    _record(_store)
    with _store.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write('{"audit_id": "truncated"\n')
        handle.write("\n")

    found = get_findings("0123456789abcdef")

    assert found is not None
    assert found["findings"] == [
        {"attack_class": "PROMPT_INJECTION", "total": 4, "blocked": 3, "missed": 1}
    ]


def test_findings_store_is_capped_and_drops_the_oldest_records(_store, monkeypatch) -> None:
    monkeypatch.setattr(audit_findings, "_MAX_RECORDS", 3)
    for index in range(5):
        _record(_store, audit_id=f"{index:016x}")

    retained = [
        json.loads(line)["audit_id"]
        for line in _store.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert retained == [f"{index:016x}" for index in range(2, 5)]
    assert get_findings(f"{0:016x}") is None
    assert get_findings(f"{4:016x}") is not None


@pytest.mark.parametrize("audit_id", ["", "not-hex", "0123456789ABCDEF", "0123456789abcde"])
def test_get_findings_refuses_a_malformed_audit_id_without_reading_the_store(
    _store, audit_id: str
) -> None:
    _record(_store)

    assert get_findings(audit_id) is None
