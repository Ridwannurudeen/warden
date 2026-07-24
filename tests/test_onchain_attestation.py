"""Offline ERC-8004 feedback transactions for signed Warden audits."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account
from web3 import Web3

from warden import audit_attestations, onchain_attestation
from warden.badges import b64u_encode

ATTESTATION_URI = "https://warden.gudman.xyz/apa/audit/0123456789abcdef"
BLOCKED_BY_GRADE = {
    "A": 20,
    "B": 17,
    "C": 15,
    "D": 13,
    "F": 11,
}


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))


def _record(grade: str = "A") -> dict[str, object]:
    return audit_attestations.issue_audit_attestation(
        audit_id="0123456789abcdef",
        subject="https://agent.example/scan?mode=strict",
        endpoint_host="agent.example",
        battery_id="warden-core-http",
        battery_version="2026-07",
        battery_sha256="a" * 64,
        blocked=BLOCKED_BY_GRADE[grade],
        total=20,
        benign_total=3,
        benign_passed=3,
        observed_on="2026-07-24",
        issued_at=1_785_000_000,
        log_seq=1,
    )


def _build(
    record: dict[str, object],
    *,
    sender: str,
    target_agent_id: int = 42,
    attestation_uri: str = ATTESTATION_URI,
    nonce: int = 7,
    gas: int = 250_000,
    max_fee_per_gas: int = 1_000_000_000,
    max_priority_fee_per_gas: int = 0,
) -> dict[str, object]:
    return onchain_attestation.build_feedback_transaction(
        record,
        target_agent_id=target_agent_id,
        sender=sender,
        attestation_uri=attestation_uri,
        nonce=nonce,
        gas=gas,
        max_fee_per_gas=max_fee_per_gas,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
    )


@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_grade_mapping_is_injective_and_calldata_preserves_sha256_pointer(
    grade: str,
) -> None:
    record = _record(grade)
    transaction = _build(record, sender=Account.create().address)
    contract = Web3().eth.contract(
        address=onchain_attestation.REPUTATION_REGISTRY,
        abi=onchain_attestation.REPUTATION_ABI,
    )
    function, arguments = contract.decode_function_input(str(transaction["data"]))
    record_hash = audit_attestations.record_sha256(record)

    assert function.fn_name == "giveFeedback"
    assert arguments == {
        "agentId": 42,
        "value": onchain_attestation.GRADE_TO_VALUE[grade],
        "valueDecimals": 0,
        "tag1": "security-audit",
        "tag2": f"sha256:{record_hash}",
        "endpoint": record["subject"],
        "feedbackURI": ATTESTATION_URI,
        "feedbackHash": b"\x00" * 32,
    }
    assert transaction["chainId"] == 196
    assert transaction["to"] == onchain_attestation.REPUTATION_REGISTRY
    assert transaction["value"] == 0


def test_grade_mapping_is_lossless_and_documented() -> None:
    assert onchain_attestation.GRADE_TO_VALUE == {
        "A": 5,
        "B": 4,
        "C": 3,
        "D": 2,
        "F": 1,
    }
    assert len(set(onchain_attestation.GRADE_TO_VALUE.values())) == 5


def test_new_feedback_abi_matches_the_official_event_shape() -> None:
    event = next(
        item
        for item in onchain_attestation.REPUTATION_ABI
        if item["type"] == "event" and item["name"] == "NewFeedback"
    )

    assert [(item["name"], item["type"], item["indexed"]) for item in event["inputs"]] == [
        ("agentId", "uint256", True),
        ("clientAddress", "address", True),
        ("feedbackIndex", "uint64", False),
        ("value", "int128", False),
        ("valueDecimals", "uint8", False),
        ("indexedTag1", "string", True),
        ("tag1", "string", False),
        ("tag2", "string", False),
        ("endpoint", "string", False),
        ("feedbackURI", "string", False),
        ("feedbackHash", "bytes32", False),
    ]


def test_feedback_transaction_signing_is_offline() -> None:
    signer = Account.create("warden-feedback-local-test")
    transaction = _build(_record(), sender=signer.address)

    raw_transaction = onchain_attestation.sign_feedback_transaction(transaction, signer)

    assert Account.recover_transaction(raw_transaction) == signer.address


def test_feedback_builder_requires_consented_conclusive_signed_evidence() -> None:
    signer = Account.create()
    unconsented = _record()
    unconsented["consent_verified"] = False
    inconclusive = _record()
    inconclusive["conclusive"] = 19
    inconclusive["inconclusive"] = 1
    unsigned = _record()
    unsigned.pop("issuer_sig")

    with pytest.raises(ValueError, match="consented"):
        _build(unconsented, sender=signer.address)
    with pytest.raises(ValueError, match="conclusive"):
        _build(inconclusive, sender=signer.address)
    with pytest.raises(ValueError, match="signed"):
        _build(unsigned, sender=signer.address)


def test_feedback_builder_refuses_warden_self_attestation() -> None:
    with pytest.raises(ValueError, match="itself"):
        _build(
            _record(),
            sender=Account.create().address,
            target_agent_id=onchain_attestation.WARDEN_AGENT_ID,
        )


@pytest.mark.parametrize(
    "uri",
    [
        "http://warden.gudman.xyz/apa/audit/0123456789abcdef",
        "https://user@warden.gudman.xyz/apa/audit/0123456789abcdef",
        "https://warden.gudman.xyz/apa/audit/ffffffffffffffff",
        "https://warden.gudman.xyz/apa/audit/0123456789abcdef?view=raw",
        "https://warden.gudman.xyz/apa/audit/0123456789abcdef#fragment",
    ],
)
def test_feedback_builder_rejects_invalid_attestation_uri(uri: str) -> None:
    with pytest.raises(ValueError, match="attestation_uri"):
        _build(_record(), sender=Account.create().address, attestation_uri=uri)


def test_feedback_builder_validates_addresses_and_transaction_fields() -> None:
    record = _record()

    with pytest.raises(ValueError, match="sender"):
        _build(record, sender="not-an-address")
    with pytest.raises(ValueError, match="target_agent_id"):
        _build(record, sender=Account.create().address, target_agent_id=-1)
    with pytest.raises(ValueError, match="nonce"):
        _build(record, sender=Account.create().address, nonce=-1)
    with pytest.raises(ValueError, match="gas"):
        _build(record, sender=Account.create().address, gas=0)
    with pytest.raises(ValueError, match="max_priority_fee_per_gas"):
        _build(
            record,
            sender=Account.create().address,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=2,
        )


def test_feedback_signer_rejects_wrong_signer_and_non_feedback_calldata() -> None:
    signer = Account.create("warden-feedback-correct-signer")
    transaction = _build(_record(), sender=signer.address)

    with pytest.raises(ValueError, match="does not match signer"):
        onchain_attestation.sign_feedback_transaction(transaction, Account.create())

    wrong_call = dict(transaction)
    wrong_call["data"] = "0x00000000"
    with pytest.raises(ValueError, match="calldata"):
        onchain_attestation.sign_feedback_transaction(wrong_call, signer)
