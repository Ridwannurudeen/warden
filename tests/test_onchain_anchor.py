"""Offline X Layer anchoring for signed APA transparency checkpoints."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account
from web3 import Web3

from warden import anchor_history, onchain_anchor, protection
from warden.badges import _canonical_json, b64u_encode

ANCHOR_ADDRESS = "0x1111111111111111111111111111111111111111"


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch):
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(seed, "ed25519-seed"))


def _entries(count: int = 3) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    previous_hash = anchor_history.GENESIS_HISTORY_HASH
    for sequence in range(1, count + 1):
        entry = {
            "seq": sequence,
            "ts": 1_784_000_000 + sequence,
            "event": "issued",
            "attestation_id": f"attestation-{sequence}",
            "endpoint_host": "agent.example",
            "status": "active",
            "record_hash": f"{sequence:064x}",
            "prev_hash": previous_hash,
        }
        entries.append(entry)
        previous_hash = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
    return entries


def _checkpoint(
    entries: list[dict[str, object]],
    sequence: int,
) -> dict[str, object]:
    return protection.issue_log_checkpoint(
        sequence,
        anchor_history.log_prefix_hashes(entries)[sequence],
        issued_at=1_784_000_100 + sequence,
    )


def _event(
    anchor_index: int,
    sequence: int,
    root: str,
) -> dict[str, object]:
    return {
        "args": {
            "anchorIndex": anchor_index,
            "seq": sequence,
            "root": bytes.fromhex(root),
        }
    }


def test_log_prefix_hashes_is_public_and_matches_checkpoint_roots() -> None:
    entries = _entries()
    prefix_hashes = anchor_history.log_prefix_hashes(entries)

    assert prefix_hashes[0] == "0" * 64
    assert len(prefix_hashes) == len(entries) + 1
    for sequence, entry in enumerate(entries, start=1):
        assert (
            prefix_hashes[sequence]
            == hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
        )


def test_anchor_transaction_build_and_sign_are_offline_and_decode_exactly() -> None:
    entries = _entries()
    checkpoint = _checkpoint(entries, 3)
    signer = Account.create("warden-anchor-local-test")

    transaction = onchain_anchor.build_anchor_transaction(
        checkpoint,
        contract_address=ANCHOR_ADDRESS,
        sender=signer.address,
        nonce=7,
        gas=90_000,
        max_fee_per_gas=1_000_000_000,
        max_priority_fee_per_gas=0,
    )
    signed = onchain_anchor.sign_anchor_transaction(transaction, signer)
    contract = Web3().eth.contract(address=ANCHOR_ADDRESS, abi=onchain_anchor.ANCHOR_ABI)
    function, arguments = contract.decode_function_input(str(transaction["data"]))

    assert function.fn_name == "anchor"
    assert arguments == {
        "root": bytes.fromhex(str(checkpoint["head_hash"])),
        "seq": 3,
    }
    assert transaction["chainId"] == 196
    assert transaction["to"] == Web3.to_checksum_address(ANCHOR_ADDRESS)
    assert transaction["nonce"] == 7
    assert transaction["value"] == 0
    assert Account.recover_transaction(signed) == signer.address


def test_anchor_transaction_rejects_invalid_or_empty_checkpoints() -> None:
    entries = _entries()
    tampered = _checkpoint(entries, 2)
    tampered["head_hash"] = "f" * 64
    empty = protection.issue_log_checkpoint(
        0,
        anchor_history.GENESIS_HISTORY_HASH,
        issued_at=1_784_000_000,
    )

    with pytest.raises(ValueError, match="signed APA checkpoint"):
        onchain_anchor.build_anchor_transaction(
            tampered,
            contract_address=ANCHOR_ADDRESS,
            sender=Account.create().address,
            nonce=0,
            gas=90_000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=0,
        )
    with pytest.raises(ValueError, match="non-empty"):
        onchain_anchor.build_anchor_transaction(
            empty,
            contract_address=ANCHOR_ADDRESS,
            sender=Account.create().address,
            nonce=0,
            gas=90_000,
            max_fee_per_gas=1,
            max_priority_fee_per_gas=0,
        )


def test_anchor_signer_rejects_wrong_signer_and_non_anchor_calldata() -> None:
    entries = _entries(1)
    signer = Account.create("warden-anchor-correct-signer")
    transaction = onchain_anchor.build_anchor_transaction(
        _checkpoint(entries, 1),
        contract_address=ANCHOR_ADDRESS,
        sender=signer.address,
        nonce=0,
        gas=90_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=0,
    )

    with pytest.raises(ValueError, match="does not match signer"):
        onchain_anchor.sign_anchor_transaction(transaction, Account.create())

    wrong_call = dict(transaction)
    wrong_call["data"] = "0x00000000"
    with pytest.raises(ValueError, match="does not call anchor"):
        onchain_anchor.sign_anchor_transaction(wrong_call, signer)


def test_anchor_verifier_allows_apa_sequence_jumps_with_contiguous_anchor_indexes() -> None:
    entries = _entries()
    roots = anchor_history.log_prefix_hashes(entries)
    events = [
        _event(1, 1, roots[1]),
        _event(2, 3, roots[3]),
    ]

    verified = onchain_anchor.verify_anchor_events(events, entries)

    assert verified == (
        onchain_anchor.AnchorEvent(anchor_index=1, seq=1, root=roots[1]),
        onchain_anchor.AnchorEvent(anchor_index=2, seq=3, root=roots[3]),
    )


def test_anchor_verifier_detects_publication_gap() -> None:
    entries = _entries()
    roots = anchor_history.log_prefix_hashes(entries)

    with pytest.raises(onchain_anchor.OnchainAnchorError, match="publication sequence"):
        onchain_anchor.verify_anchor_events(
            [_event(1, 1, roots[1]), _event(3, 3, roots[3])],
            entries,
        )


def test_anchor_verifier_rejects_non_increasing_apa_sequences() -> None:
    entries = _entries()
    roots = anchor_history.log_prefix_hashes(entries)

    with pytest.raises(onchain_anchor.OnchainAnchorError, match="APA sequence"):
        onchain_anchor.verify_anchor_events(
            [_event(1, 2, roots[2]), _event(2, 1, roots[1])],
            entries,
        )


def test_anchor_verifier_detects_rewrite_and_truncation_against_retained_anchor() -> None:
    entries = _entries()
    roots = anchor_history.log_prefix_hashes(entries)
    events = [_event(1, 1, roots[1]), _event(2, 3, roots[3])]
    retained = onchain_anchor.AnchorEvent(anchor_index=1, seq=1, root=roots[1])
    rewritten = [dict(entry) for entry in entries]
    rewritten[0]["endpoint_host"] = "rewritten.example"
    rewritten[1]["prev_hash"] = hashlib.sha256(
        _canonical_json(rewritten[0]).encode("utf-8")
    ).hexdigest()
    rewritten[2]["prev_hash"] = hashlib.sha256(
        _canonical_json(rewritten[1]).encode("utf-8")
    ).hexdigest()

    with pytest.raises(onchain_anchor.OnchainAnchorError, match="root"):
        onchain_anchor.verify_anchor_events(events, rewritten, retained_anchor=retained)
    with pytest.raises(onchain_anchor.OnchainAnchorError, match="available log"):
        onchain_anchor.verify_anchor_events(events, entries[:1], retained_anchor=retained)
    with pytest.raises(onchain_anchor.OnchainAnchorError, match="retained anchor"):
        onchain_anchor.verify_anchor_events(
            [_event(1, 3, roots[3])],
            entries,
            retained_anchor=retained,
        )


def test_anchor_event_shape_is_strict() -> None:
    entries = _entries(1)

    with pytest.raises(onchain_anchor.OnchainAnchorError, match="exactly"):
        onchain_anchor.verify_anchor_events(
            [{"args": {"anchorIndex": 1, "seq": 1}}],
            entries,
        )
    with pytest.raises(onchain_anchor.OnchainAnchorError, match="root"):
        onchain_anchor.verify_anchor_events(
            [
                {
                    "args": {
                        "anchorIndex": 1,
                        "seq": 1,
                        "root": b"short",
                    }
                }
            ],
            entries,
        )
