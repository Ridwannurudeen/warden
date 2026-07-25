"""Offline X Layer transaction construction and verification for APA log anchors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.providers.base import BaseProvider
from web3.types import RPCEndpoint, RPCResponse

from warden import anchor_history, protection

X_LAYER_CHAIN_ID = 196
UINT64_MAX = (1 << 64) - 1
ANCHOR_ABI: list[dict[str, object]] = [
    {
        "type": "function",
        "name": "anchor",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "root", "type": "bytes32"},
            {"name": "seq", "type": "uint64"},
        ],
        "outputs": [],
    },
    {
        "type": "event",
        "name": "CheckpointAnchored",
        "anonymous": False,
        "inputs": [
            {"name": "anchorIndex", "type": "uint64", "indexed": True},
            {"name": "seq", "type": "uint64", "indexed": True},
            {"name": "root", "type": "bytes32", "indexed": False},
        ],
    },
]


class _OfflineProvider(BaseProvider):
    def make_request(self, method: RPCEndpoint, params: object) -> RPCResponse:
        raise RuntimeError(f"offline anchor builder attempted RPC method {method}")


_OFFLINE_WEB3 = Web3(_OfflineProvider())
_ANCHOR_SELECTOR = _OFFLINE_WEB3.keccak(text="anchor(bytes32,uint64)")[:4]
_EVENT_ARGUMENTS = {"anchorIndex", "seq", "root"}


class OnchainAnchorError(ValueError):
    """On-chain anchor evidence failed structural or cryptographic validation."""


@dataclass(frozen=True)
class AnchorEvent:
    """One normalized checkpoint event from the WardenLogAnchor contract."""

    anchor_index: int
    seq: int
    root: str


def _uint64(value: object, field: str) -> int:
    if type(value) is not int or not 1 <= value <= UINT64_MAX:
        raise ValueError(f"{field} must be a positive uint64")
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not Web3.is_address(value):
        raise ValueError(f"{field} must be an EVM address")
    return Web3.to_checksum_address(value)


def _root_hex(value: object) -> str:
    if isinstance(value, str):
        candidate = value[2:] if value.startswith("0x") else value
        if len(candidate) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in candidate
        ):
            raise OnchainAnchorError("anchor root must be exactly 32 bytes")
        return candidate.lower()
    if isinstance(value, bytes) and len(value) == 32:
        return value.hex()
    raise OnchainAnchorError("anchor root must be exactly 32 bytes")


def build_anchor_transaction(
    checkpoint: dict[str, object],
    *,
    contract_address: str,
    sender: str,
    nonce: int,
    gas: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
) -> dict[str, object]:
    """Build a complete EIP-1559 anchor transaction without contacting a provider."""
    if not protection.verify_log_checkpoint(checkpoint):
        raise ValueError("anchor requires a valid signed APA checkpoint")
    sequence = checkpoint["seq"]
    if sequence == 0:
        raise ValueError("anchor requires a non-empty APA checkpoint")
    _uint64(sequence, "checkpoint seq")
    normalized_contract = _address(contract_address, "contract_address")
    normalized_sender = _address(sender, "sender")
    if type(nonce) is not int or nonce < 0:
        raise ValueError("nonce must be a non-negative integer")
    if type(gas) is not int or gas <= 0:
        raise ValueError("gas must be a positive integer")
    if type(max_fee_per_gas) is not int or max_fee_per_gas < 0:
        raise ValueError("max_fee_per_gas must be a non-negative integer")
    if (
        type(max_priority_fee_per_gas) is not int
        or not 0 <= max_priority_fee_per_gas <= max_fee_per_gas
    ):
        raise ValueError("max_priority_fee_per_gas must be between zero and max_fee_per_gas")

    contract = _OFFLINE_WEB3.eth.contract(address=normalized_contract, abi=ANCHOR_ABI)
    transaction = contract.functions.anchor(
        bytes.fromhex(str(checkpoint["head_hash"])),
        sequence,
    ).build_transaction(
        {
            "chainId": X_LAYER_CHAIN_ID,
            "from": normalized_sender,
            "nonce": nonce,
            "gas": gas,
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "value": 0,
        }
    )
    return dict(transaction)


def sign_anchor_transaction(
    transaction: Mapping[str, object],
    signer: LocalAccount,
) -> bytes:
    """Sign one complete anchor transaction locally without broadcasting it."""
    sender = _address(transaction.get("from"), "transaction from")
    if sender != signer.address:
        raise ValueError("transaction sender does not match signer")
    if transaction.get("chainId") != X_LAYER_CHAIN_ID:
        raise ValueError("anchor transaction must target X Layer chain 196")
    if transaction.get("value") != 0:
        raise ValueError("anchor transaction must not transfer value")
    data = transaction.get("data")
    try:
        encoded_hex = data if isinstance(data, str) else Web3.to_hex(data)
        if not encoded_hex.startswith("0x"):
            raise ValueError
        encoded = bytes.fromhex(encoded_hex[2:])
    except (TypeError, ValueError) as exc:
        raise ValueError("anchor transaction calldata is invalid") from exc
    if len(encoded) != 68 or not encoded.startswith(_ANCHOR_SELECTOR):
        raise ValueError("transaction does not call anchor(bytes32,uint64)")
    signed = signer.sign_transaction(dict(transaction))
    return bytes(signed.raw_transaction)


def normalize_anchor_event(event: Mapping[str, object]) -> AnchorEvent:
    """Normalize one decoded Web3 event while rejecting ambiguous shapes."""
    arguments = event.get("args")
    if not isinstance(arguments, Mapping) or set(arguments) != _EVENT_ARGUMENTS:
        raise OnchainAnchorError(
            "checkpoint event args must contain exactly anchorIndex, seq, and root"
        )
    try:
        anchor_index = _uint64(arguments["anchorIndex"], "anchorIndex")
        sequence = _uint64(arguments["seq"], "seq")
    except ValueError as exc:
        raise OnchainAnchorError(str(exc)) from exc
    return AnchorEvent(
        anchor_index=anchor_index,
        seq=sequence,
        root=_root_hex(arguments["root"]),
    )


def verify_anchor_events(
    events: Sequence[Mapping[str, object]],
    entries: Sequence[dict[str, object]],
    *,
    retained_anchor: AnchorEvent | None = None,
) -> tuple[AnchorEvent, ...]:
    """Reconstruct and verify the on-chain checkpoint sequence against one APA log."""
    prefix_hashes = anchor_history.log_prefix_hashes(entries)
    verified: list[AnchorEvent] = []
    previous_apa_sequence = 0
    for expected_anchor_index, raw_event in enumerate(events, start=1):
        event = normalize_anchor_event(raw_event)
        if event.anchor_index != expected_anchor_index:
            raise OnchainAnchorError("on-chain publication sequence contains a gap")
        if event.seq <= previous_apa_sequence:
            raise OnchainAnchorError("on-chain APA sequence must increase")
        if event.seq >= len(prefix_hashes):
            raise OnchainAnchorError("anchor sequence exceeds the available log")
        if event.root != prefix_hashes[event.seq]:
            raise OnchainAnchorError("on-chain root does not match the APA log prefix")
        verified.append(event)
        previous_apa_sequence = event.seq

    if retained_anchor is not None and retained_anchor not in verified:
        raise OnchainAnchorError("retained anchor is absent from the verified event chain")
    return tuple(verified)
