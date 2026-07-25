"""Offline ERC-8004 feedback transactions for signed Warden audit evidence."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.providers.base import BaseProvider
from web3.types import RPCEndpoint, RPCResponse

from warden import audit_attestations

X_LAYER_CHAIN_ID = 196
WARDEN_AGENT_ID = 3808
UINT256_MAX = (1 << 256) - 1
REPUTATION_REGISTRY = Web3.to_checksum_address("0x8004BAa17C55a88189AE136b182e5fdA19dE9b63")
GRADE_TO_VALUE = {
    "A": 5,
    "B": 4,
    "C": 3,
    "D": 2,
    "F": 1,
}
REPUTATION_ABI: list[dict[str, object]] = [
    {
        "type": "function",
        "name": "giveFeedback",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "value", "type": "int128"},
            {"name": "valueDecimals", "type": "uint8"},
            {"name": "tag1", "type": "string"},
            {"name": "tag2", "type": "string"},
            {"name": "endpoint", "type": "string"},
            {"name": "feedbackURI", "type": "string"},
            {"name": "feedbackHash", "type": "bytes32"},
        ],
        "outputs": [],
    },
    {
        "type": "event",
        "name": "NewFeedback",
        "anonymous": False,
        "inputs": [
            {"name": "agentId", "type": "uint256", "indexed": True},
            {"name": "clientAddress", "type": "address", "indexed": True},
            {"name": "feedbackIndex", "type": "uint64", "indexed": False},
            {"name": "value", "type": "int128", "indexed": False},
            {"name": "valueDecimals", "type": "uint8", "indexed": False},
            {"name": "indexedTag1", "type": "string", "indexed": True},
            {"name": "tag1", "type": "string", "indexed": False},
            {"name": "tag2", "type": "string", "indexed": False},
            {"name": "endpoint", "type": "string", "indexed": False},
            {"name": "feedbackURI", "type": "string", "indexed": False},
            {"name": "feedbackHash", "type": "bytes32", "indexed": False},
        ],
    },
]


class _OfflineProvider(BaseProvider):
    def make_request(self, method: RPCEndpoint, params: object) -> RPCResponse:
        raise RuntimeError(f"offline feedback builder attempted RPC method {method}")


_OFFLINE_WEB3 = Web3(_OfflineProvider())
_REPUTATION_CONTRACT = _OFFLINE_WEB3.eth.contract(
    address=REPUTATION_REGISTRY,
    abi=REPUTATION_ABI,
)


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or not Web3.is_address(value):
        raise ValueError(f"{field} must be an EVM address")
    return Web3.to_checksum_address(value)


def _uint256(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT256_MAX:
        raise ValueError(f"{field} must be a uint256")
    return value


def _validated_attestation_uri(value: object, audit_id: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ValueError("attestation_uri must be a bounded HTTPS URI")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as exc:
        raise ValueError("attestation_uri must be a bounded HTTPS URI") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != f"/apa/audit/{audit_id}"
    ):
        raise ValueError("attestation_uri must identify this audit's HTTPS evidence route")
    return value


def _validated_evidence(record: dict[str, object]) -> tuple[str, str]:
    if record.get("consent_verified") is not True:
        raise ValueError("ERC-8004 feedback requires a consented audit")
    if record.get("inconclusive") != 0 or record.get("conclusive") != record.get("total"):
        raise ValueError("ERC-8004 feedback requires a conclusive audit")
    if not audit_attestations.verify_audit_attestation(record):
        raise ValueError("ERC-8004 feedback requires signed Warden audit evidence")
    grade = record["grade"]
    if not isinstance(grade, str) or grade not in GRADE_TO_VALUE:
        raise ValueError("audit grade is unsupported")
    return grade, audit_attestations.record_sha256(record)


def build_feedback_transaction(
    record: dict[str, object],
    *,
    target_agent_id: int,
    sender: str,
    attestation_uri: str,
    nonce: int,
    gas: int,
    max_fee_per_gas: int,
    max_priority_fee_per_gas: int,
) -> dict[str, object]:
    """Build an ERC-8004 feedback transaction without contacting a provider.

    ERC-8004 defines ``feedbackHash`` as Keccak-256 of ``feedbackURI`` content.
    Warden's evidence commitment is SHA-256 over its canonical signed record, so
    this transaction stores that commitment explicitly in ``tag2`` and leaves
    the optional EIP hash field zero instead of mislabelling SHA-256 as Keccak.
    """
    grade, record_hash = _validated_evidence(record)
    agent_id = _uint256(target_agent_id, "target_agent_id")
    if agent_id == WARDEN_AGENT_ID:
        raise ValueError("Warden cannot publish ERC-8004 feedback about itself")
    normalized_sender = _address(sender, "sender")
    evidence_uri = _validated_attestation_uri(attestation_uri, str(record["audit_id"]))
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

    transaction = _REPUTATION_CONTRACT.functions.giveFeedback(
        agent_id,
        GRADE_TO_VALUE[grade],
        0,
        "security-audit",
        f"sha256:{record_hash}",
        str(record["subject"]),
        evidence_uri,
        bytes(32),
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


def sign_feedback_transaction(
    transaction: Mapping[str, object],
    signer: LocalAccount,
) -> bytes:
    """Sign one complete ERC-8004 feedback transaction locally without broadcasting it."""
    sender = _address(transaction.get("from"), "transaction from")
    if sender != signer.address:
        raise ValueError("transaction sender does not match signer")
    if transaction.get("chainId") != X_LAYER_CHAIN_ID:
        raise ValueError("feedback transaction must target X Layer chain 196")
    if transaction.get("to") != REPUTATION_REGISTRY:
        raise ValueError("feedback transaction must target the X Layer ReputationRegistry")
    if transaction.get("value") != 0:
        raise ValueError("feedback transaction must not transfer value")
    data = transaction.get("data")
    try:
        encoded = data if isinstance(data, str) else Web3.to_hex(data)
        if not encoded.startswith("0x"):
            raise ValueError
        function, arguments = _REPUTATION_CONTRACT.decode_function_input(encoded)
        rebuilt = _REPUTATION_CONTRACT.encode_abi("giveFeedback", kwargs=arguments)
    except (TypeError, ValueError) as exc:
        raise ValueError("feedback transaction calldata is invalid") from exc
    if function.fn_name != "giveFeedback" or rebuilt.lower() != encoded.lower():
        raise ValueError("transaction does not call giveFeedback with canonical calldata")
    signed = signer.sign_transaction(dict(transaction))
    return bytes(signed.raw_transaction)
