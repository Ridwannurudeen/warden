"""On-chain proof that a registration belongs to the agent it names.

A registered policy may name an `agent_id`, but a name is not evidence: the field
is caller-supplied, and nothing checked it. ERC-8004 registers each agent as an
ERC-721 token on X Layer, so an agent's owner is a matter of public record.
Requiring a signature from that owner at registration time is what turns
`agent_id` from an assertion into something an adjudicator can check.

The read is live and fails closed. An agent is a transferable token: a cached
owner is wrong the moment one is sold, and it would let a former owner keep
proving control of an agent it no longer holds. If the chain cannot be reached,
the registration is refused rather than recorded as unbound — a silent downgrade
would let anyone who can stall one RPC call obtain a registration that reads as
though it were never meant to be bound.
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from warden.badges import _canonical_json
from warden.onchain_attestation import X_LAYER_CHAIN_ID

BINDING_SPEC_VERSION = "warden-agent-binding/1"
# Read from the pinned ReputationRegistry's getIdentityRegistry() on X Layer
# rather than taken on trust; the two registries are deployed as a pair.
IDENTITY_REGISTRY = Web3.to_checksum_address("0x8004a169fb4a3325136eb29fa0ceb6d2e539a432")
DEFAULT_RPC_URL = "https://rpc.xlayer.tech"
# ERC-1271's "signature is valid" answer. Any other return value, including a
# revert or empty data, is a refusal.
ERC1271_MAGIC_VALUE = "1626ba7e"
RPC_TIMEOUT_SECONDS = 5.0
MAX_RPC_RESPONSE_BYTES = 16_000
# An owner signature is a deliberate act, not a standing grant. A bounded window
# keeps a captured proof from authorizing a registration indefinitely.
MAX_BINDING_LIFETIME_SECONDS = 3_600


class AgentIdentityUnavailable(RuntimeError):
    """The registry could not be read, so ownership is unknown rather than absent."""


class AgentNotRegistered(ValueError):
    """The chain answered, and this agent id holds no owner.

    Distinct from AgentIdentityUnavailable on purpose: this is a caller naming an
    agent that does not exist, which it can fix, whereas an unreachable registry
    is ours to fix and must never be reported as though the agent were absent.
    """


def _selector(signature: str) -> str:
    return Web3.keccak(text=signature)[:4].hex()


def _rpc_url() -> str:
    url = os.environ.get("WARDEN_XLAYER_RPC_URL", DEFAULT_RPC_URL).strip()
    if not url.startswith("https://"):
        raise AgentIdentityUnavailable("X Layer RPC URL must be https")
    return url


async def _eth_call(
    to: str,
    data: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str | None:
    """Read-only call against the pinned X Layer RPC. None means the call reverted.

    A revert is an answer, not a failure: `ownerOf` reverts for an unminted token
    and a contract wallet may revert instead of refusing a signature politely.
    Collapsing that into the unreachable-RPC error would turn a caller's mistake
    into a 503 and hide a real outage behind the same message.

    The URL is a constant or an operator-set environment value and never derives
    from a request, so it is a different trust class from the caller-supplied
    endpoints `apa_url.validate_public_http_url` exists to defend against.
    Routing it through that guard would pin DNS for a host we already trust
    without excluding anything.
    """
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    try:
        async with asyncio.timeout(RPC_TIMEOUT_SECONDS):
            async with httpx.AsyncClient(
                timeout=RPC_TIMEOUT_SECONDS, follow_redirects=False, transport=transport
            ) as client:
                response = await client.post(_rpc_url(), json=request)
    except (httpx.HTTPError, TimeoutError) as exc:
        raise AgentIdentityUnavailable(f"X Layer RPC is unreachable: {exc}") from exc
    if response.status_code != 200:
        raise AgentIdentityUnavailable(f"X Layer RPC returned HTTP {response.status_code}")
    if len(response.content) > MAX_RPC_RESPONSE_BYTES:
        raise AgentIdentityUnavailable("X Layer RPC response was oversized")
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise AgentIdentityUnavailable("X Layer RPC returned malformed JSON") from exc
    if not isinstance(body, dict):
        raise AgentIdentityUnavailable("X Layer RPC returned malformed JSON")
    if "error" in body:
        return None
    result = body.get("result")
    if not isinstance(result, str) or not result.startswith("0x"):
        raise AgentIdentityUnavailable("X Layer RPC returned no result")
    return result


def _decode_address(result: str) -> str:
    word = result[2:]
    if len(word) != 64 or int(word[:24], 16) != 0:
        raise AgentNotRegistered("registry returned a malformed address")
    address = "0x" + word[24:]
    if int(address, 16) == 0:
        raise AgentNotRegistered("registry returned the zero address")
    return Web3.to_checksum_address(address)


async def resolve_agent_owner(
    agent_id: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """The address holding this ERC-8004 agent, read from the registry right now."""
    try:
        token_id = int(agent_id)
    except ValueError as exc:
        raise AgentNotRegistered("agent_id must be a decimal token id") from exc
    data = "0x" + _selector("ownerOf(uint256)") + f"{token_id:064x}"
    result = await _eth_call(IDENTITY_REGISTRY, data, transport=transport)
    if result is None:
        raise AgentNotRegistered(f"agent {agent_id} is not registered on X Layer")
    return _decode_address(result)


def owner_binding_payload(
    *,
    agent_id: str,
    caller_key: str | None,
    policy_sha256: str,
    expires_at: int,
) -> bytes:
    """Exactly what an agent owner signs to bind a registration to its agent.

    The caller key is inside the payload because binding the agent to the key
    that will sign guard requests is the entire point; binding `policy_sha256`
    keeps a proof from authorizing rules its signer never saw. The chain id and
    registry address are named so a signature made for one deployment cannot be
    presented against another.
    """
    return _canonical_json(
        {
            "spec_version": BINDING_SPEC_VERSION,
            "chain_id": X_LAYER_CHAIN_ID,
            "identity_registry": IDENTITY_REGISTRY,
            "agent_id": agent_id,
            "caller_key": caller_key,
            "policy_sha256": policy_sha256,
            "expires_at": expires_at,
        }
    ).encode("utf-8")


def eip191_hash(payload: bytes) -> bytes:
    """The EIP-191 personal_sign digest, built from the spec rather than a helper.

    Computed here so the published contract does not depend on a library's
    interpretation of it; a test asserts this agrees with eth_account.
    """
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(payload)).encode("ascii")
    return Web3.keccak(prefix + payload)


def _recovers_to_owner(owner: str, signature: bytes, payload: bytes) -> bool:
    try:
        recovered = Account.recover_message(encode_defunct(payload), signature=signature)
    except (ValueError, TypeError):
        return False
    return recovered == owner


async def _erc1271_accepts(
    owner: str,
    signature: bytes,
    payload: bytes,
    transport: httpx.AsyncBaseTransport | None,
) -> bool:
    data = (
        "0x"
        + _selector("isValidSignature(bytes32,bytes)")
        + abi_encode(["bytes32", "bytes"], [eip191_hash(payload), signature]).hex()
    )
    result = await _eth_call(owner, data, transport=transport)
    # A revert, or the empty data an EOA returns, both mean "not accepted".
    return result is not None and result[2:10].lower() == ERC1271_MAGIC_VALUE


async def owner_signature_valid(
    *,
    owner: str,
    signature: str,
    payload: bytes,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """True when `signature` proves control of `owner` over exactly these bytes.

    Two shapes are accepted because agent owners are not all plain keys. OKX's
    own agent wallets carry an EIP-7702 delegation, which leaves the underlying
    account an EOA that still signs recoverably, so ECDSA settles the common
    case without a second network round trip. A true contract wallet cannot
    produce a recoverable signature at all, so it is asked directly via ERC-1271.
    """
    try:
        raw = bytes.fromhex(signature[2:] if signature.startswith("0x") else signature)
    except ValueError:
        return False
    if len(raw) != 65:
        return False
    if _recovers_to_owner(owner, raw, payload):
        return True
    return await _erc1271_accepts(owner, raw, payload, transport)
