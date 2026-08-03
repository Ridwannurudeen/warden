"""Ownership proofs read from the ERC-8004 registry rather than taken on trust.

Covers the last open finding from the external review of `/api/action/guard`:
`agent_id` was an unauthenticated caller-supplied string on every receipt.
"""

from __future__ import annotations

import json

import httpx
import pytest
from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_defunct

from warden import agent_identity

AGENT_ID = "3808"
POLICY_HASH = "b" * 64
CALLER_KEY = "ed25519:" + "A" * 43
EXPIRES_AT = 1_785_756_110


def _word(value: int) -> str:
    return f"{value:064x}"


def _address_word(address: str) -> str:
    return _word(int(address, 16))


def _rpc(handler):
    """A transport that answers eth_call with whatever `handler` returns."""

    async def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "eth_call"
        return handler(body["params"][0])

    return httpx.MockTransport(respond)


def _returns(value: str):
    return _rpc(
        lambda _call: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": value})
    )


def _reverts():
    return _rpc(
        lambda _call: httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "reverted"}}
        )
    )


async def test_the_owner_is_read_from_the_registry_not_the_request():
    owner = Account.create().address
    transport = _returns("0x" + _address_word(owner))

    assert await agent_identity.resolve_agent_owner(AGENT_ID, transport=transport) == owner


async def test_an_unregistered_agent_is_a_caller_error_not_an_outage():
    # The distinction is load-bearing: naming a nonexistent agent is something the
    # caller can fix, and reporting it as an outage would hide a real one.
    with pytest.raises(agent_identity.AgentNotRegistered):
        await agent_identity.resolve_agent_owner(AGENT_ID, transport=_reverts())

    with pytest.raises(agent_identity.AgentNotRegistered):
        await agent_identity.resolve_agent_owner(AGENT_ID, transport=_returns("0x" + _word(0)))


async def test_an_unreachable_registry_never_reads_as_unowned():
    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with pytest.raises(agent_identity.AgentIdentityUnavailable):
        await agent_identity.resolve_agent_owner(AGENT_ID, transport=httpx.MockTransport(refuse))

    with pytest.raises(agent_identity.AgentIdentityUnavailable):
        await agent_identity.resolve_agent_owner(
            AGENT_ID, transport=httpx.MockTransport(lambda _r: httpx.Response(502))
        )


async def test_an_eoa_owner_proves_control_by_signing_the_published_bytes():
    # Built from the spec with stdlib json, not from the module's own helper.
    # Signing with the implementation's own canonicaliser would test it against
    # itself and prove nothing about what an external signer can produce.
    owner = Account.create()
    published = json.dumps(
        {
            "spec_version": "warden-agent-binding/1",
            "chain_id": 196,
            "identity_registry": agent_identity.IDENTITY_REGISTRY,
            "agent_id": AGENT_ID,
            "caller_key": CALLER_KEY,
            "policy_sha256": POLICY_HASH,
            "expires_at": EXPIRES_AT,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    assert published == agent_identity.owner_binding_payload(
        agent_id=AGENT_ID,
        caller_key=CALLER_KEY,
        policy_sha256=POLICY_HASH,
        expires_at=EXPIRES_AT,
    )

    signature = owner.sign_message(encode_defunct(published)).signature.hex()
    assert await agent_identity.owner_signature_valid(
        owner=owner.address, signature=signature, payload=published
    )


async def test_a_stranger_cannot_sign_for_an_owner():
    owner = Account.create()
    stranger = Account.create()
    payload = agent_identity.owner_binding_payload(
        agent_id=AGENT_ID,
        caller_key=CALLER_KEY,
        policy_sha256=POLICY_HASH,
        expires_at=EXPIRES_AT,
    )
    forged = stranger.sign_message(encode_defunct(payload)).signature.hex()

    # An EOA has no code, so the ERC-1271 fallback reaches empty data and refuses
    # rather than erroring.
    assert not await agent_identity.owner_signature_valid(
        owner=owner.address, signature=forged, payload=payload, transport=_returns("0x")
    )


async def test_a_signature_does_not_carry_to_different_terms():
    owner = Account.create()
    signed_for = agent_identity.owner_binding_payload(
        agent_id=AGENT_ID,
        caller_key=CALLER_KEY,
        policy_sha256=POLICY_HASH,
        expires_at=EXPIRES_AT,
    )
    signature = owner.sign_message(encode_defunct(signed_for)).signature.hex()

    # Each of these is a term the signer committed to; changing any one of them
    # must invalidate the proof rather than quietly widen it.
    for altered in (
        {"agent_id": "5246"},
        {"policy_sha256": "c" * 64},
        {"caller_key": None},
        {"expires_at": EXPIRES_AT + 1},
    ):
        other = agent_identity.owner_binding_payload(
            **{
                "agent_id": AGENT_ID,
                "caller_key": CALLER_KEY,
                "policy_sha256": POLICY_HASH,
                "expires_at": EXPIRES_AT,
                **altered,
            }
        )
        assert not await agent_identity.owner_signature_valid(
            owner=owner.address, signature=signature, payload=other, transport=_returns("0x")
        )


async def test_a_contract_wallet_is_asked_directly():
    # A true contract wallet cannot produce a recoverable signature, so ECDSA
    # fails and ERC-1271 decides. Owners on X Layer today are EIP-7702-delegated
    # EOAs, which still recover; this covers the ones that will not.
    wallet = Account.create().address
    signature = Account.create().sign_message(encode_defunct(b"unrelated")).signature.hex()
    payload = agent_identity.owner_binding_payload(
        agent_id=AGENT_ID,
        caller_key=None,
        policy_sha256=POLICY_HASH,
        expires_at=EXPIRES_AT,
    )
    magic = "0x" + agent_identity.ERC1271_MAGIC_VALUE + "0" * 56

    assert await agent_identity.owner_signature_valid(
        owner=wallet, signature=signature, payload=payload, transport=_returns(magic)
    )
    # Any other answer, including a revert, is a refusal.
    assert not await agent_identity.owner_signature_valid(
        owner=wallet, signature=signature, payload=payload, transport=_returns("0x" + _word(0))
    )
    assert not await agent_identity.owner_signature_valid(
        owner=wallet, signature=signature, payload=payload, transport=_reverts()
    )


async def test_a_malformed_signature_is_refused_without_asking_the_chain():
    def unreachable(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("a malformed signature must not reach the chain")

    for candidate in ("0xdeadbeef", "not-hex", "0x" + "ab" * 64):
        assert not await agent_identity.owner_signature_valid(
            owner=Account.create().address,
            signature=candidate,
            payload=b"{}",
            transport=httpx.MockTransport(unreachable),
        )


def test_the_eip191_digest_matches_the_library_it_does_not_use():
    # The digest is built from the EIP-191 text rather than borrowed, so this
    # pins the two together; a drift here would silently break contract wallets.
    payload = agent_identity.owner_binding_payload(
        agent_id=AGENT_ID,
        caller_key=CALLER_KEY,
        policy_sha256=POLICY_HASH,
        expires_at=EXPIRES_AT,
    )

    assert agent_identity.eip191_hash(payload) == _hash_eip191_message(encode_defunct(payload))


def test_the_rpc_endpoint_must_be_https(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WARDEN_XLAYER_RPC_URL", "http://rpc.example.invalid")

    with pytest.raises(agent_identity.AgentIdentityUnavailable):
        agent_identity._rpc_url()
