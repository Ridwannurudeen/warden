"""Registered policies, so a receipt can cite one instead of asserting it.

Covers the two structural findings from the 2026-07-30 external review: policy
shopping (a caller could assert any policy inline) and caller binding (a receipt
could not show who asked).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from unittest import mock
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from warden import agent_identity, evidence_store, policy_registry
from warden.action_guard import action_context_sha256, policy_sha256, verify_decision_receipt
from warden.badges import b64u_encode
from warden.models import ActionIntent, ActionPolicy, OkxTaskContext

POLICY = {
    "allowed_actions": ["transfer"],
    "allowed_tools": ["wallet.send"],
    "allowed_destinations": ["0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"],
    "max_amount_atomic_by_asset": {"USDT0": 1_000},
}
INTENT = {
    "action_type": "transfer",
    "tool": "wallet.send",
    "destination": "0xabcdef0123456789abcdef0123456789abcdef01",
    "asset": "USDT0",
    "amount_atomic": 10,
    "payload": "Pay the approved invoice.",
}
TASK = {
    "network": "eip155:196",
    "agent_id": "5246",
    "service_id": "argus-screen",
    "service_revision_sha256": "a" * 64,
    "task_id": "task-1",
}


@pytest.fixture(autouse=True)
def _isolated_issuer_and_store(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("WARDEN_ISSUER_KEY", b64u_encode(key.private_bytes_raw(), "ed25519-seed"))
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(Path(tempfile.mkdtemp()) / "registry.db"))


@pytest.fixture()
def client() -> TestClient:
    from warden.api import app

    return TestClient(app)


def _caller_signature(private_key: Ed25519PrivateKey, policy_id: str, intent: dict) -> str:
    """Sign exactly what the published spec tells a caller to sign.

    Deliberately not routed through any internal signing helper. The previous
    version signed an internal wrapper, which matched the implementation and so
    passed while no external caller could ever produce a valid signature.
    """
    context = action_context_sha256(ActionIntent(**intent), OkxTaskContext(**TASK))
    payload = policy_registry.caller_binding_payload(policy_id, context)
    return b64u_encode(private_key.sign(payload), "sig")


def test_a_registered_policy_is_anchored_in_the_transparency_log(client: TestClient):
    response = client.post("/api/policy/register", json={"policy": POLICY})

    assert response.status_code == 200
    body = response.json()
    # The sequence is the whole point: it places the policy in the hash chain
    # before any action that cites it.
    assert isinstance(body["log_seq"], int) and body["log_seq"] >= 1
    assert policy_registry.verify_policy_record(body["record"])


def test_registering_the_same_policy_twice_keeps_the_original_anchor(client: TestClient):
    # The clock is pinned apart deliberately. Same-second registrations produce a
    # byte-identical record, which the store accepts on its own, so the test would
    # pass without proving anything. A later re-registration is the real case.
    with mock.patch("warden.policy_registry.time.time", return_value=1_000.0):
        first = client.post("/api/policy/register", json={"policy": POLICY}).json()
    with mock.patch("warden.policy_registry.time.time", return_value=2_000.0):
        second = client.post("/api/policy/register", json={"policy": POLICY}).json()

    # Otherwise a caller could re-register to move its evidence forward in time.
    assert first["policy_id"] == second["policy_id"]
    assert first["log_seq"] == second["log_seq"]
    assert second["record"]["issued_at"] == 1_000


def test_a_laxer_policy_registers_separately_and_later(client: TestClient):
    strict = client.post("/api/policy/register", json={"policy": POLICY}).json()
    lax = client.post(
        "/api/policy/register",
        json={"policy": {**POLICY, "max_amount_atomic_by_asset": {"USDT0": 99_999_999}}},
    ).json()

    assert lax["policy_id"] != strict["policy_id"]
    assert lax["log_seq"] > strict["log_seq"]


def test_a_receipt_says_whether_the_policy_was_registered_or_merely_asserted(
    client: TestClient,
):
    inline = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy": POLICY}
    ).json()
    assert inline["receipt"]["policy_binding"] == "inline"
    assert inline["receipt"]["policy_log_seq"] is None

    policy_id = client.post("/api/policy/register", json={"policy": POLICY}).json()["policy_id"]
    registered = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": policy_id}
    ).json()
    assert registered["receipt"]["policy_binding"] == "registered"
    assert registered["receipt"]["policy_log_seq"] == evidence_store.action_policy_log_seq(
        policy_id
    )


def test_the_binding_is_inside_the_signature(client: TestClient):
    policy_id = client.post("/api/policy/register", json={"policy": POLICY}).json()["policy_id"]
    receipt = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": policy_id}
    ).json()["receipt"]

    assert verify_decision_receipt(receipt)
    # Downgrading the claim must not survive verification.
    assert not verify_decision_receipt({**receipt, "policy_binding": "inline"})


def test_a_caller_signature_binds_the_request_and_does_not_replay(client: TestClient):
    caller = Ed25519PrivateKey.generate()
    public = b64u_encode(caller.public_key().public_bytes_raw(), "ed25519")
    policy_id = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": public}
    ).json()["policy_id"]

    signature = _caller_signature(caller, policy_id, INTENT)
    signed = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": policy_id, "caller_sig": signature},
    ).json()
    assert signed["receipt"]["caller_verified"] is True

    # The signature covers the action context, so it cannot authorize a larger
    # payment — and a presented signature that does not verify is a hard error.
    replayed = client.post(
        "/api/action/guard",
        json={
            "intent": {**INTENT, "amount_atomic": 999},
            "task": TASK,
            "policy_id": policy_id,
            "caller_sig": signature,
        },
    )
    assert replayed.status_code == 400

    unsigned = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": policy_id}
    ).json()
    assert unsigned["receipt"]["caller_verified"] is False


def test_a_wrong_key_cannot_claim_the_registration(client: TestClient):
    owner = Ed25519PrivateKey.generate()
    public = b64u_encode(owner.public_key().public_bytes_raw(), "ed25519")
    policy_id = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": public}
    ).json()["policy_id"]

    impostor = Ed25519PrivateKey.generate()
    forged = _caller_signature(impostor, policy_id, INTENT)
    result = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": policy_id, "caller_sig": forged},
    )

    assert result.status_code == 400


def test_an_unknown_policy_id_is_refused_rather_than_defaulted(client: TestClient):
    response = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": "b" * 64}
    )

    assert response.status_code == 404


def test_a_request_must_name_exactly_one_policy_source(client: TestClient):
    assert (
        client.post("/api/action/guard", json={"intent": INTENT, "task": TASK}).status_code == 422
    )
    assert (
        client.post(
            "/api/action/guard",
            json={"intent": INTENT, "task": TASK, "policy": POLICY, "policy_id": "c" * 64},
        ).status_code
        == 422
    )


def test_the_policy_id_is_content_addressed_and_case_insensitive():
    lower = ActionPolicy(**{**POLICY, "allowed_destinations": [INTENT["destination"]]})
    upper = ActionPolicy(**POLICY)

    assert policy_registry.policy_id_for(lower) == policy_registry.policy_id_for(upper)


def test_two_callers_may_register_the_same_rules_under_their_own_keys(client: TestClient):
    # Found in production: with the policy alone as the address, a second party
    # registering identical rules collided with the first record, silently
    # inherited its (absent) key, and got a receipt whose caller_verified could
    # never become true — while still receiving a 200 and a policy_id.
    first = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate()
    key_one = b64u_encode(first.public_key().public_bytes_raw(), "ed25519")
    key_two = b64u_encode(second.public_key().public_bytes_raw(), "ed25519")

    unkeyed = client.post("/api/policy/register", json={"policy": POLICY}).json()
    one = client.post("/api/policy/register", json={"policy": POLICY, "caller_key": key_one}).json()
    two = client.post("/api/policy/register", json={"policy": POLICY, "caller_key": key_two}).json()

    assert len({unkeyed["policy_id"], one["policy_id"], two["policy_id"]}) == 3
    assert one["record"]["caller_key"] == key_one
    assert two["record"]["caller_key"] == key_two

    # And each key still only authorizes its own registration.
    signature = _caller_signature(first, one["policy_id"], INTENT)
    mine = client.post(
        "/api/action/guard",
        json={
            "intent": INTENT,
            "task": TASK,
            "policy_id": one["policy_id"],
            "caller_sig": signature,
        },
    ).json()
    assert mine["receipt"]["caller_verified"] is True

    theirs = client.post(
        "/api/action/guard",
        json={
            "intent": INTENT,
            "task": TASK,
            "policy_id": two["policy_id"],
            "caller_sig": signature,
        },
    )
    assert theirs.status_code == 400


def test_a_signature_made_from_the_published_spec_alone_verifies(client: TestClient):
    # The regression that matters. caller_verified was previously checked against an
    # internal wrapper, so a caller following the spec could never reach it. This
    # signs with nothing but the documented bytes and a raw Ed25519 key.
    caller = Ed25519PrivateKey.generate()
    public = b64u_encode(caller.public_key().public_bytes_raw(), "ed25519")
    policy_id = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": public}
    ).json()["policy_id"]

    context = action_context_sha256(ActionIntent(**INTENT), OkxTaskContext(**TASK))
    published_bytes = json.dumps(
        {
            "spec_version": "warden-action-policy/1",
            "policy_id": policy_id,
            "action_context_sha256": context,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    signature = b64u_encode(caller.sign(published_bytes), "sig")

    response = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": policy_id, "caller_sig": signature},
    )

    assert response.status_code == 200
    assert response.json()["receipt"]["caller_verified"] is True


def test_a_presented_signature_that_does_not_verify_is_a_hard_error(client: TestClient):
    # A 200 with caller_verified false made "rejected" indistinguishable from
    # "never checked" on a field an adjudicator leans on.
    caller = Ed25519PrivateKey.generate()
    impostor = Ed25519PrivateKey.generate()
    public = b64u_encode(caller.public_key().public_bytes_raw(), "ed25519")
    policy_id = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": public}
    ).json()["policy_id"]

    forged = _caller_signature(impostor, policy_id, INTENT)
    assert (
        client.post(
            "/api/action/guard",
            json={"intent": INTENT, "task": TASK, "policy_id": policy_id, "caller_sig": forged},
        ).status_code
        == 400
    )

    # Omitting it entirely stays valid, and simply proves nothing about the caller.
    unsigned = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": policy_id}
    )
    assert unsigned.status_code == 200
    assert unsigned.json()["receipt"]["caller_verified"] is False


def _owner_proof(
    owner: object,
    *,
    agent_id: str = TASK["agent_id"],
    caller_key: str | None = None,
    policy: dict | None = None,
    expires_at: int | None = None,
) -> dict[str, object]:
    """Sign the agent binding the way the spec tells an agent owner to.

    Built from the documented JSON with the stdlib, not from the module's own
    canonicaliser: signing with the implementation's own helper would test it
    against itself, which is exactly how the unreachable `caller_verified` bug
    survived a green suite.
    """
    expiry = int(time.time()) + 600 if expires_at is None else expires_at
    published = json.dumps(
        {
            "spec_version": "warden-agent-binding/1",
            "chain_id": 196,
            "identity_registry": agent_identity.IDENTITY_REGISTRY,
            "agent_id": agent_id,
            "caller_key": caller_key,
            "policy_sha256": policy_sha256(ActionPolicy(**(policy or POLICY))),
            "expires_at": expiry,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return {
        "agent_id": agent_id,
        "owner_sig": owner.sign_message(encode_defunct(published)).signature.hex(),
        "owner_sig_expires_at": expiry,
    }


@pytest.fixture()
def onchain_owner(monkeypatch: pytest.MonkeyPatch):
    """Pin the registry read; the signature check itself stays real."""
    owner = Account.create()

    async def _resolve(agent_id: str, **_kwargs: object) -> str:
        assert agent_id == TASK["agent_id"]
        return owner.address

    monkeypatch.setattr(agent_identity, "resolve_agent_owner", _resolve)
    return owner


def test_a_registration_binds_an_agent_only_its_owner_can_claim(client: TestClient, onchain_owner):
    response = client.post(
        "/api/policy/register", json={"policy": POLICY, **_owner_proof(onchain_owner)}
    )

    assert response.status_code == 200
    record = response.json()["record"]
    assert record["spec_version"] == "warden-action-policy/2"
    assert record["agent_id"] == TASK["agent_id"]
    # The owner is recorded as the chain reported it, not as the caller spelled it.
    assert record["agent_owner"] == onchain_owner.address
    assert policy_registry.verify_policy_record(record)

    guarded = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": response.json()["policy_id"]},
    ).json()
    assert guarded["receipt"]["agent_binding"] == "onchain"
    assert verify_decision_receipt(guarded["receipt"])
    # And the claim is inside the signature, so it cannot be edited afterwards.
    assert not verify_decision_receipt({**guarded["receipt"], "agent_binding": "unbound"})


def test_a_stranger_cannot_bind_an_agent_it_does_not_own(client: TestClient, onchain_owner):
    # The finding this whole change exists for: previously any caller could name
    # any agent_id and be handed a receipt carrying it.
    stranger = Account.create()

    response = client.post(
        "/api/policy/register", json={"policy": POLICY, **_owner_proof(stranger)}
    )

    assert response.status_code == 400
    assert "owner_sig" in response.json()["detail"]


def test_an_owner_proof_does_not_carry_to_a_policy_its_signer_never_saw(
    client: TestClient, onchain_owner
):
    lax = {**POLICY, "max_amount_atomic_by_asset": {"USDT0": 99_999_999}}
    proof_for_strict = _owner_proof(onchain_owner, policy=POLICY)

    assert (
        client.post("/api/policy/register", json={"policy": lax, **proof_for_strict}).status_code
        == 400
    )


def test_an_expired_owner_proof_is_refused(client: TestClient, onchain_owner):
    stale = _owner_proof(onchain_owner, expires_at=int(time.time()) - 1)
    assert client.post("/api/policy/register", json={"policy": POLICY, **stale}).status_code == 400

    # An unbounded expiry would make one signature a standing grant.
    forever = _owner_proof(onchain_owner, expires_at=int(time.time()) + 86_400)
    assert (
        client.post("/api/policy/register", json={"policy": POLICY, **forever}).status_code == 400
    )


def test_an_unreachable_registry_refuses_rather_than_registering_unbound(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    # The dangerous failure mode: if a stalled RPC silently downgraded to an
    # unbound registration, anyone able to stall one call could obtain a record
    # that reads as though binding had never been requested.
    owner = Account.create()

    async def _unavailable(_agent_id: str, **_kwargs: object) -> str:
        raise agent_identity.AgentIdentityUnavailable("no route to host")

    monkeypatch.setattr(agent_identity, "resolve_agent_owner", _unavailable)

    response = client.post("/api/policy/register", json={"policy": POLICY, **_owner_proof(owner)})

    assert response.status_code == 503
    bound_id = policy_registry.policy_id_for(ActionPolicy(**POLICY), None, TASK["agent_id"])
    assert policy_registry.load_registered_policy(bound_id) is None


def test_naming_an_agent_that_does_not_exist_is_the_callers_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    async def _missing(_agent_id: str, **_kwargs: object) -> str:
        raise agent_identity.AgentNotRegistered("agent 3808 is not registered on X Layer")

    monkeypatch.setattr(agent_identity, "resolve_agent_owner", _missing)

    response = client.post(
        "/api/policy/register", json={"policy": POLICY, **_owner_proof(Account.create())}
    )

    assert response.status_code == 400


def test_a_bound_policy_refuses_a_request_naming_a_different_agent(
    client: TestClient, onchain_owner
):
    policy_id = client.post(
        "/api/policy/register", json={"policy": POLICY, **_owner_proof(onchain_owner)}
    ).json()["policy_id"]

    impersonated = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": {**TASK, "agent_id": "4844"}, "policy_id": policy_id},
    )

    # Issuing a receipt here would put a proven binding beside a contradicting
    # agent_id, which is worse than refusing.
    assert impersonated.status_code == 400


def test_an_unbound_registration_is_untouched_by_agent_binding(client: TestClient):
    # Production's hash-chained log already holds records addressed the old way,
    # and every read re-checks a stored record against its log entry. If this
    # drifts, anchored evidence stops verifying.
    policy = ActionPolicy(**POLICY)
    documented = hashlib.sha256(
        json.dumps(
            {"policy": policy_registry.canonical_policy(policy), "caller_key": None},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    body = client.post("/api/policy/register", json={"policy": POLICY}).json()

    assert body["policy_id"] == documented
    assert body["record"]["spec_version"] == "warden-action-policy/1"
    assert "agent_id" not in body["record"]

    guarded = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": body["policy_id"]},
    ).json()
    assert guarded["receipt"]["agent_binding"] == "unbound"


def test_binding_an_agent_does_not_collide_with_the_same_rules_unbound(
    client: TestClient, onchain_owner
):
    # The PR #42 failure mode, one level up: if the agent were left out of the
    # content address, registering these same rules unbound first would make the
    # bound registration hit the idempotent early return, silently discard the
    # binding, and still answer 200 with a policy_id.
    unbound = client.post("/api/policy/register", json={"policy": POLICY}).json()
    bound = client.post(
        "/api/policy/register", json={"policy": POLICY, **_owner_proof(onchain_owner)}
    ).json()

    assert unbound["policy_id"] != bound["policy_id"]
    assert "agent_id" not in unbound["record"]
    assert bound["record"]["agent_id"] == TASK["agent_id"]


def test_a_partial_agent_binding_is_rejected_outright(client: TestClient):
    proof = _owner_proof(Account.create())
    for dropped in ("agent_id", "owner_sig", "owner_sig_expires_at"):
        partial = {key: value for key, value in proof.items() if key != dropped}
        assert (
            client.post("/api/policy/register", json={"policy": POLICY, **partial}).status_code
            == 422
        )


def test_the_policy_id_covers_the_caller_key_as_documented():
    # The spec claimed the id was the hash of the policy alone; it is not.
    policy = ActionPolicy(**POLICY)
    key = "ed25519:" + "A" * 43
    documented = hashlib.sha256(
        json.dumps(
            {"policy": policy_registry.canonical_policy(policy), "caller_key": key},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    assert policy_registry.policy_id_for(policy, key) == documented
    assert policy_registry.policy_id_for(policy, None) != documented
