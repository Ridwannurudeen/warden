"""Registered policies, so a receipt can cite one instead of asserting it.

Covers the two structural findings from the 2026-07-30 external review: policy
shopping (a caller could assert any policy inline) and caller binding (a receipt
could not show who asked).
"""

from __future__ import annotations

import hashlib
import tempfile
from unittest import mock
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from warden import evidence_store, policy_registry
from warden.action_guard import action_context_sha256, verify_decision_receipt
from warden.badges import b64u_encode, ed25519_sign_record
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
    monkeypatch.setenv(
        "WARDEN_PROTECTION_DB", str(Path(tempfile.mkdtemp()) / "registry.db")
    )


@pytest.fixture()
def client() -> TestClient:
    from warden.api import app

    return TestClient(app)


def _caller_signature(private_key: Ed25519PrivateKey, policy_id: str, intent: dict) -> str:
    context = action_context_sha256(ActionIntent(**intent), OkxTaskContext(**TASK))
    payload = policy_registry.caller_binding_payload(policy_id, context)
    signed = ed25519_sign_record(
        {"payload_sha256": hashlib.sha256(payload).hexdigest()}, private_key, "caller_sig"
    )
    return str(signed["caller_sig"])


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

    # The signature covers the action context, so it cannot authorize a larger payment.
    replayed = client.post(
        "/api/action/guard",
        json={
            "intent": {**INTENT, "amount_atomic": 999},
            "task": TASK,
            "policy_id": policy_id,
            "caller_sig": signature,
        },
    ).json()
    assert replayed["receipt"]["caller_verified"] is False

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
    ).json()

    assert result["receipt"]["caller_verified"] is False


def test_an_unknown_policy_id_is_refused_rather_than_defaulted(client: TestClient):
    response = client.post(
        "/api/action/guard", json={"intent": INTENT, "task": TASK, "policy_id": "b" * 64}
    )

    assert response.status_code == 404


def test_a_request_must_name_exactly_one_policy_source(client: TestClient):
    assert client.post("/api/action/guard", json={"intent": INTENT, "task": TASK}).status_code == 422
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
    one = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": key_one}
    ).json()
    two = client.post(
        "/api/policy/register", json={"policy": POLICY, "caller_key": key_two}
    ).json()

    assert len({unkeyed["policy_id"], one["policy_id"], two["policy_id"]}) == 3
    assert one["record"]["caller_key"] == key_one
    assert two["record"]["caller_key"] == key_two

    # And each key still only authorizes its own registration.
    signature = _caller_signature(first, one["policy_id"], INTENT)
    mine = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": one["policy_id"], "caller_sig": signature},
    ).json()
    assert mine["receipt"]["caller_verified"] is True

    theirs = client.post(
        "/api/action/guard",
        json={"intent": INTENT, "task": TASK, "policy_id": two["policy_id"], "caller_sig": signature},
    ).json()
    assert theirs["receipt"]["caller_verified"] is False
