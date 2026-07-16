import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import protection
from warden.badges import b64u_encode, ed25519_sign_record


@pytest.fixture(autouse=True)
def _issuer_environment(monkeypatch):
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )


def _record():
    endpoint_key = Ed25519PrivateKey.generate()
    endpoint_pub = b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519")
    return protection.issue_attestation("guard.example", endpoint_pub, 7)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: record.pop("spec_version"),
        lambda record: record.pop("attestation_id"),
        lambda record: record.update(issuer="another-issuer"),
        lambda record: record.update(protector="another-protector"),
        lambda record: record.update(endpoint_host=""),
        lambda record: record.update(pub="ed25519:not-a-key"),
        lambda record: record.update(tier="protected"),
        lambda record: record.update(status="unsupported"),
        lambda record: record.update(scans_24h=True),
        lambda record: record.update(scans_24h=-1),
        lambda record: record.update(extension_score=0.5),
    ],
)
def test_server_rejects_issuer_signed_nonconforming_attestation(mutation):
    record = _record()
    mutation(record)
    malformed = ed25519_sign_record(record, protection.issuer_private_key(), "issuer_sig")

    assert protection.verify_attestation_record(malformed) is False
    assert protection.effective_status(malformed) == "invalid"


@pytest.mark.parametrize("signature_mutation", [lambda value: value + "=", lambda value: value.replace("sig:", "other:", 1)])
def test_server_rejects_noncanonical_attestation_signature(signature_mutation):
    record = _record()
    record["issuer_sig"] = signature_mutation(str(record["issuer_sig"]))

    assert protection.verify_attestation_record(record) is False
