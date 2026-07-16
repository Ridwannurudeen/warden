import json

from warden_guard.apa import sign_document
from warden_guard.cli import verify_endpoint
from warden_guard.keys import load_or_create_key
from warden_guard.proof import protection_proof


def test_cli_endpoint_verifier_rejects_a_redirected_final_url(monkeypatch):
    key = load_or_create_key()
    payload = json.dumps(
        sign_document(protection_proof("api.example.com", key=key), key, sig_field="sig")
    ).encode("utf-8")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self, limit):
            return payload[:limit]

        def geturl(self):
            return "http://127.0.0.1/internal"

    class Opener:
        def open(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr("warden_guard.cli._PROOF_OPENER", Opener())

    ok, message = verify_endpoint("https://api.example.com")

    assert ok is False
    assert "redirect" in message.lower()
