"""Cross-language and static contracts for the independent APA browser verifier."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
FIXTURE = ROOT / "tests" / "fixtures" / "apa_cross_language.json"


def _load_spec_verifier():
    spec = importlib.util.spec_from_file_location(
        "browser_verify_apa", ROOT / "spec" / "verify_apa.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["browser_verify_apa"] = module
    spec.loader.exec_module(module)
    return module


verify_apa = _load_spec_verifier()


def _b64u(raw: bytes, prefix: str) -> str:
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{prefix}:{encoded}"


def _rotation_attestation(private_key: Ed25519PrivateKey) -> dict[str, object]:
    now = int(time.time())
    endpoint_key = Ed25519PrivateKey.generate()
    record = {
        "spec_version": "apa/0.1",
        "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
        "attestation_id": "33333333333333333333333333333333",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": "agent.example",
        "pub": _b64u(endpoint_key.public_key().public_bytes_raw(), "ed25519"),
        "tier": "guard-live",
        "status": "active",
        "scans_24h": 7,
        "verified_at": now - 10,
        "expires_at": now - 10 + 3600,
    }
    record["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(record)), "sig")
    return record


def test_python_generated_fixture_matches_signature_and_reference_oracle(monkeypatch):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"warden-apa-browser-cross-language-fixture-v1").digest()
    )
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = fixture["attestation"]
    core = {key: value for key, value in attestation.items() if key != "issuer_sig"}
    expected_signature = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")

    assert fixture["issuer_document"]["keys"][0]["pub"] == issuer_pub
    assert attestation["issuer_sig"] == expected_signature
    monkeypatch.setattr(verify_apa.time, "time", lambda: 1_784_000_100)
    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)
    assert ok, message


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scans_24h", True),
        ("verified_at", True),
        ("expires_at", True),
        ("tier", "protected"),
    ],
)
def test_reference_oracle_rejects_signed_malformed_attestations(field, value):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"warden-apa-browser-cross-language-fixture-v1").digest()
    )
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = dict(fixture["attestation"])
    attestation[field] = value
    core = {key: item for key, item in attestation.items() if key != "issuer_sig"}
    attestation["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")

    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)

    assert ok is False
    assert "attestation INVALID" in message


def test_reference_oracle_requires_the_scans_24h_field():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"warden-apa-browser-cross-language-fixture-v1").digest()
    )
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = dict(fixture["attestation"])
    attestation.pop("scans_24h")
    core = {key: item for key, item in attestation.items() if key != "issuer_sig"}
    attestation["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")

    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)

    assert ok is False
    assert "scans_24h" in message


def test_reference_oracle_renders_null_scan_count_as_unavailable(monkeypatch):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"warden-apa-browser-cross-language-fixture-v1").digest()
    )
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = dict(fixture["attestation"])
    attestation["scans_24h"] = None
    core = {key: item for key, item in attestation.items() if key != "issuer_sig"}
    attestation["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")
    monkeypatch.setattr(verify_apa.time, "time", lambda: 1_784_000_100)

    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)

    assert ok is True
    assert "unavailable" in message.lower()
    assert "None scans/24h" not in message


def test_reference_oracle_rejects_noncanonical_attestation_lifetime():
    private_key = Ed25519PrivateKey.generate()
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = _rotation_attestation(private_key)
    attestation["expires_at"] = attestation["verified_at"] + 3601
    core = {key: item for key, item in attestation.items() if key != "issuer_sig"}
    attestation["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")

    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)

    assert ok is False
    assert "expires_at" in message


@pytest.mark.parametrize("field", ["pub", "issuer_sig"])
def test_reference_oracle_rejects_noncanonical_attestation_encoding(field):
    private_key = Ed25519PrivateKey.generate()
    issuer_pub = _b64u(private_key.public_key().public_bytes_raw(), "ed25519")
    attestation = _rotation_attestation(private_key)
    attestation[field] = str(attestation[field]) + "="
    if field == "pub":
        core = {key: item for key, item in attestation.items() if key != "issuer_sig"}
        attestation["issuer_sig"] = _b64u(private_key.sign(verify_apa.canonical(core)), "sig")

    ok, message = verify_apa.verify_attestation(attestation, issuer_pub)

    assert ok is False
    assert field in message


def test_reference_oracle_verifies_recent_key_by_attestation_cutoff():
    retired_key = Ed25519PrivateKey.generate()
    current_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(retired_key)
    document = {
        "issuer": "warden",
        "keys": [
            {
                "kid": "current",
                "pub": _b64u(current_key.public_key().public_bytes_raw(), "ed25519"),
                "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS,
            },
            {
                "kid": "retired",
                "pub": _b64u(retired_key.public_key().public_bytes_raw(), "ed25519"),
                "not_after": attestation["verified_at"],
            },
        ],
    }

    ok, message = verify_apa.verify_attestation(attestation, document)

    assert ok, message


def test_reference_oracle_rejects_retired_key_after_signed_cutoff():
    retired_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(retired_key)
    document = {
        "issuer": "warden",
        "keys": [
            {
                "kid": "current",
                "pub": _b64u(
                    Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
                ),
                "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS,
            },
            {
                "kid": "retired",
                "pub": _b64u(retired_key.public_key().public_bytes_raw(), "ed25519"),
                "not_after": attestation["verified_at"] - 1,
            },
        ],
    }

    ok, message = verify_apa.verify_attestation(attestation, document)

    assert ok is False
    assert "signature INVALID" in message


@pytest.mark.parametrize(
    "mutate",
    [
        lambda keys: keys.append({**keys[0], "not_after": 1}),
        lambda keys: keys.append({**keys[0], "kid": "other", "not_after": 1}),
        lambda keys: keys[0].update(not_after=None),
        lambda keys: keys[0].update(not_after=True),
        lambda keys: keys[0].update(pub="ed25519:not-a-key"),
        lambda keys: keys[0].update(extra="unsupported"),
    ],
)
def test_reference_oracle_rejects_duplicate_or_malformed_issuer_history(mutate):
    issuer_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(issuer_key)
    keys = [
        {
            "kid": "current",
            "pub": _b64u(issuer_key.public_key().public_bytes_raw(), "ed25519"),
            "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS,
        }
    ]
    mutate(keys)

    ok, message = verify_apa.verify_attestation(
        attestation,
        {"issuer": "warden", "keys": keys},
    )

    assert ok is False
    assert "issuer document INVALID" in message


@pytest.mark.parametrize(
    "keys",
    [
        lambda current, retired: [{**current, "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS - 1}],
        lambda current, retired: [
            current,
            {**retired, "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS},
        ],
    ],
)
def test_reference_oracle_requires_one_current_sentinel_then_finite_history(keys):
    issuer_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(issuer_key)
    current = {
        "kid": "current",
        "pub": _b64u(issuer_key.public_key().public_bytes_raw(), "ed25519"),
        "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS,
    }
    retired = {
        "kid": "retired",
        "pub": _b64u(Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"),
        "not_after": attestation["verified_at"],
    }

    ok, message = verify_apa.verify_attestation(
        attestation,
        {"issuer": "warden", "keys": keys(current, retired)},
    )

    assert ok is False
    assert "issuer document INVALID" in message


def test_reference_cli_issuer_url_tries_recent_keys(tmp_path, monkeypatch):
    retired_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(retired_key)
    document = {
        "issuer": "warden",
        "keys": [
            {
                "kid": "current",
                "pub": _b64u(
                    Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
                ),
                "not_after": verify_apa.MAX_SAFE_UNIX_SECONDS,
            },
            {
                "kid": "retired",
                "pub": _b64u(retired_key.public_key().public_bytes_raw(), "ed25519"),
                "not_after": attestation["verified_at"],
            },
        ],
    }
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(attestation), encoding="utf-8")

    opener = _IssuerOpener(document)
    monkeypatch.setattr(
        verify_apa.urllib.request,
        "build_opener",
        lambda *handlers: opener,
    )

    assert verify_apa.main([str(path), "--issuer-url", "https://issuer.example"]) == 0
    assert len(opener.calls) == 1


class _IssuerSource(io.BytesIO):
    def __init__(self, payload: dict[str, object], url: str):
        super().__init__(json.dumps(payload).encode())
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def geturl(self):
        return self._url


class _IssuerOpener:
    def __init__(self, payload: dict[str, object], final_url: str | None = None):
        self.payload = payload
        self.final_url = final_url
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return _IssuerSource(self.payload, self.final_url or request.full_url)


def test_reference_issuer_url_uses_exact_https_discovery_source_without_redirects():
    document = {"issuer": "warden", "keys": []}
    opener = _IssuerOpener(document)

    loaded = verify_apa._load_issuer_document_from_url("https://issuer.example/", opener=opener)

    assert loaded == document
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == "https://issuer.example/.well-known/apa-issuer.json"
    assert request.get_method() == "GET"
    assert timeout == 5


@pytest.mark.parametrize(
    "base_url",
    [
        "http://issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example?source=other",
        "https://issuer.example#other",
        "https://issuer.example/nested",
    ],
)
def test_reference_issuer_url_rejects_unclean_or_non_https_bases(base_url):
    opener = _IssuerOpener({"issuer": "warden", "keys": []})

    with pytest.raises(ValueError):
        verify_apa._load_issuer_document_from_url(base_url, opener=opener)

    assert opener.calls == []


def test_reference_issuer_url_rejects_a_changed_or_downgraded_response_url():
    opener = _IssuerOpener(
        {"issuer": "warden", "keys": []},
        final_url="http://issuer.example/.well-known/apa-issuer.json",
    )

    with pytest.raises(ValueError, match="redirect"):
        verify_apa._load_issuer_document_from_url("https://issuer.example", opener=opener)


def test_reference_redirect_handler_refuses_every_redirect():
    request = urllib.request.Request("https://issuer.example/.well-known/apa-issuer.json")

    with pytest.raises(urllib.error.HTTPError, match="redirects are not allowed"):
        verify_apa._NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "http://issuer.example/.well-known/apa-issuer.json",
        )


def test_reference_cli_rejects_issuer_pub_and_url_together(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    attestation = _rotation_attestation(private_key)
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(attestation), encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        verify_apa.main(
            [
                str(path),
                "--issuer-pub",
                _b64u(private_key.public_key().public_bytes_raw(), "ed25519"),
                "--issuer-url",
                "https://issuer.example",
            ]
        )

    assert exc.value.code == 2


def test_verify_page_is_csp_clean_and_exposes_the_independent_crypto_boundary():
    page = (SITE / "verify.html").read_text(encoding="utf-8")
    script = (SITE / "verify.js").read_text(encoding="utf-8")

    assert 'rel="canonical" href="https://warden.gudman.xyz/verify"' in page
    assert "data-apa-verify-form" in page
    assert "data-apa-verify-input" in page
    assert "data-apa-verify-result" in page
    assert '<script src="/verify.js" defer></script>' in page
    assert "WebCrypto Ed25519" in page
    assert "crypto.subtle" in script
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "payload.verified" not in script
    assert "A valid, fresh attestation proves" in script
    assert "endpoint signed that proof" in script
    assert "issuer separately signed the attestation" in script
    assert "does not prove that every request" in script
    assert "counter-signed" not in script
    assert "trust-on-first-use" in script
    assert "stolen endpoint private key" in script
    assert "<style" not in page
    assert " style=" not in page
    assert "<script>" not in page
