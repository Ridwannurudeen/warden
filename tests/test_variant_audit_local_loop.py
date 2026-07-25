"""A real adversarial variant audit against a live consented endpoint on loopback.

Every other variant-audit test stubs the transport. This one opens a socket: a real
`ThreadingHTTPServer` publishes the consent marker, real `httpx` requests carry real
encoded attack payloads over the wire, and the report is signed from what actually
came back. It is the only test that proves the paid `/variant-audit` path works end to
end rather than proving that the stub does.

The SSRF guard is not weakened. `_validate_public_http_url` is substituted at the same
boundary `tests/test_hardening_loop.py` substitutes it: the resolver step is replaced
with a fixed loopback pin, and every later hop — consent, Host header, redirect policy,
response bounds — runs the production code path.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.auditor import AgentAuditor
from warden.badges import b64u_encode
from warden.variant_audit import REPORT_FIELDS, run_variant_audit, verify_report

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from warden_guard import WardenBlocked, WardenClient  # noqa: E402

CONSENT_PATH = "/.well-known/warden-consent"
CONSENT_MARKER = "warden-audit-allowed"


@pytest.fixture
def consented_endpoint():
    """A consenting endpoint whose defence is swapped between runs.

    With `guard` unset it is deliberately weak: it refuses only payloads that spell an
    attack out in plain English, which is exactly what an encoded variant does not do.
    """
    state: dict[str, object] = {"guard": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == CONSENT_PATH:
                self._json(200, {"consent": CONSENT_MARKER})
                return
            self._json(404, {"detail": "not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            payload = str(json.loads(self.rfile.read(length))["payload"])
            guard = state["guard"]
            if guard is None:
                blocked = "ignore all previous instructions" in payload.casefold()
            else:
                try:
                    guard.guard(payload, depth="thorough")
                except WardenBlocked:
                    blocked = True
                else:
                    blocked = False
            self._json(200, {"verdict": "BLOCK" if blocked else "ALLOW"})

        def _json(self, status: int, body: dict[str, object]) -> None:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.fixture
def pinned_to_loopback(consented_endpoint, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the audit to the local server and return the target URL."""
    server, _state = consented_endpoint
    port = server.server_address[1]

    async def _validate_public_http_url(self: AgentAuditor, target_url: str):
        return f"http://127.0.0.1:{port}/scan", "agent.local", urlparse(target_url)

    monkeypatch.setattr(AgentAuditor, "_validate_public_http_url", _validate_public_http_url)
    return f"http://agent.local:{port}/scan"


@pytest.fixture(autouse=True)
def _issuer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.delenv("WARDEN_ISSUER_HISTORY", raising=False)
    monkeypatch.delenv("WARDEN_REQUIRE_CONSENT", raising=False)
    monkeypatch.delenv("WARDEN_ENVIRONMENT", raising=False)


async def test_live_variant_audit_separates_a_weak_endpoint_from_a_guarded_one(
    consented_endpoint,
    pinned_to_loopback: str,
) -> None:
    _server, state = consented_endpoint

    weak = await run_variant_audit(pinned_to_loopback, max_variants_per_class=2)

    assert verify_report(dict(weak)) is True
    assert set(weak) == REPORT_FIELDS
    assert weak["target_host"] == "agent.local"
    assert weak["consent_verified"] is True
    # A live run answers every probe: nothing timed out and nothing was unreachable.
    assert int(weak["totals"]["inconclusive"]) == 0
    assert int(weak["totals"]["conclusive"]) == int(weak["totals"]["variants_sent"]) == 20
    assert int(weak["totals"]["threat_classes"]) == 10
    # Substring matching on English text catches none of the encoded variants.
    assert float(weak["totals"]["detection_rate"]) == 0.0
    assert all(int(entry["detected"]) == 0 for entry in weak["per_class"])

    state["guard"] = WardenClient(local=True, fail_open=False)
    guarded = await run_variant_audit(pinned_to_loopback, max_variants_per_class=2)

    assert verify_report(dict(guarded)) is True
    assert int(guarded["totals"]["inconclusive"]) == 0
    assert float(guarded["totals"]["detection_rate"]) > float(weak["totals"]["detection_rate"])
    assert int(guarded["totals"]["detected"]) > 0
    # Same probes, same caps, same corpus: only the endpoint's behaviour moved.
    assert guarded["caps"] == weak["caps"]
    assert guarded["corpus_fingerprint"] == weak["corpus_fingerprint"]
    assert guarded["target_host"] == weak["target_host"]
    assert guarded["report_id"] != weak["report_id"]


async def test_live_variant_audit_report_survives_a_round_trip_and_fails_when_edited(
    pinned_to_loopback: str,
) -> None:
    """A buyer's copy of a real report verifies, and an edited copy does not."""
    report = await run_variant_audit(
        pinned_to_loopback,
        threat_classes=("DRAIN_ADDRESS", "SECRET_EXFIL"),
        max_variants_per_class=3,
    )

    delivered = json.loads(json.dumps(report, ensure_ascii=False))
    assert delivered == report
    assert verify_report(delivered) is True

    inflated = json.loads(json.dumps(report, ensure_ascii=False))
    inflated["per_class"][0]["detected"] = int(inflated["per_class"][0]["total"])
    assert verify_report(inflated) is False


async def test_live_variant_audit_refuses_an_endpoint_that_withdraws_consent(
    consented_endpoint,
    pinned_to_loopback: str,
) -> None:
    """Consent is fetched over the wire, so withdrawing the marker stops the battery."""
    server, _state = consented_endpoint
    server.RequestHandlerClass.do_GET = lambda self: self._json(404, {"detail": "gone"})

    with pytest.raises(ValueError, match="did not pass consent check"):
        await run_variant_audit(pinned_to_loopback, max_variants_per_class=1)
