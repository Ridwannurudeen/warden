"""A real local audit-to-hardening-to-improved-audit acceptance loop."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import (
    api,
    audit_attestations,
    audit_findings,
    badge_store,
    hardening,
    protection_store,
)
from warden.auditor import AgentAuditor
from warden.badges import b64u_encode
from warden.models import HardenRequest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from warden_guard import WardenBlocked, WardenClient  # noqa: E402


@pytest.fixture
def local_endpoint():
    state: dict[str, object] = {"guard": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/.well-known/warden-consent":
                self._json(200, {"consent": "warden-audit-allowed"})
                return
            self._json(404, {"detail": "not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            payload = str(json.loads(self.rfile.read(length))["payload"])
            guard = state["guard"]
            if guard is None:
                self._json(200, {"verdict": "ALLOW"})
                return
            try:
                guard.guard(payload, depth="thorough")
            except WardenBlocked:
                self._json(200, {"verdict": "BLOCK"})
                return
            # This fixture's documented business contract supports three
            # read-only intents. The hardened boundary combines Warden's local
            # guard with a deny-by-default application allowlist.
            if payload.partition(" ")[0].casefold() not in {
                "summarize",
                "return",
                "confirm",
            }:
                self._json(200, {"verdict": "BLOCK"})
                return
            self._json(200, {"verdict": "ALLOW"})

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


@pytest.mark.asyncio
async def test_local_f_to_harden_to_improved_loop(
    local_endpoint,
    tmp_path,
    monkeypatch,
) -> None:
    server, state = local_endpoint
    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "WARDEN_ISSUER_KEY",
        b64u_encode(issuer_key.private_bytes_raw(), "ed25519-seed"),
    )
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "hardening-loop-test-secret")
    monkeypatch.setenv("WARDEN_PROTECTION_DB", str(tmp_path / "protection.db"))
    monkeypatch.setattr(badge_store, "_STORE_PATH", tmp_path / "badges.jsonl")
    monkeypatch.setattr(audit_findings, "_STORE_PATH", tmp_path / "findings.jsonl")
    auditor = AgentAuditor()
    port = server.server_address[1]
    target_url = f"http://agent.local:{port}/scan"

    async def validate_local(url: str):
        parsed = urlparse(url)
        return f"http://127.0.0.1:{port}/scan", "agent.local", parsed

    monkeypatch.setattr(auditor, "_validate_public_http_url", validate_local)

    initial = await auditor.audit(target_url)
    assert initial.grade == "F"
    assert initial.badge_record is not None
    initial_audit_id = initial.badge_record.audit_id

    pack_response = await api.harden(HardenRequest(audit_id=initial_audit_id))
    pack = pack_response.model_dump()
    assert hardening.verify_pack(pack)
    assert pack["addressed_classes"]
    assert "WardenClient(local=True, fail_open=False)" in pack["integration"]["in_process"]

    state["guard"] = WardenClient(local=True, fail_open=False)
    improved = await auditor.audit(target_url)
    assert improved.badge_record is not None
    assert improved.score > initial.score
    assert improved.grade == "A"

    first_audit = protection_store.get_audit_attestation_with_evidence(
        initial_audit_id,
        record_validator=audit_attestations.verify_audit_attestation,
    )
    second_audit = protection_store.get_audit_attestation_with_evidence(
        improved.badge_record.audit_id,
        record_validator=audit_attestations.verify_audit_attestation,
    )
    stored_pack = protection_store.get_hardening_pack_with_evidence(
        str(pack["pack_id"]),
        record_validator=hardening.verify_pack,
    )
    entries = protection_store.read_log()
    checkpoint = protection_store.read_log_checkpoint()

    assert first_audit is not None
    assert second_audit is not None
    assert audit_attestations.verify_audit_attestation(first_audit["attestation"])
    assert audit_attestations.verify_audit_attestation(second_audit["attestation"])
    assert stored_pack == pack
    assert protection_store.verify_log_chain(entries, checkpoint)
    assert [entry["event"] for entry in entries] == [
        "audit-issued",
        "hardening-pack-issued",
        "audit-issued",
    ]
    assert "does not prove" in str(pack["limitations"])
