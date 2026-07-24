"""Run the no-funds audit-to-hardening-to-improved-audit demo."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SDK_ROOT = ROOT / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from warden import (  # noqa: E402
    api,
    audit_attestations,
    audit_findings,
    badge_store,
    hardening,
    protection_store,
)
from warden.auditor import AgentAuditor  # noqa: E402
from warden.badges import b64u_encode  # noqa: E402
from warden.models import HardenRequest  # noqa: E402
from warden_guard import WardenBlocked, WardenClient  # noqa: E402


@contextmanager
def local_endpoint() -> Iterator[
    tuple[ThreadingHTTPServer, dict[str, WardenClient | None]]
]:
    state: dict[str, WardenClient | None] = {"guard": None}

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


@contextmanager
def isolated_evidence_state(directory: Path) -> Iterator[None]:
    environment = {
        "WARDEN_ISSUER_KEY": b64u_encode(
            Ed25519PrivateKey.generate().private_bytes_raw(),
            "ed25519-seed",
        ),
        "WARDEN_BADGE_SECRET": secrets.token_urlsafe(32),
        "WARDEN_PROTECTION_DB": str(directory / "protection.db"),
    }
    previous_environment = {key: os.environ.get(key) for key in environment}
    previous_badge_store = badge_store._STORE_PATH
    previous_findings_store = audit_findings._STORE_PATH
    os.environ.update(environment)
    badge_store._STORE_PATH = directory / "badges.jsonl"
    audit_findings._STORE_PATH = directory / "findings.jsonl"
    try:
        yield
    finally:
        badge_store._STORE_PATH = previous_badge_store
        audit_findings._STORE_PATH = previous_findings_store
        for key, value in previous_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


async def run_loop() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="warden-hardening-demo-") as temporary:
        with isolated_evidence_state(Path(temporary)), local_endpoint() as endpoint:
            server, state = endpoint
            auditor = AgentAuditor()
            port = int(server.server_address[1])
            target_url = f"http://agent.local:{port}/scan"

            async def validate_local(url: str):
                parsed = urlparse(url)
                return f"http://127.0.0.1:{port}/scan", "agent.local", parsed

            auditor._validate_public_http_url = validate_local
            initial = await auditor.audit(target_url)
            if initial.grade != "F" or initial.badge_record is None:
                raise RuntimeError("weak endpoint did not produce signed grade F")

            pack_response = await api.harden(
                HardenRequest(audit_id=initial.badge_record.audit_id)
            )
            pack = pack_response.model_dump(mode="json")
            if not hardening.verify_pack(pack) or not pack["addressed_classes"]:
                raise RuntimeError("Hardening Pack signature or remediation is invalid")

            state["guard"] = WardenClient(local=True, fail_open=False)
            improved = await auditor.audit(target_url)
            if (
                improved.grade != "A"
                or improved.score <= initial.score
                or improved.badge_record is None
            ):
                raise RuntimeError("hardened endpoint did not produce an improved grade A")

            initial_evidence = protection_store.get_audit_attestation_with_evidence(
                initial.badge_record.audit_id,
                record_validator=audit_attestations.verify_audit_attestation,
            )
            improved_evidence = protection_store.get_audit_attestation_with_evidence(
                improved.badge_record.audit_id,
                record_validator=audit_attestations.verify_audit_attestation,
            )
            stored_pack = protection_store.get_hardening_pack_with_evidence(
                str(pack["pack_id"]),
                record_validator=hardening.verify_pack,
            )
            entries = protection_store.read_log()
            checkpoint = protection_store.read_log_checkpoint()
            evidence_verified = (
                initial_evidence is not None
                and improved_evidence is not None
                and audit_attestations.verify_audit_attestation(
                    initial_evidence["attestation"]
                )
                and audit_attestations.verify_audit_attestation(
                    improved_evidence["attestation"]
                )
                and stored_pack == pack
                and protection_store.verify_log_chain(entries, checkpoint)
            )
            if not evidence_verified:
                raise RuntimeError("signed evidence or transparency chain did not verify")

            return {
                "mode": "local-no-funds",
                "battery": {
                    "id": pack["battery_id"],
                    "version": pack["battery_version"],
                },
                "before": {
                    "audit_id": initial.badge_record.audit_id,
                    "grade": initial.grade,
                    "score": initial.score,
                },
                "hardening_pack": {
                    "pack_id": pack["pack_id"],
                    "addressed_classes": pack["addressed_classes"],
                    "signature_verified": True,
                },
                "enforcement": {
                    "sdk": "WardenClient(local=True, fail_open=False)",
                    "application_policy": "deny-by-default command allowlist",
                },
                "after": {
                    "audit_id": improved.badge_record.audit_id,
                    "grade": improved.grade,
                    "score": improved.score,
                },
                "transparency": {
                    "events": [entry["event"] for entry in entries],
                    "checkpoint_seq": checkpoint["seq"],
                    "chain_verified": True,
                },
                "limitations": pack["limitations"],
            }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a local F -> signed Hardening Pack -> enforcement -> A loop. "
            "No network payment, wallet, third-party endpoint, or submission is used."
        )
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print one-line JSON instead of recording-friendly formatted JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = asyncio.run(run_loop())
    print(
        json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":") if args.compact else None,
            indent=None if args.compact else 2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
