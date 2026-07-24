from __future__ import annotations

import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden import audit_attestations, onchain_anchor, onchain_attestation, protection
from warden.badges import b64u_encode


def _configure_ephemeral_issuer() -> None:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    os.environ["WARDEN_ISSUER_KEY"] = b64u_encode(seed, "ed25519-seed")


def _anchor_vector(contract_address: str, sender: str) -> dict[str, object]:
    checkpoint = protection.issue_log_checkpoint(
        9,
        "66" * 32,
        issued_at=1_785_000_000,
    )
    transaction = onchain_anchor.build_anchor_transaction(
        checkpoint,
        contract_address=contract_address,
        sender=sender,
        nonce=0,
        gas=90_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=0,
    )
    return {
        "data": transaction["data"],
        "root": f"0x{checkpoint['head_hash']}",
        "seq": checkpoint["seq"],
    }


def _feedback_vector(sender: str) -> dict[str, object]:
    attestation = audit_attestations.issue_audit_attestation(
        audit_id="0123456789abcdef",
        subject="https://agent.example/scan",
        endpoint_host="agent.example",
        battery_id="warden-core-http",
        battery_version="2026-07",
        battery_sha256="a" * 64,
        blocked=20,
        total=20,
        benign_total=3,
        benign_passed=3,
        observed_on="2026-07-24",
        issued_at=1_785_000_000,
        log_seq=1,
    )
    transaction = onchain_attestation.build_feedback_transaction(
        attestation,
        target_agent_id=42,
        sender=sender,
        attestation_uri=(
            "https://warden.gudman.xyz/apa/audit/0123456789abcdef"
        ),
        nonce=0,
        gas=250_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=0,
    )
    return {
        "data": transaction["data"],
        "record_sha256": audit_attestations.record_sha256(attestation),
    }


def main() -> int:
    _configure_ephemeral_issuer()
    mode = sys.argv[1]
    if mode == "anchor" and len(sys.argv) == 4:
        result = _anchor_vector(sys.argv[2], sys.argv[3])
    elif mode == "feedback" and len(sys.argv) == 3:
        result = _feedback_vector(sys.argv[2])
    else:
        raise ValueError("usage: emit_onchain_vector.py anchor <contract> <sender> | feedback <sender>")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
