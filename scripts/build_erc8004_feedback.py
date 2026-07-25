"""Build an unsigned ERC-8004 feedback transaction from a signed Warden audit record.

Operator entry point for `warden.onchain_attestation`. It only ever writes an
unsigned transaction to a file: it contacts no provider, holds no key, signs
nothing, and broadcasts nothing. Nonce and gas are supplied by the operator from
their own read-only preflight, so this script has no network dependency at all.

Review the emitted JSON, then sign and submit it with your own wallet tooling
following `deploy/X_LAYER_ERC8004.md` — including the mandatory re-check that the
registry's current implementation still matches the pinned selector.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from warden.onchain_attestation import (  # noqa: E402
    REPUTATION_REGISTRY,
    X_LAYER_CHAIN_ID,
    build_feedback_transaction,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "record",
        type=Path,
        help="signed audit attestation record JSON (from /apa/audit/{audit_id})",
    )
    parser.add_argument("output", type=Path, help="path to write the unsigned transaction JSON")
    parser.add_argument(
        "--target-agent-id",
        type=int,
        required=True,
        help="OKX.AI agent id the audit describes (never Warden's own id)",
    )
    parser.add_argument(
        "--sender",
        required=True,
        help="address that will sign; must not be the target's owner or operator",
    )
    parser.add_argument(
        "--attestation-uri",
        required=True,
        help="public URI of the signed record, e.g. https://warden.gudman.xyz/apa/audit/<audit_id>",
    )
    parser.add_argument("--nonce", type=int, required=True, help="sender nonce from your preflight")
    parser.add_argument("--gas", type=int, required=True)
    parser.add_argument("--max-fee-per-gas", type=int, required=True)
    parser.add_argument("--max-priority-fee-per-gas", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    transaction = build_feedback_transaction(
        record,
        target_agent_id=args.target_agent_id,
        sender=args.sender,
        attestation_uri=args.attestation_uri,
        nonce=args.nonce,
        gas=args.gas,
        max_fee_per_gas=args.max_fee_per_gas,
        max_priority_fee_per_gas=args.max_priority_fee_per_gas,
    )
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("refusing to overwrite an existing output path")
    args.output.write_text(
        json.dumps(transaction, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"unsigned transaction written to {args.output}")
    print(f"chain id {X_LAYER_CHAIN_ID}, registry {REPUTATION_REGISTRY}")
    print("nothing was signed or broadcast; review it before submitting")


if __name__ == "__main__":
    main()
