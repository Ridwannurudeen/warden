# X Layer ERC-8004 audit feedback runbook

## Status and source

`warden/onchain_attestation.py` builds and signs transactions offline. It has no broadcast function,
provider URL, funded key, or live transaction. No ERC-8004 feedback was submitted during this build.

The ABI in `REPUTATION_ABI` comes from the official draft
[ERC-8004 specification](https://eips.ethereum.org/EIPS/eip-8004):

```solidity
function giveFeedback(
    uint256 agentId,
    int128 value,
    uint8 valueDecimals,
    string calldata tag1,
    string calldata tag2,
    string calldata endpoint,
    string calldata feedbackURI,
    bytes32 feedbackHash
) external;
```

The X Layer transaction is pinned to chain ID `196` and ReputationRegistry
`0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`. Before signing, independently confirm through
read-only chain and explorer checks that chain ID, proxy address, current implementation, and ABI
still match the reviewed values.

## Evidence encoding

The transaction encodes one signed, consented, fully conclusive Warden endpoint audit:

| ERC-8004 field | Warden value |
| --- | --- |
| `agentId` | The audited third-party ERC-8004 agent ID |
| `value` | `A=5`, `B=4`, `C=3`, `D=2`, `F=1` |
| `valueDecimals` | `0` |
| `tag1` | `security-audit` |
| `tag2` | `sha256:<record_sha256>` |
| `endpoint` | The exact audited subject from the signed record |
| `feedbackURI` | The HTTPS `/apa/audit/<audit_id>` evidence route |
| `feedbackHash` | `bytes32(0)` |

The grade mapping is injective: every Warden grade has one distinct integer and can be recovered
without ambiguity. It is an ordinal grade signal, not the audit's raw blocked-probe percentage.
Consumers should follow `feedbackURI` to inspect the signed counts and limitations.

### SHA-256 versus ERC-8004 `feedbackHash`

The build specification asks for Warden's `record_sha256`, while ERC-8004 defines a nonzero
`feedbackHash` as **Keccak-256 of the complete file referenced by `feedbackURI`**. Those are different
algorithms and different byte commitments. The Warden URI response also wraps the signed attestation
with current status fields, so its full response bytes are not the same object as the canonical
signed record.

The builder therefore does not place SHA-256 into `feedbackHash` or call it an ERC-8004 file hash.
Instead, it stores the explicit `sha256:<hex>` commitment in `tag2` and leaves the optional
`feedbackHash` zero. A verifier fetches the record, verifies its Ed25519 signature, computes
`audit_attestations.record_sha256(attestation)`, and compares that lowercase hex value with `tag2`.
This preserves the required evidence pointer without misrepresenting hash semantics.

## Identity and self-feedback preflight

The signed Warden attestation binds an endpoint, not an ERC-8004 token ID. Before building:

1. Read the target `agentId` registration from the X Layer IdentityRegistry.
2. Confirm its registration file advertises the audited endpoint or satisfies ERC-8004's optional
   endpoint-domain verification procedure.
3. Confirm the transaction sender is not the target agent owner or an approved operator. ERC-8004
   forbids owner/operator self-feedback.
4. Confirm the target is a third party. The builder always rejects Warden agent `3808`.
5. Confirm the audit evidence is consented, conclusive, signature-valid, and the URI returns that
   exact `audit_id`.

These identity and owner/operator checks require current chain state and deliberately remain an
operator preflight; the offline builder never invents a binding from cached marketplace data.

## Build and sign offline

Obtain the sender nonce, gas limit, `maxFeePerGas`, and `maxPriorityFeePerGas` through approved
read-only tooling. Then disconnect networking and create the `LocalAccount` signer outside Warden.
Warden does not load or choose the key.

```python
from pathlib import Path

from warden.onchain_attestation import (
    build_feedback_transaction,
    sign_feedback_transaction,
)

transaction = build_feedback_transaction(
    attestation,
    target_agent_id=<verified third-party agent ID>,
    sender=signer.address,
    attestation_uri="https://warden.gudman.xyz/apa/audit/<audit_id>",
    nonce=<verified nonce>,
    gas=<verified gas limit>,
    max_fee_per_gas=<verified wei amount>,
    max_priority_fee_per_gas=<verified wei amount>,
)
raw_transaction = sign_feedback_transaction(transaction, signer)
Path("<operator-controlled output path>").write_bytes(raw_transaction)
```

The builder uses a provider that rejects every RPC method. It validates the signed audit, agent ID,
sender, evidence URI, transaction fields, registry address, chain, and zero-value boundary. The
signer decodes and canonically re-encodes `giveFeedback` before signing. Neither function can submit
the bytes.

Decode and record all eight arguments before approval. Only after separate explicit user approval
may the operator submit the signed bytes through approved wallet/RPC tooling. If submission status is
uncertain, query the known transaction hash; never blindly send the same feedback again.

## Post-submission verification

Confirm exactly one successful `NewFeedback` event at the expected registry and verify:

- `agentId` is the reviewed third-party ID;
- `clientAddress` is the approved sender;
- `value` and `valueDecimals` decode to the expected Warden grade;
- the `indexedTag1` topic matches `keccak256("security-audit")`;
- the plain `tag1` value is `security-audit`, and `tag2` is the expected `sha256:<record_sha256>`;
- `endpoint` and `feedbackURI` match the signed audit;
- `feedbackHash` is zero.

Retain the transaction hash, block number, feedback index, signed attestation, and calculated
SHA-256 together. The result is public point-in-time feedback, not continuous monitoring or proof of
future safety.

## Cost estimate

Use a read-only gas estimate for the exact populated transaction immediately before approval:

```text
maximum feedback cost in OKB =
    gas_limit * max_fee_per_gas / 1_000_000_000_000_000_000
```

For illustration only, a `250,000` gas ceiling at `1 gwei` is `0.00025 OKB`. This is not measured
X Layer gas usage or a fee promise. The approved wallet should display its current estimate and
maximum cost before the one authorized submission.
