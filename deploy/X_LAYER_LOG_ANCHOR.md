# X Layer APA log anchor runbook

## Status and boundary

`contracts/WardenLogAnchor.sol` and `warden/onchain_anchor.py` are source-only. No contract address in
this repository is live, and the build performed no deployment, RPC call, transaction broadcast, or
wallet action.

The contract accepts checkpoint publications only from the immutable constructor `publisher`. Each
publication records:

- a contiguous `anchorIndex`, used to detect omitted publications;
- the strictly increasing APA log `seq`, which may jump when several log entries arrive between
  publications;
- the signed checkpoint `head_hash` as a `bytes32` root.

The publisher is an operational transaction signer. It is not the Warden Ed25519 issuer key, and the
contract never receives or verifies that private signing material.

## Pre-deployment gate

Do not deploy until all of these checks pass:

1. Obtain explicit user approval for the deployment, publisher address, and exact reviewed source.
2. Use an approved Solidity compiler compatible with `pragma solidity ^0.8.24`.
3. Compile `contracts/WardenLogAnchor.sol` and run compiler-level contract tests in that approved
   toolchain.
4. Confirm the destination reports chain ID `196` and is X Layer.
5. Confirm the constructor publisher is a nonzero address controlled independently of the deployment
   key or covered by the operator's documented recovery procedure.
6. Record the compiled bytecode hash, constructor argument, deployment block, transaction hash, and
   resulting address before treating any event as Warden evidence.

This checkout has no `solc`, Foundry, Anvil, Hardhat, or Solidity test dependency. The Python suite
tests the exact ABI, offline transaction construction/signing, and event-chain verification, but it
does not substitute for compiler-level verification.

After deployment, perform read-only checks before the first publication:

- `publisher()` equals the approved publisher;
- `anchorCount()` equals `0`;
- `latestLogSequence()` equals `0`;
- the deployed runtime bytecode matches the reviewed compiled artifact.

## Build and sign one publication offline

First obtain `nonce`, `gas`, `maxFeePerGas`, and `maxPriorityFeePerGas` through the operator's approved
read-only tooling. Then run the following in a network-disabled process. The `signer` must be a
caller-created `eth_account.signers.local.LocalAccount`; Warden does not load a key or choose a wallet.

```python
from pathlib import Path

from warden import protection_store
from warden.onchain_anchor import (
    build_anchor_transaction,
    sign_anchor_transaction,
)

checkpoint = protection_store.read_log_checkpoint_for_external_publish()
transaction = build_anchor_transaction(
    checkpoint,
    contract_address="<deployed WardenLogAnchor address>",
    sender=signer.address,
    nonce=<verified nonce>,
    gas=<verified gas limit>,
    max_fee_per_gas=<verified wei amount>,
    max_priority_fee_per_gas=<verified wei amount>,
)
raw_transaction = sign_anchor_transaction(transaction, signer)
Path("<operator-controlled output path>").write_bytes(raw_transaction)
```

`build_anchor_transaction` verifies the Ed25519 checkpoint, rejects the empty genesis checkpoint, pins
chain ID `196`, transfers zero value, and uses a provider that rejects every RPC method.
`sign_anchor_transaction` verifies the signer, chain, zero-value boundary, and
`anchor(bytes32,uint64)` selector. Neither function can broadcast.

Inspect and record the decoded `root` and `seq`. Only after a separate explicit approval may the
operator submit the signed bytes through approved wallet/RPC tooling. Never retry an uncertain send;
check the transaction hash and receipt first.

## Verify the on-chain lineage

Fetch every `CheckpointAnchored` event from the recorded deployment block, ordered by block number and
log index. Do not start from a later block: verification deliberately requires `anchorIndex == 1` for
the first event so a provider omission is visible.

```python
from web3 import Web3

from warden import protection_store
from warden.onchain_anchor import ANCHOR_ABI, verify_anchor_events

contract = Web3(rpc_provider).eth.contract(
    address="<deployed WardenLogAnchor address>",
    abi=ANCHOR_ABI,
)
events = contract.events.CheckpointAnchored().get_logs(
    from_block=<recorded deployment block>,
    to_block="latest",
)
verified = verify_anchor_events(events, protection_store.read_log())
```

Persist at least one returned `AnchorEvent(anchor_index, seq, root)` outside Warden's operator
boundary. Pass it as `retained_anchor=` on later verification. The verifier rejects:

- a missing or noncontiguous publication index;
- a non-increasing APA sequence;
- an event beyond the available local log;
- a root that does not match the canonical APA prefix;
- a history that omits the retained anchor.

These checks detect local log rewriting and truncation relative to a retained on-chain publication.

## Cost estimate

Use the network's read-only gas estimate immediately before approval:

```text
maximum anchor cost in OKB =
    gas_limit * max_fee_per_gas / 1_000_000_000_000_000_000
```

For illustration only, a `90,000` gas ceiling at `1 gwei` is `0.00009 OKB`. That is not a measured
X Layer fee or a promise of actual gas use. Deployment cost is:

```text
estimated deployment gas * max_fee_per_gas / 1e18 OKB
```

No numeric deployment estimate is claimed until the approved compiler artifact exists and the
operator obtains a read-only estimate for its exact constructor transaction.

## Rollback

On-chain events cannot be removed. If the publisher or deployment is wrong, stop publishing, retain
the faulty address and events as evidence, deploy a reviewed replacement only after new approval, and
publish the superseding address plus deployment block. Never describe a replacement as erasing the
prior chain.
