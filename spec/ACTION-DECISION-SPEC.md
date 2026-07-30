# Warden Action Decision Receipt — `warden-action-receipt/2`

Predicate type: `https://warden.gudman.xyz/spec/action-decision/v1`

A decision receipt is a signed, metadata-only record of one pre-action decision made by
`POST /api/action/guard`. This document exists so a receipt can be verified by a third party with
no access to Warden and no trust in it.

## What a receipt does and does not establish

**It establishes** that this issuer, at `issued_at`, evaluated an action whose context hashes to
`action_context_sha256`, against a policy hashing to `policy_sha256`, over a payload hashing to
`payload_sha256`, and returned `decision` with `reason_codes`.

**It does not establish**, and the signed `limitations` string says so:

- that the action was executed, delivered, settled, or authorized;
- that the caller obeyed the decision;
- that the payload or the agent is safe in general.

Three further limits are properties of the current design rather than of any one receipt, and a
verifier should treat them as load-bearing:

1. **The policy is caller-supplied inline on each request.** A receipt records the policy that was
   *asserted at call time*. It is not evidence that the policy was in force beforehand. The same
   intent submitted under a laxer policy yields a different, equally valid receipt.
2. **The route is unauthenticated.** A receipt does not prove which agent requested it. `agent_id`
   and `service_id` are values the caller supplied.
3. **Action receipts are not written to the transparency log.** There is no proof of absence: a
   verifier cannot tell how many decisions preceded the one being shown.

Consequently a receipt is sound evidence of *what Warden decided given stated inputs*, and is not
by itself sufficient for a third party adjudicating a dispute between two parties. Pre-registered
policies bound to a `policy_id` anchored in the transparency log, plus caller binding, are required
for that, and are not implemented.

## Verifying a receipt

1. Fetch the issuer keys from `/.well-known/apa-issuer.json`. Each entry has `kid`, `pub`
   (`ed25519:` + unpadded base64url), and `not_after`.
2. Remove `issuer_sig` from the record. Serialize the remainder as canonical JSON: keys sorted
   lexicographically, `separators=(",", ":")`, UTF-8, no trailing newline. This is the same
   canonicalisation used throughout [APA-SPEC.md](APA-SPEC.md).
3. Verify the Ed25519 signature in `issuer_sig` (also `ed25519:` + unpadded base64url) over those
   bytes, using a key whose `not_after` has not passed.
4. Independently recompute `receipt_id`: canonical JSON of the record minus **both** `receipt_id`
   and `issuer_sig`, then SHA-256. A receipt whose id does not reproduce is invalid even if the
   signature verifies.

Altering any field — flipping `BLOCK` to `ALLOW`, widening a limit — breaks step 3.

## Fields

| Field | Meaning |
| --- | --- |
| `spec_version` | `warden-action-receipt/2` |
| `predicate_type` | This document's URL |
| `receipt_id` | SHA-256 over the content fields, per step 4 |
| `issuer` | `warden` |
| `network` | CAIP-2 chain, `eip155:196` |
| `agent_id`, `service_id`, `service_revision_sha256` | Caller-supplied task identity; not authenticated |
| `task_id_sha256` | SHA-256 of the caller's task id; the raw id is never published |
| `action_type` | `transfer`, `contract_call`, or `tool_call` |
| `action_context_sha256` | SHA-256 of the canonical action context, `warden-action-context/2` |
| `policy_sha256` | SHA-256 of the canonical policy |
| `payload_sha256` | SHA-256 of the submitted payload; the payload itself is never stored |
| `effective_payload_sha256` | Hash of the text the caller should act on, or `null` on `BLOCK` |
| `decision` | `ALLOW`, `SANITIZE`, or `BLOCK` |
| `reason_codes` | Ordered, deduplicated; see below |
| `issued_at` | Unix seconds, set by the server, not the caller |
| `limitations` | The signed limitations string |
| `issuer_sig` | Ed25519 signature over the canonical content |

## Canonical action context (`warden-action-context/2`)

```json
{"spec_version":"warden-action-context/2",
 "task":{"network":…,"agent_id":…,"service_id":…,"service_revision_sha256":…,"task_id_sha256":…},
 "action":{"action_type":…,"tool":…,"destination_sha256":…,"asset":…,"amount_atomic":…,
           "selector":…,"payload_sha256":…}}
```

`destination_sha256` hashes the **normalized** destination: an EVM address (`0x` + 40 hex) is
lowercased first, so the same address expressed checksummed or lowercase produces one hash. Other
destination forms are hashed as given. `selector` is the 4-byte function selector for a
`contract_call`, or `null`.

## Reason codes

Content findings: `PROMPT_INJECTION`, `ROLE_OVERRIDE`, `WEB3_INJECTION`, `HIDDEN_UNICODE`,
`ENCODING_TRICK`, `STATISTICAL_ANOMALY`, `CORPUS_MATCH`, `DRAIN_ADDRESS`, `TOOL_HIJACK`,
`SECRET_EXFIL`, `MALICIOUS_LINK`, `PAYLOAD_SANITIZED`, `PAYLOAD_BLOCKED`.

Policy findings: `ACTION_NOT_ALLOWED`, `TOOL_NOT_ALLOWED`, `DESTINATION_NOT_ALLOWED`,
`ASSET_NOT_ALLOWED`, `AMOUNT_LIMIT_EXCEEDED`, `SELECTOR_NOT_ALLOWED`.

A policy finding blocks on its own: an action outside the caller's stated rules is refused even
when no detector fires.

## Fail-closed behaviour

- A `SANITIZE` whose sanitized text is byte-identical to the input becomes `BLOCK`.
- Any verdict outside `ALLOW`/`SANITIZE`/`BLOCK` becomes `BLOCK`.
- A `contract_call` whose `selector` is absent, or absent from `allowed_selectors`, is refused.
  An unstated selector cannot be policed, and an amount limit does not help: `approve(spender, MAX)`
  grants away a balance while moving no value.
