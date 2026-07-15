# Agent Protection Attestation (APA) — Specification v0.1

**Status:** Draft (v0.1) · **License:** Apache-2.0 / CC-BY-4.0 · **First deployment:** Warden on OKX.AI
(agent `#3808`, X Layer) — but this spec is **issuer- and marketplace-neutral**: any registry MAY implement it,
any endpoint MAY serve it, and any party MAY verify an attestation with no account and no callback to the issuer.

APA is a small, open format that lets an autonomous agent service **cryptographically prove that a payload
firewall is live in front of it**, and lets anyone verify that proof **offline**. It is deliberately modeled on
proven, copyable primitives — Sigstore/Rekor (transparency log), in-toto/SLSA (typed predicate), EAS
(issuer-neutral attestation), C2PA (signed claim travels with the subject), and RFC 9116 `security.txt`
(`.well-known` discovery).

> **What APA proves, precisely (read this first — honesty is normative):**
> A valid, fresh attestation proves that *"the host serving `endpoint_host` controls the key `pub`, is running an
> APA-conformant guard, and has counter-signed a monotonic count of payloads screened over the stated window."*
> It does **NOT** prove that every request to that endpoint is routed through the guard. Implementations and
> UIs **MUST NOT** claim more than this. The `scans_24h` counter is the honest measure of real usage.

---

## 1. Terminology

The keywords MUST, MUST NOT, SHOULD, MAY are per RFC 2119.

- **Guarded Endpoint** — an agent service (ASP) that runs an APA-conformant payload firewall and serves a
  Protection Proof. Identified by its origin **`endpoint_host`** (host[:port]).
- **Protector** — the firewall implementation running at the endpoint (e.g. `"warden"`). A `protector` field
  makes the format multi-vendor.
- **Issuer** — a registry that probes a Guarded Endpoint and issues signed Attestations (e.g. Warden). Identified
  by `issuer` and a published Ed25519 **issuer key**.
- **Verifier** — any party (a router agent, another marketplace, a browser) that checks an Attestation. A Verifier
  needs only the format, the issuer's public key, and — optionally — one HTTP GET to re-probe liveness.

## 2. Cryptography & canonicalization

- **Signatures:** Ed25519 (RFC 8032). Two independent layers, never conflated:
  - **Endpoint layer:** the Guarded Endpoint signs its Protection Proof with the endpoint keypair (`pub`/`priv`).
  - **Issuer layer:** the Issuer signs the Attestation record with the issuer keypair.
- **Keys/signatures** are encoded as `base64url` (unpadded), prefixed with the algorithm, e.g.
  `ed25519:PB1n…` and `sig:Q2h5…`. (Hex MAY be accepted on input but base64url is canonical.)
- **Canonicalization** of any signed object: UTF-8 JSON with object keys sorted lexicographically by Unicode
  code point and no insignificant whitespace (`separators = ",",":"`), aligned with RFC 8785 (JCS). Signed cores
  **MUST NOT contain floating-point numbers** (represent quantities as integers or decimal strings) to keep
  canonicalization unambiguous. The signature is computed over the canonical bytes of the object **with the
  `sig` field removed**.

> Reference note: Warden's existing `warden/badges.py::_canonical_json` already implements this JSON
> canonicalization (`sort_keys=True, separators=(",",":"), ensure_ascii=False`); APA reuses it and adds the
> Ed25519 layers.

## 3. Discovery — the Protection Proof endpoint

A Guarded Endpoint MUST serve, over HTTPS:

```
GET /.well-known/agent-protection
```

(Implementations MAY also serve the alias `/.well-known/warden-protected` for the reference deployment.)
The response is a JSON **Protection Proof**:

```json
{
  "spec_version": "apa/0.1",
  "protector":    "warden",
  "endpoint_host":"api.example.com",
  "pub":          "ed25519:PB1n…",
  "ts":           1789200000,
  "nonce":        "9f2c…(≥128-bit base64url)",
  "window_s":     86400,
  "scans_served": 41207,
  "sig":          "sig:Q2h5…"
}
```

Rules:
- `sig` = Ed25519 signature by `priv` over the canonical bytes of the object **without `sig`**. A Verifier
  checks it against `pub`. This binds the key to the live document.
- `ts` is Unix seconds (UTC). A proof is **fresh** iff `now - ts ≤ TTL`. Default TTL = **3600 s (1h)**.
- `nonce` MUST be ≥128 bits, unique per proof; Issuers MUST reject a replayed `nonce` within the TTL window.
- `scans_served` is a **monotonic** count of payloads the guard has screened since process/keypair start (or
  since `window_s` ago if the implementation reports a rolling window). It MUST only increase when `scan()`
  actually runs. This is the number that makes the Attestation an honest usage measure — do not synthesize it.
- The endpoint MUST NOT require authentication to serve this document (it is public and self-authenticating).

## 4. Registration & issuance

An Issuer binds a `pub` to an `endpoint_host` on **first successful proof** (trust-on-first-use):

```
POST /apa/register        { "endpoint": "https://api.example.com" }
```

The Issuer MUST:
1. Validate `endpoint` as a public HTTPS origin (reject private/loopback/link-local/rebinding; `follow_redirects
   = false`; hard timeout ≤3 s; response-size cap). **Never derive identity from a client-supplied `agent_id`;**
   identity is the host that served a valid proof.
2. GET the Protection Proof, verify `sig` against the proof's `pub`, verify freshness + nonce-uniqueness.
3. Record `(endpoint_host → pub)`. If a later proof presents a **different `pub`** for the same host, the Issuer
   MUST mark the attestation `key-changed` (possible key rotation or compromise) rather than silently trusting it.
4. Issue an **Attestation** (§5) and append it to the transparency log (§7).

## 5. The Attestation record

```json
{
  "spec_version":  "apa/0.1",
  "predicate_type":"https://warden.gudman.xyz/spec/protection/v1",
  "attestation_id":"a1b2c3…",
  "issuer":        "warden",
  "protector":     "warden",
  "endpoint_host": "api.example.com",
  "pub":           "ed25519:PB1n…",
  "tier":          "guard-live",
  "status":        "active",
  "scans_24h":     41207,
  "verified_at":   1789200000,
  "expires_at":    1789203600,
  "issuer_sig":    "sig:Zm9v…"
}
```

- `tier` ∈ { `"guard-live"` (a live signed proof), `"audited"` (a passed attack-battery audit — see §8) }.
  There is no bare `"protected"` tier; UIs MUST render `guard-live` honestly (e.g. "Warden Guard Live · N/24h").
- `status` ∈ { `active` (fresh valid proof), `stale` (no fresh proof within TTL), `key-changed`, `revoked`,
  `invalid` }. A UI/SVG MUST render the true current status.
- `scans_24h` is copied from the endpoint's counter; if the counter is unavailable the field MUST be `null`, not 0.
- `issuer_sig` = Ed25519 signature by the issuer key over the canonical record **without `issuer_sig`**.
- `predicate_type` is a URI so the record composes as an in-toto/SLSA predicate if wrapped in a DSSE Statement
  (OPTIONAL interop, §9).

## 6. Verification algorithm (offline)

Given an Attestation and the issuer's public key (fetched once from §7.1):

1. Recompute the canonical bytes without `issuer_sig`; verify `issuer_sig` against the issuer key. Fail → reject.
2. Check `now ≤ expires_at`. If expired, treat as `stale` regardless of stored `status`.
3. (OPTIONAL, stronger) Independently GET `https://{endpoint_host}/.well-known/agent-protection`, verify its
   `sig` against the Attestation's `pub`, and check freshness — this confirms the guard is **still** live without
   trusting the Issuer's stored status.
4. Render exactly what is proven (§ preamble). Never upgrade `guard-live` to "protected/secure".

A conforming **portable verifier** (≤~40 lines, any language) implements steps 1–2 with a single Ed25519 verify
and no network calls. Reference: `warden-guard verify <attestation|endpoint>`.

## 7. Transparency & issuer identity

### 7.1 Issuer key discovery
An Issuer MUST publish its current (and recent, for rotation) verification key at:
```
GET /.well-known/apa-issuer.json   → { "issuer": "...", "keys": [ { "kid": "...", "pub": "ed25519:…", "not_after": ... } ] }
```
(did:web-aligned; a Verifier caches this and needs nothing else to verify offline.)

### 7.2 Append-only transparency log
An Issuer SHOULD publish a hash-chained log of every issuance and status change:
```
GET /apa/log        (paginated JSONL; also downloadable in full)
```
Each entry: `{ seq, ts, event, attestation_id, endpoint_host, status, record_hash, prev_hash }`, where
`prev_hash` = SHA-256 of the previous entry's canonical bytes (genesis `prev_hash` = 64 zero bytes hex). Any
party can fetch the log and confirm it has not been rewritten. This is what lets the ecosystem trust the Issuer
without trusting its database.

## 8. The `audited` tier (optional, ties to endpoint audits)
An Issuer MAY additionally issue an `audited` Attestation after running a published attack battery against the
endpoint (with the endpoint's consent — the proof of consent MUST be included in the signed record as
`consent_verified: true`, and an unconsented audit MUST NOT be issued as `audited`). The `audited` record adds
`grade`, `blocked`, `total`, `battery_version` and is otherwise identical. It is **point-in-time**; UIs MUST say so.

## 9. Extensibility & interop
- **Other protectors / issuers:** the `protector` and `issuer` fields make APA multi-vendor. A different firewall
  MAY serve a conformant Protection Proof; a different registry MAY issue Attestations under its own key.
- **Other marketplaces:** nothing in APA is OKX-specific. `endpoint_host` + Ed25519 make an Attestation portable
  and self-verifying across chains/marketplaces.
- **Supply-chain interop (OPTIONAL):** an Attestation MAY be wrapped in a DSSE envelope as an in-toto Statement
  with `predicateType = predicate_type`, making it consumable by SLSA/Sigstore tooling.

## 10. Security considerations
- **Scope (normative):** see the preamble. APA attests a *live guard + honest scan count*, not per-request
  routing. Do not overclaim.
- **Key theft:** a stolen `priv` lets an attacker serve valid proofs for the victim host. Issuers MUST support
  `POST /apa/revoke` (signed by the current key) and key rotation, and SHOULD surface `key-changed`.
- **TOFU:** first-registration trust is TOFU; the transparency log makes silent re-binding detectable.
- **SSRF/DoS:** issuers MUST apply the §4.1 URL guards and cap concurrent outbound probes.
- **No floats in signed cores** (canonicalization determinism).

## 11. Reference implementation
Warden (`warden/protection.py`, `warden/badges.py`, `sdk/python/warden_guard/proof.py`) is the reference
implementation and first deployment. The reference verifier is `warden-guard verify`. This document is
implementable without reading that code.

---
*APA v0.1 — a small open primitive for a safer agent economy. Deployment #1 is OKX.AI; the standard is for
everyone.*
