# Agent Protection Attestation (APA) — Specification v0.1

**Status:** Draft (v0.1) · **License:** Apache-2.0 / CC-BY-4.0 · **Reference implementation:** Warden
(source-ready; not deployed). This spec is **issuer- and marketplace-neutral**: any registry MAY implement it,
any endpoint MAY serve it, and any party MAY verify an attestation with no account and no callback to the issuer.

APA is a small, open format that lets an autonomous agent service **cryptographically prove that a payload
firewall is live in front of it**, and lets anyone verify that proof **offline**. It is deliberately modeled on
proven, copyable primitives — Sigstore/Rekor (transparency log), in-toto/SLSA (typed predicate), EAS
(issuer-neutral attestation), C2PA (signed claim travels with the subject), and RFC 9116 `security.txt`
(`.well-known` discovery).

> **What APA proves, precisely (read this first — honesty is normative):**
> A valid, fresh attestation proves that _"the host serving `endpoint_host` controls the key `pub`, is running an
> APA-conformant guard, and has signed either an exact rolling count of payloads screened over the stated window
> or an explicit declaration that the exact count is temporarily unavailable."_
> It does **NOT** prove that every request to that endpoint is routed through the guard. Implementations and
> UIs **MUST NOT** claim more than this. A non-null `scans_24h` is the honest measure of real usage; `null` means
> the exact rolling count was unavailable and MUST NOT be rendered as zero.

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
  "protector": "warden",
  "endpoint_host": "api.example.com",
  "pub": "ed25519:PB1n…",
  "ts": 1789200000,
  "nonce": "9f2c…(≥128-bit base64url)",
  "window_s": 86400,
  "window_start": 1789113600,
  "scans_served": 41207,
  "sig": "sig:Q2h5…"
}
```

Rules:

- `sig` = Ed25519 signature by `priv` over the canonical bytes of the object **without `sig`**. A Verifier
  checks it against `pub`. This binds the key to the live document.
- `ts` is Unix seconds (UTC). A proof is **fresh** iff `abs(now - ts) ≤ TTL`. Default TTL = **3600 s
  (1h)**; proofs too far in the future are invalid, not indefinitely fresh.
- `nonce` MUST be ≥128 bits, unique per proof; Issuers MUST reject a replayed `nonce` within the TTL window.
- APA v0.1 uses `window_s = 86400`. `window_start` MUST equal `ts - window_s`.
- `scans_served` MUST be either the non-negative integer count of payloads the guard screened during the
  inclusive rolling interval `[window_start, ts]`, or `null` only while exact coverage of that interval is
  unavailable. For example, migrating lifetime-only state requires a full 24-hour warmup; the field MUST remain
  `null` through `migration_ts + 86400` because that boundary second is still in the inclusive interval. Unknown
  usage MUST NOT be encoded as `0`. An integer count MUST change only after a real scan returns a valid verdict;
  failed, fail-open, or malformed hosted responses MUST NOT increment it. A rolling count can decrease as older
  scans leave the window. Endpoint signatures prevent third-party alteration of the claim; they do not
  independently audit an endpoint owner's local counter state.
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

### 4.1 Explicit endpoint-key rotation

Endpoint-key rotation extends the existing signed revocation request additively:

```json
{
  "attestation_id": "a1b2c3…",
  "ts": 1789200000,
  "nonce": "9f2c…(≥128-bit base64url)",
  "replacement_pub": "ed25519:NEW…",
  "sig": "sig:SIGNED-BY-CURRENT-ENDPOINT-KEY…"
}
```

`replacement_pub` is OPTIONAL. Without it, `POST /apa/revoke` remains a plain revocation. With it, the Issuer
MUST verify that the signed `attestation_id` belongs to the bound `endpoint_host`, verify `sig` against that
host's currently bound endpoint key, require `abs(now - ts) ≤ 3600`, reject a replayed ≥128-bit `nonce`, and
require `replacement_pub` to be exactly one canonical unpadded `ed25519:` 32-byte public key different from the
bound key. The request revokes and issuer-resigns the referenced Attestation and stores the exact replacement as
a **pending authorization**; it does not rebind the host.

A subsequent `POST /apa/register` completes rotation only after a fresh live Protection Proof verifies against
that exact pending key. In one serialized transaction the Issuer MUST then replace the binding, clear both the
pending authorization and `key-changed`, issuer-resign every still-active old-key Attestation to a terminal
status, issue a new `active` Attestation under the current issuer key, and append a reviewable rotation event.
The Warden reference log uses `rotation-authorized` for the signed authorization, `revoked` for other old active
records terminalized during acceptance, and `rotated` for the new active record. A proof from any wrong or
unapproved key MUST remain `key-changed`, MUST preserve the pending authorization, and MUST NOT silently rebind.
Revocation-nonce consumption, pending/bound-key changes, Attestation updates, and log appends MUST commit or
roll back together under concurrent register/revoke requests. The endpoint operator MUST retain the old private
key until registration returns an `active` Attestation whose `pub` is the authorized replacement.

## 5. The Attestation record

```json
{
  "spec_version": "apa/0.1",
  "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
  "attestation_id": "a1b2c3…",
  "issuer": "warden",
  "protector": "warden",
  "endpoint_host": "api.example.com",
  "pub": "ed25519:PB1n…",
  "tier": "guard-live",
  "status": "active",
  "scans_24h": 41207,
  "verified_at": 1789200000,
  "expires_at": 1789203600,
  "issuer_sig": "sig:Zm9v…"
}
```

- `tier` ∈ { `"guard-live"` (a live signed proof), `"audited"` (a passed attack-battery audit — see §8) }.
  There is no bare `"protected"` tier; UIs MUST render `guard-live` honestly (e.g. "Warden Guard Live · N/24h").
- `status` ∈ { `active` (fresh valid proof), `stale` (no fresh proof within TTL), `key-changed`, `revoked`,
  `invalid` }. A UI/SVG MUST render the true current status.
- `scans_24h` is copied only from a valid endpoint proof with `window_s = 86400` and a matching
  `window_start`; if the counter is unavailable the field MUST be `null`, not 0.
- `verified_at` and `expires_at` MUST be non-negative interoperable JSON safe integers, and
  `expires_at` MUST equal `verified_at + 3600`. Verifiers MUST reject any other lifetime even when the
  issuer signature is valid.
- `issuer_sig` = Ed25519 signature by the issuer key over the canonical record **without `issuer_sig`**.
- `predicate_type` is a URI so the record composes as an in-toto/SLSA predicate if wrapped in a DSSE Statement
  (OPTIONAL interop, §9).

## 6. Verification algorithm (offline)

Given an Attestation and the issuer's public-key document (fetched from §7.1), or one explicitly trusted
public key:

1. Validate the complete issuer document. Its top level MUST contain exactly `issuer` and `keys`. Every key
   MUST contain exactly a non-empty `kid`, a canonical Ed25519 `pub`, and a non-negative safe-integer
   `not_after`; decoded public-key bytes and `kid` values MUST be unique. The first key MUST be the current
   key with `not_after = 9007199254740991`. Every following verify-only history key MUST have a finite
   `not_after` below that sentinel and keys MUST be newest-first by descending `not_after`. Malformed or
   duplicate history invalidates the entire document.
2. Select every key for which the Attestation's signed `verified_at <= not_after`, then verify `issuer_sig`
   against those applicable keys. The cutoff is the signed `verified_at`, **not verifier wall-clock time**;
   this keeps an unexpired pre-rotation record verifiable. It does not make backdating by a retained or stolen
   retired key impossible: that key can still sign a record whose `verified_at` is at or before its cutoff.
   The exact one-hour lifetime bounds that exposure, so no such record can remain fresh after
   `not_after + 3600`; verifiers cannot distinguish a forged backdated record during that bounded grace.
   If no applicable key verifies, reject.
3. Check `expires_at == verified_at + 3600`, then check `now ≤ expires_at`. If either check fails, reject;
   an otherwise valid but expired record has effective status `stale` regardless of stored `status`.
4. (OPTIONAL, stronger) Independently GET `https://{endpoint_host}/.well-known/agent-protection`, verify its
   `sig` against the Attestation's `pub`, and check freshness — this confirms the guard is **still** live without
   trusting the Issuer's stored status.
5. Render exactly what is proven (§ preamble). Never upgrade `guard-live` to "protected/secure".

A conforming **portable verifier** (≤~40 lines, any language) implements steps 1–3 with Ed25519 verification
and no network calls. Reference: `warden-guard verify <attestation|endpoint>`.

## 7. Transparency & issuer identity

### 7.1 Issuer key discovery

An Issuer MUST publish its current (and recent, for rotation) verification key at:

```
GET /.well-known/apa-issuer.json   → { "issuer": "...", "keys": [ { "kid": "...", "pub": "ed25519:…", "not_after": ... } ] }
```

(did:web-aligned; a Verifier caches this and needs nothing else to verify offline.) The first entry MUST be the
current signing key with `not_after = 9007199254740991` (the largest interoperable JSON safe integer). Recent
verify-only keys follow in descending `not_after` order, and every history cutoff MUST be finite and below that
sentinel. `not_after` is the latest signed Attestation `verified_at` accepted for that key, not a comparison
against verifier wall-clock time. At rotation the Issuer replaces the retired key's sentinel with the last
`verified_at` signed by that key. The new current private key signs every new, refreshed, or status-updated
record. Rotation history contains public keys only: an Issuer MUST NOT retain or load prior private keys for
verification.

### 7.2 Append-only transparency log

An Issuer SHOULD publish a hash-chained log of every issuance and status change:

```
GET /apa/log        → { "entries": [...], "total": N }
GET /apa/log/checkpoint → { "spec_version": "apa-log/0.1", "issuer": "...", "seq": N,
                            "head_hash": "...", "issued_at": 1789200000, "issuer_sig": "sig:..." }
```

Each entry: `{ seq, ts, event, attestation_id, endpoint_host, status, record_hash, prev_hash }`, where
`prev_hash` = SHA-256 of the previous entry's canonical bytes (genesis `prev_hash` = 64 zero bytes hex). A party
that preserved or independently anchored a prior entry hash can confirm continuity from that checkpoint. The
hash chain alone cannot detect a complete rewrite when the verifier has no independently anchored checkpoint.
The signed checkpoint binds the current sequence and canonical entry hash to the applicable issuer key. The
Warden reference endpoint paginates the ordered JSON log and serves a rendered view only when the request
explicitly accepts `text/html`.

### 7.3 Warden BREAKER evidence extension

The Warden reference implementation additively uses the same issuer key and transparency log for
human-confirmed Gauntlet bypass evidence. A BREAKER certificate has exactly:

```json
{
  "spec_version": "warden-breaker/1",
  "predicate_type": "https://warden.gudman.xyz/spec/gauntlet-breaker/v1",
  "certificate_id": "32 lowercase hex characters",
  "issuer": "warden",
  "award": "WARDEN BREAKER",
  "benchmark_case_id": "gauntlet- plus 16 lowercase hex characters",
  "threat_class": "one implemented Warden reason code",
  "payload_sha256": "64 lowercase hex characters",
  "payload_scope": "human-reviewed-redacted-reproducer",
  "finder": "consented public handle or null",
  "confirmed_at": 1789200000,
  "log_seq": 42,
  "issuer_sig": "sig:..."
}
```

A non-null `finder` contains 1–128 Unicode scalar values and must already be in the issuer's canonical
display form: NFKC-normalized, ASCII-whitespace trimmed, free of format controls and Unicode 15
`Default_Ignorable_Code_Point` values, and limited to printable characters (ordinary U+0020 spaces are
allowed). The issuer applies that normalization before signing. Verifiers validate the signature over the
exact raw certificate, then reject a `finder` that is not already canonical and display the accepted signed
value verbatim.

`issuer_sig` covers the canonical certificate without `issuer_sig`. Verification selects issuer keys using the
signed `confirmed_at` and each key's `not_after`, just as APA Attestations use `verified_at`. BREAKER
certificates are historical evidence and do not expire. The certificate proves that the issuer signed these
review facts and committed their digest to its log; it does not reveal or independently prove the private raw
submission. Human review and the current-scanner recheck are issuer procedures, not facts established by
Ed25519 alone. A non-null `finder` proves only that Warden signed that public credit after its consent
workflow; it does not authenticate ownership of an external handle.

A BREAKER log entry has exactly
`{ seq, ts, event, record_type, certificate_id, benchmark_case_id, record_hash, prev_hash }`, with
`event = "breaker-confirmed"`, `record_type = "breaker-certificate"`, `ts = confirmed_at`, and
`record_hash` equal to SHA-256 of the complete signed certificate's canonical bytes. APA entries retain the
exact §7.2 shape and do not gain a `record_type` field. Verifiers therefore treat the shared log as a strict
tagged union, verify every entry from genesis, verify the signed checkpoint, and require the BREAKER entry at
the certificate's signed `log_seq` to match both IDs and `record_hash`. The Warden browser verifier fails
closed above 10,000 entries to bound client-side request, memory, and DOM work.

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

- **Scope (normative):** see the preamble. APA attests a _live guard + honest scan count_, not per-request
  routing. Do not overclaim.
- **Key theft:** a stolen `priv` lets an attacker serve valid proofs for the victim host. Issuers MUST support
  `POST /apa/revoke` (signed by the current key) and key rotation, and SHOULD surface `key-changed`.
- **Retired issuer keys:** a cutoff does not prevent a retained or stolen retired key from backdating
  `verified_at`. The required one-hour lifetime bounds this to at most a one-hour post-retirement backdating
  grace; verifiers MUST NOT describe rotation as making post-retirement signing impossible.
- **TOFU:** first-registration trust is TOFU. A preserved or independently anchored log checkpoint makes later
  silent re-binding detectable; an unanchored chain cannot expose a complete rewrite.
- **SSRF/DoS:** issuers MUST apply the §4.1 URL guards and cap concurrent outbound probes.
- **No floats in signed cores** (canonicalization determinism).

## 11. Reference implementation

Warden (`warden/protection.py`, `warden/badges.py`, `sdk/python/warden_guard/proof.py`) is the reference
implementation. The Trust Layer routes and deployment units in this repository are source-ready and are not
claimed live. The reference verifier is `warden-guard verify`. This document is implementable without reading
that code.

---

_APA v0.1 — a small open primitive for a safer agent economy._
