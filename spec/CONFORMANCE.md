# APA v0.1 conformance

This pack turns the normative APA wire formats into independently runnable checks. It contains strict JSON
Schemas for the Protection Proof, issuer document, guard-live and audited attestations, mixed transparency-log
entries, signed checkpoints, and WARDEN BREAKER certificates. Frozen vectors cover a valid record, expiry,
revocation, one-byte-equivalent field tampering, endpoint proof verification, issuer discovery, chain
continuity, checkpoint binding, and BREAKER evidence.

Install the two verifier dependencies and run:

```bash
python -m pip install cryptography jsonschema
python spec/run_conformance.py
```

A conforming implementation must also follow the semantic rules in `APA-SPEC.md`; JSON Schema cannot express
key-history ordering, `expires_at == verified_at + 3600`, signature verification, hash-chain continuity,
Unicode canonicalization, or the difference between a valid signature and a current claim. The runner checks
those rules represented by the frozen vectors.

Passing this pack establishes wire-format and cryptographic interoperability for the tested cases. It does not certify endpoint safety, prove that every request traversed a guard, authenticate an issuer key's provenance, or turn a point-in-time audit into a security guarantee.

The existing `tests/fixtures/apa_cross_language.json` remains unchanged as a canonicalization compatibility
fixture. The stricter profile in this directory is the normative adopter target for new APA v0.1 records.
