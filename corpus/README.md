# Warden Corpus

Each JSONL row is a deterministic test vector for `WardenEngine.scan`.

Fields:
- `id`: stable case id.
- `category`: primary `ReasonCode` family.
- `payload`: untrusted content submitted to Warden.
- `expected_verdict`: exact expected verdict.
- `expected_classes`: threat classes that must appear in the verdict.
- `context`: optional scan context, usually `expected_addresses`.
- `depth`: optional scan depth. `CORPUS_MATCH` cases use `thorough` to exercise Layer 3.
- `note`: provenance or scenario label.

Rows promoted from an external dataset additionally carry:
- `source_id`: exact source in `spec/corpus-source-allowlist-v1.json`.
- `source_revision`: immutable 40-hex Git revision.
- `source_path`: exact allowlisted path within the source checkout.
- `source_record_id`: human-reviewed locator for the source record.
- `source_url`: revision-pinned source file URL.
- `source_file_sha256`: digest of the checked-out source file used for review.
- `license_spdx`: all simultaneously applicable SPDX identifiers.
- `license_url`: revision-pinned primary license source.

`corpus/license-manifest.json` is the deterministic per-case projection of this metadata. The
manifest keeps allowlisted third-party cases in `cases`, points recipients to the root
`THIRD-PARTY-NOTICES` file, and records separately consented first-party Gauntlet rows in
`first_party_cases`. First-party rows cite their WARDEN BREAKER certificate, held-out case, consent
digest, rights basis, and second-review time; they are not treated as allowlisted third-party data.

External ingestion is deliberately offline and human-gated. Prepare a JSONL mapping with
`source_path`, `source_record_id`, and `payload`; attack mappings must also contain `category` and
`expected_verdict`. Then run:

```text
python scripts/ingest_corpus.py SOURCE_ID LOCAL_CHECKOUT REVIEW.jsonl attacks \
  --confirm-human-review
```

The command verifies the checkout origin and pinned revision without network access, accepts only
exact allowlisted files, rejects Git LFS pointer files and local source modifications, checks the
candidate batch against both training files, both held-out files, and the built-in injection list,
and atomically promotes into exactly one training dataset.

## Deterministic adversarial variants

Build an offline evaluation pack from `corpus/attacks.jsonl`:

```text
python scripts/build_variant_pack.py build/adversarial-variants.json
```

The generator applies only bounded transformations already reversed by
`warden/scanner/normalize.py`: base64, hex, percent encoding, HTML entities, `\xNN` escapes,
casing, whitespace, homoglyphs, and nested encoded JSON containers. Every emitted row records its
training source ID, ordered transform chain, source/license metadata, source `context` and `depth`
when present, and payload hash. A variant passes evaluation when the observed verdict is not
`ALLOW` and contains every required source threat class; the source's exact verdict is not copied
because an encoding can legitimately change `SANITIZE` to `BLOCK` or vice versa.

Both held-out files are exclusion sets only. Their rows and metadata are never copied into the
pack. The command requires Warden's canonical four dataset paths and uses Warden's canonical
training-corpus fingerprint. It rejects any training/held-out overlap across canonicalized
`derive_candidates` closures. Generated rows are deduplicated by exact scanner-equivalence set and
are dropped when they overlap held-out rows or the built-in injection list. It performs no network
or model calls.

A CI job can prove byte stability without committing generated output:

```bash
python scripts/build_variant_pack.py "$RUNNER_TEMP/variants-a.json"
python scripts/build_variant_pack.py "$RUNNER_TEMP/variants-b.json"
cmp "$RUNNER_TEMP/variants-a.json" "$RUNNER_TEMP/variants-b.json"
```

Provenance labels:
- `shieldbot-pattern`: cases derived from the copied ShieldBot prompt-injection patterns.
- `owasp-llm01-pattern`: prompt-injection and data-exfiltration phrasing from public LLM01 prompt-injection taxonomies.
- `warden-demo`: Warden's OKX demo-critical payment redirection scenario.
- `warden-custom`: custom A2MCP/tool-result and link-abuse variants from the build brief.
- `bip39`: seed phrase vectors use the bundled BIP-39 English list from `bitcoin/bips`.

The corpus intentionally keeps expected outputs conservative. Non-hard-gate attacks usually return
`SANITIZE`; `DRAIN_ADDRESS` mismatches and seed/private-key exfiltration return `BLOCK`.
