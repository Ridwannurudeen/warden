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
manifest points recipients to the root `THIRD-PARTY-NOTICES` file.

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

Provenance labels:
- `shieldbot-pattern`: cases derived from the copied ShieldBot prompt-injection patterns.
- `owasp-llm01-pattern`: prompt-injection and data-exfiltration phrasing from public LLM01 prompt-injection taxonomies.
- `warden-demo`: Warden's OKX demo-critical payment redirection scenario.
- `warden-custom`: custom A2MCP/tool-result and link-abuse variants from the build brief.
- `bip39`: seed phrase vectors use the bundled BIP-39 English list from `bitcoin/bips`.

The corpus intentionally keeps expected outputs conservative. Non-hard-gate attacks usually return
`SANITIZE`; `DRAIN_ADDRESS` mismatches and seed/private-key exfiltration return `BLOCK`.
