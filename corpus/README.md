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

## Over-defence measurement set

`corpus/benign_ops_v1.jsonl` is a 378-row first-party benign corpus used to measure how often
Warden flags text that is not an attack. It is authored by us rather than sampled from
production or ingested from a third party, so it carries no `source_*` or license metadata and
never enters the ingestion workflow above. The scanner does not load it; it is disjoint from
both training files and both held-out files. Run it with `python scripts/measure_benign_fp.py`
and see `docs/BENIGN_OPS_CORPUS.md` for provenance, composition, and the measured result.

## Deterministic adversarial variants

Build offline per-threat-class evaluation packs from `corpus/attacks.jsonl`:

```text
python scripts/build_variant_packs.py build/adversarial-variants
```

The command writes one pack per `ReasonCode` (`PROMPT_INJECTION.json` … `MALICIOUS_LINK.json`)
plus an `index.json` listing every class, its file, its variant count, its contributing training
case IDs, and the SHA-256 of the exact bytes written. Every class file exists on every run, so a
class with no variants is an explicit empty pack rather than a missing file. Each variant carries
its `threat_class`, training source ID, ordered transform chain, source/license metadata, source
`context` and `depth` when present, and payload hash. A variant passes evaluation when the
observed verdict is not `ALLOW` and contains every required source threat class; the source's
exact verdict is not copied because an encoding can legitimately change `SANITIZE` to `BLOCK` or
vice versa.

Both held-out files are exclusion sets only. Their rows and metadata are never copied into a pack.
The command requires Warden's canonical four dataset paths and uses Warden's canonical
training-corpus fingerprint. It rejects any training/held-out overlap across canonicalized
`derive_candidates` closures. It performs no network or model calls.

### Transforms and what actually ships

The generator applies nine transform chains, all of them bounded transformations already reversed
by `warden/scanner/normalize.py`:

| Transform chain | Distinct in output |
| --- | --- |
| `encoding:base64` | yes |
| `encoding:hex` | yes |
| `encoding:percent` | yes |
| `encoding:html-entities` | yes |
| `encoding:x-escape` | yes |
| `case:swap` + `encoding:base64` | yes |
| `whitespace:expand` + `encoding:base64` | yes, except when the source contains no space |
| `unicode:homoglyph` + `encoding:base64` | yes |
| `nesting:json` + `encoding:base64` (twice) | yes |

Deduplication is by the variant's own canonicalized payload, because the engine scans the raw
payload as well as every derived candidate — two encodings of the same source are different
scanner inputs and exercise different decoder branches. `whitespace:expand` is the one chain that
can collapse: expanding spaces in a source that has none reproduces the plain `encoding:base64`
payload exactly, and the duplicate is dropped.

Two further exclusions reduce what ships, and both are deliberate:

- **Sources that are built-in injections.** 16 of the 94 training attacks (all eight
  `CORPUS_MATCH` rows, `role-009`–`role-012`, `web3-004`, `web3-006`, `encoding-004`,
  `encoding-005`) are scanner-equivalent to an entry in `KNOWN_INJECTIONS`, so every variant of
  them is dropped by the built-in-injection guard. `CORPUS_MATCH` therefore ships as an empty
  pack.
- **Encodings the Decoder Wall will not reverse.** `web3-003` and `drain-005` are short and
  digit-heavy, so their single-layer encodings fail `normalize._is_plausible_text` and never
  decode back to the source. The generator refuses to emit a variant whose decoded closure does
  not contain its own training source, so those two contribute only their nested-JSON variant.

At the current corpus that yields **675 variants from 78 of the 94 training attacks**: 75 each for
the five single-layer encodings, 76 each for `case:swap` and `unicode:homoglyph`, 77 for the
nested-JSON chain, and 71 for `whitespace:expand`.

### Consuming the packs

```text
python scripts/evaluate_variant_packs.py build/adversarial-variants
```

The consumer verifies each pack file against its `index.json` digest, then runs the deterministic
detector over every variant and reports per-class detection. It is a **separate evaluation
surface**: it never reads, writes, or re-records the published held-out benchmark
(`scripts/benchmark_recall.py`), and it exits 0 whatever the numbers are, so nothing about it can
pressure the published 87/94 recall figure. Variants are derived from training rows, so their
results are robustness evidence, not held-out generalization evidence.

### CI command

```text
python scripts/verify_variant_packs.py
```

This regenerates every class pack twice into a temporary directory, requires the two runs to be
byte-identical, checks the index digests and class partitioning, and independently re-derives
training/held-out separation from the written packs: no held-out case ID appears in any pack, no
variant payload matches or is scanner-equivalent to a held-out row, every variant decodes back to
its named training source, and every payload digest matches its payload. It writes nothing outside
the temporary directory and exits non-zero on any failure.

Provenance labels:
- `shieldbot-pattern`: cases derived from the copied ShieldBot prompt-injection patterns.
- `owasp-llm01-pattern`: prompt-injection and data-exfiltration phrasing from public LLM01 prompt-injection taxonomies.
- `warden-demo`: Warden's OKX demo-critical payment redirection scenario.
- `warden-custom`: custom A2MCP/tool-result and link-abuse variants from the build brief.
- `bip39`: seed phrase vectors use the bundled BIP-39 English list from `bitcoin/bips`.

The corpus intentionally keeps expected outputs conservative. Non-hard-gate attacks usually return
`SANITIZE`; `DRAIN_ADDRESS` mismatches and seed/private-key exfiltration return `BLOCK`.
