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

Provenance labels:
- `shieldbot-pattern`: cases derived from the copied ShieldBot prompt-injection patterns.
- `owasp-llm01-pattern`: prompt-injection and data-exfiltration phrasing from public LLM01 prompt-injection taxonomies.
- `warden-demo`: Warden's OKX demo-critical payment redirection scenario.
- `warden-custom`: custom A2MCP/tool-result and link-abuse variants from the build brief.
- `bip39`: seed phrase vectors use the bundled BIP-39 English list from `bitcoin/bips`.

The corpus intentionally keeps expected outputs conservative. Non-hard-gate attacks usually return
`SANITIZE`; `DRAIN_ADDRESS` mismatches and seed/private-key exfiltration return `BLOCK`.
