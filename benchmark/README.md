# Warden held-out benchmark

`warden-held-out-v1` is an offline evaluation set. The scanner never loads these files, and the
integrity test rejects any attack payload that exactly overlaps either `corpus/attacks.jsonl` or the
TF-IDF examples in `warden/scanner/patterns.py` after case and whitespace normalization.

## Published result

Measured on 2026-07-17 with the deterministic fast path, using thorough mode only for the cases
that declare it and with semantic analysis disabled. The set now includes a held-out evasion
family (`held-evade-*`, 66 cases) covering nested base64/hex/percent/HTML/`\xNN`-encoded
injections and drains, homoglyph-swapped keywords, and zero-width obfuscation, all folded by the
Decoder Wall normalization pre-pass before detection:

- Attack recall: **92.55% (87/94)**
- False-positive rate: **0.00% (0/45)**

An attack counts as detected only when Warden returns `SANITIZE` or `BLOCK` and includes the case's
expected threat class. A benign case counts as a false positive when Warden returns anything other
than `ALLOW`. The exact misses and per-category counts are committed in `results.json`.

This is a small, authored regression benchmark, not a claim about universal production efficacy. In
particular, it currently exposes misses in indirect prompt overrides, a semantic role override, a
corpus paraphrase, `transmit` exfiltration, a bare address without expected-address context, and one
base64-of-hex double-encoding whose intermediate hex blob is deliberately not treated as decodable
text (that same conservatism keeps benign hex blobs at zero false positives). Those misses remain
published rather than being copied into the detector's training corpus.

Run it from the repository root:

```powershell
python scripts/benchmark_recall.py
python scripts/benchmark_recall.py --json
python scripts/benchmark_recall.py --record --json
```

`--record` appends an exact UTC result to `history.jsonl` and atomically refreshes the public
`site/data/evaluation.json` consumed by `/status`. It does not conceal misses or mutate detector inputs.

Human-reviewed Gauntlet candidates enter evaluation only through an operator action:

```powershell
$env:WARDEN_PROTECTION_DB = "C:\path\to\protection.db"
python scripts/review_gauntlet.py CLAIM_ID PROMPT_INJECTION `
  --confirm-human-review `
  --redacted-payload-file .\reviewed-reproducer.txt `
  --credit-handle researcher.example
```

`WARDEN_ISSUER_KEY` must also be present in the operator environment; the command refuses the development-key
fallback. Use `--anonymous` instead of `--credit-handle` when the submitted finder did not consent to public
credit. A supplied handle is self-asserted: the workflow proves Warden recorded the credit after review, not
that the submitter controls an external account.

The reviewer assigns one existing reason code after inspecting the retained candidate, writes a publishable
redacted reproducer, and explicitly confirms the review. The workflow rechecks that exact reproducer against
the current fast scanner and proceeds only while the verdict remains `ALLOW`. It refuses finder credit unless
the same submitted handle carries stored public-credit consent, refuses overlaps with the training corpus or
held-out benign cases, and appends only the redacted reproducer to `held_out_attacks.jsonl`.

The same APA Ed25519 issuer key signs a `WARDEN BREAKER` certificate over the reproducer's SHA-256 digest,
assigned threat class, finder credit or anonymity, confirmation time, benchmark case ID, and transparency-log
position. The certificate and its typed `breaker-confirmed` entry commit atomically with a signed log
checkpoint. Publication remains gated on the claim's final confirmed state, and retries recover without
duplicating the benchmark case, certificate, or log entry.

After promotion, rerun the benchmark, intentionally update the published result, and record the dated
measurement. There is no public confirmation API, no automatic confirmation, and no training-corpus mutation.

The optional paid semantic runtime has a separate guarded evaluation mode:

```powershell
python scripts/benchmark_recall.py --semantic --json
```

That command requires the complete semantic environment documented in the repository README, forces every
case through paid `thorough` orchestration, and reports an enablement gate. The feature must stay disabled
unless model-backed recall exceeds this 92.55% baseline while the held-out benign set remains at zero false
positives.

A semantic-enabled run recorded on 2026-07-16 against the original 28-case set is published separately in
`history.jsonl`: **71.43% recall (20/28)** with **0.00% false positives
(0/16)**. That historical measurement predates both the Decoder Wall pre-pass and the expanded evasion set,
so it is not comparable to the current 94-case deterministic baseline. The deterministic `results.json`
remains the reproducible offline baseline. Repository configuration does not enable the paid semantic
runtime, and reproducing that after-result requires an explicitly configured external model.

`tests/test_d4_benchmark.py` reruns the evaluation and requires byte-equivalent JSON data after
parsing, so detector changes must update the published result intentionally.
