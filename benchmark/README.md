# Warden held-out benchmark

`warden-held-out-v1` is an offline evaluation set. The scanner never loads these files, and the
integrity test rejects any attack payload that exactly overlaps either `corpus/attacks.jsonl` or the
TF-IDF examples in `warden/scanner/patterns.py` after case and whitespace normalization.

## Published result

Measured on 2026-07-16 with the deterministic fast path, using thorough mode only for the two cases
that declare it and with semantic analysis disabled:

- Attack recall: **64.29% (18/28)**
- False-positive rate: **0.00% (0/16)**

An attack counts as detected only when Warden returns `SANITIZE` or `BLOCK` and includes the case's
expected threat class. A benign case counts as a false positive when Warden returns anything other
than `ALLOW`. The exact misses and per-category counts are committed in `results.json`.

This is a small, authored regression benchmark, not a claim about universal production efficacy. In
particular, it currently exposes misses in indirect prompt overrides, novel authorization wording,
hex-encoded instructions, `remit` redirection, XML-shaped tool calls, `transmit` exfiltration, and
`javascript:` links. Those misses remain published rather than being copied into the detector's
training corpus.

Run it from the repository root:

```powershell
python scripts/benchmark_recall.py
python scripts/benchmark_recall.py --json
```

The optional paid semantic runtime has a separate guarded evaluation mode:

```powershell
python scripts/benchmark_recall.py --semantic --json
```

That command requires the complete semantic environment documented in the repository README, forces every
case through paid `thorough` orchestration, and reports an enablement gate. The feature must stay disabled
unless model-backed recall exceeds this 64.29% baseline while the held-out benign set remains at zero false
positives. No model endpoint was called and no semantic after-result is claimed in this repository state.

`tests/test_d4_benchmark.py` reruns the evaluation and requires byte-equivalent JSON data after
parsing, so detector changes must update the published result intentionally.
