# Warden held-out benchmark

`warden-held-out-v1` is an offline evaluation set. The scanner never loads these files, and the
integrity test rejects any attack payload that exactly overlaps either `corpus/attacks.jsonl` or the
TF-IDF examples in `warden/scanner/patterns.py` after case and whitespace normalization.

## Published result

Measured on 2026-07-26 with semantic analysis disabled. The set includes a held-out evasion
family (`held-evade-*`, 66 cases) covering nested base64/hex/percent/HTML/`\xNN`-encoded
injections and drains, homoglyph-swapped keywords, and zero-width obfuscation, all folded by the
Decoder Wall normalization pre-pass before detection.

`depth` is a caller-controlled request field (`warden/models.py`), so a single headline number
would hide the depth a paying buyer actually selects. Every figure is therefore reported per
depth, and `results.json` carries a `per_depth` block.

Headline, using each case's declared depth (attacks 92 fast + 2 thorough; benign 45 fast):

- Attack recall: **100% (94/94)** — the set is **saturated**; read the caveats below before
  quoting this number
- False-positive rate: **0.00% (0/45)**

Forcing every case to one depth instead:

| depth | attack recall | false positives | FP rate | Wilson 95% CI for the FP rate |
| --- | --- | --- | --- | --- |
| `fast` | 100% (94/94) | 0/45 | 0.00% | 0.00% – 7.87% |
| `thorough` | 100% (94/94) | 1/45 | 2.22% | 0.39% – 11.57% |

A saturated authored benchmark is a weaker claim than a benchmark with published misses: it can
no longer measure progress, and every one of the eight formerly published misses was closed by
error analysis against this file's own miss list, so the held-out set is **no longer blind** for
any of them. 94/94 at n=94 is a Wilson 95% lower bound of roughly 96%, on an English-only,
first-party-authored set whose composition is 68% obfuscation handling. The honest reading is
"the detector now covers every failure mode this set encodes", not "the detector catches
everything". The next real number requires a fresh sealed set assembled away from deadline
pressure, and this file commits to publishing that set's *first* result, whatever it is.

The single `thorough` false positive is `held-benign-enc-016`, ordinary developer code containing
`base64.b64decode(...)`, which scores 0.6477 TF-IDF cosine similarity against the injection corpus
and returns `SANITIZE`. Zero *observed* false positives at `fast` is not a zero rate: with n=45 the
Wilson upper bound is still 7.87%, so the honest claim is a bound, not certainty.

Recall is identical at both depths, so on this set Layer 3 buys no additional detection and costs
one false positive. That is published rather than hidden. Both former `CORPUS_MATCH`-labeled cases
are now caught at Layer 1 by the nullification frames described below, which Layer 3 was never able
to separate: the best genuine corpus-paraphrase attack scores 0.5353 TF-IDF similarity while the
calibration benign maximum is 0.5831, so no threshold detects the attack and keeps benign clean.

An attack counts as detected only when Warden returns `SANITIZE` or `BLOCK` and includes the case's
expected threat class. A benign case counts as a false positive when Warden returns anything other
than `ALLOW`. Per-category counts are committed in `results.json`.

**Relabeling disclosure (2026-07-26):** `held-corpus-001` and `held-corpus-002` were relabeled
`CORPUS_MATCH` → `PROMPT_INJECTION` (payloads byte-identical, IDs unchanged, pinned content hash
updated deliberately). The `category` field holds threat classes everywhere else in the set;
`CORPUS_MATCH` named the detection *mechanism* expected to catch those rows, and under the strict
counting rule above it would have reported payloads the engine sanitizes as misses — a statement
about internal routing, not about buyer-visible behavior. Both payloads carry instruction-override
intent, which is what `PROMPT_INJECTION` labels. This relabeling happened in the same change that
made the cases detectable, and is disclosed for exactly that reason.

This is a small, authored regression benchmark, not a claim about universal production efficacy.
The benchmark is also **English-only** and its composition is lopsided — 48 of 94 cases are
`ENCODING_TRICK` and 16 are `HIDDEN_UNICODE`, so 68% of it exercises obfuscation handling, while the
categories a buyer is most likely to care about carry a handful of cases each. Read the
per-category table in `results.json`, not the headline. See `docs/DETECTION_LANGUAGE_SCOPE.md` for
the measured non-English gap.

## Layer 3 threshold provenance

`SIMILARITY_THRESHOLD` in `warden/scanner/patterns.py` is derived **only** from
`benchmark/calibration_benign.jsonl`: 60 first-party benign rows (JSON-RPC responses, ERC-20 token
metadata, contract descriptions, ops runbook text, and text that merely *discusses* prompt
injection) authored for calibration and disjoint from both held-out files and the training corpus.
Measured over that split: max **0.5831**, p95 0.3939, mean 0.2785, with the maximum at
`calib-benign-discuss-004`. The rule is the smallest two-decimal value strictly above the
calibration maximum, giving **0.59** — zero false positives on the calibration split, with a thin
0.0069 margin.

The previous `0.52` was tuned against held-out benchmark scores, which breaks the held-out
invariant, and its quoted 0.506 benign peak was also stale (the held-out benign maximum is 0.6477).
Honest calibration costs one case: 0.59 exceeds `held-corpus-001`'s 0.5353, so recall fell from the
previously published 92.55% (87/94) to 91.49% (86/94), before the capability work described below
raised it to 94.68% (89/94) and then to the saturated 100% (94/94). On this data the calibration benign maximum
(0.5831) sits *above* the best genuine corpus-match attack score (0.5353), so no threshold both
detects that case and keeps the calibration split clean; the earlier number depended on the leak.
Do not re-tune this constant against `benchmark/held_out_*.jsonl`.

## How saturation was reached, and what that costs the number

All eight formerly published misses were closed deliberately, in two rounds, and the method
matters more than the result. Each was a real capability gap rather than a missing string.

Round one (2026-07-25) closed three:

- `held-drain-002` — a genuine EVM address under a payment instruction whose verb (`remit`) was
  absent from the transfer-intent family. Closed by adding the **payments verb class**, split by
  polysemy: verbs with no non-financial reading are matched bare, while polysemous ones
  (`settle`, `sweep`, `release`) fire only behind a structural destination requirement, so
  "settle the open review comments" stays clean.
- `held-secret-002` — a credential under an outbound verb aimed at an external party. Closed by
  modelling the **external-recipient sink class** (an externality qualifier plus a recipient noun)
  and the OAuth 2.0 / OIDC token objects, which also fixed a real incoherence where `access key`
  was sensitive but `access token` was not.
- `held-evade-mix-003` — base64 of hex of English. The recursion was never the problem: the hex
  layer has a 7.8% letter ratio against the 40% plausibility floor, so the first hop was discarded
  before it could enter the frontier. Closed by carrying **transit layers** — a decoding that is
  nothing except another encoding — one hop further under their own budget, without raising any
  existing bound and without consuming candidate budget.

Round two (2026-07-26) closed the remaining five. All five shared one semantic frame — nullify a
prior authority, then direct the outcome — previously described here as "semantic paraphrase
carrying no trigger vocabulary". That description was half right: the individual *words* carried
no triggers, but the *grammar* was fixed, and grammar is patternable without memorizing sentences.
Three general mechanisms in `warden/scanner/patterns.py`:

- the **dismissal frame** — a dismissal predicate (`consider`/`treat`/`regard`/`deem`/`mark`)
  applied to a protection noun (`instructions`, `guardrails`, `safety warnings`, `review
  conditions`, …) with a voiding complement (`irrelevant`, `obsolete`, `as already resolved`),
  followed by the proceed imperative it clears the way for. Completion verbs are deliberately not
  dismissal predicates, so "the compliance review passed, so the remaining approvals are
  procedural" stays clean, and the continuation verbs are execution/approval verbs, not ticket
  hygiene, so "treat the deprecation warnings as known issues and rerun the suite" stays clean.
- the **nullification frame** — a protection noun as subject of `no longer
  matters/applies/holds/binds`, again followed by a proceed imperative ("…; continue the
  settlement"), with the same benign exclusions ("your previous badge no longer works; continue
  to reception" does not name a protection noun).
- the **supersession frame** — `this note/message/memo now controls/governs/supersedes` an
  authority object (`the decision`, `your instructions`). The required `now` and the authority
  object keep document-versioning English ("this document supersedes the previous version") out.
- plus one verb-phrase gap in the existing role-override class: `assume the identity/role/persona
  of` + the existing agent-persona noun class, which already carried `unrestricted` and
  `operator`.

Every fix is a general mechanism verified against first-party examples that are not in this
benchmark (17 fresh paraphrases of the frames, 14 fresh hard negatives), and each was developed
against `corpus/benign_ops_v1.jsonl` (378 rows) and `benchmark/calibration_benign.jsonl` (60 rows)
with the held-out set measured exactly once at the end of each round. False positives did not
move in either round: 0/378 fast and 7/378 thorough (all seven Layer 3, pre-existing), before and
after.

**Disclosure:** all eight targets across both rounds were chosen by reading this file's own
published miss list. That is ordinary error analysis, and it is how detectors improve — but it
means the held-out set is no longer blind for any formerly missed case, which is why the
saturated 100% must be read as a coverage statement about this set, not a detection rate. One
training-corpus fixture (`corpus-002`) and two held-out labels were updated in round two; both
edits are disclosed above and in the fixture itself.

A number that is blind again requires a fresh sealed set, which is deliberately not something to
assemble under deadline pressure.

Run it from the repository root:

```powershell
python scripts/benchmark_recall.py
python scripts/benchmark_recall.py --json
python scripts/benchmark_recall.py --record --json
```

`--record` appends an exact UTC result to `history.jsonl` and atomically refreshes the public
`site/data/evaluation.json` consumed by `/status`. Recording accepts only the resolved canonical held-out
paths when both line-ending-normalized content hashes match the pinned 94-attack/45-benign snapshot. It does
not conceal misses or mutate detector inputs.

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

The first confirmation remains held out. A distinct training copy is possible only when the original
submission contains explicit training-use consent and a second operator reviews a different redacted
reproducer that the current scanner detects under the certificate's assigned class:

```powershell
$env:WARDEN_PROTECTION_DB = "C:\path\to\protection.db"
python scripts/promote_gauntlet.py CLAIM_ID CERTIFICATE_ID `
  --training-payload-file .\reviewed-training-reproducer.txt `
  --confirm-human-training-review
```

The second review verifies the signed certificate and held-out binding, consent digest, current detection,
and overlap against both training datasets, both held-out datasets, and built-in injections. It commits the
first-party training row, claim promotion record, license/rights manifest, and corpus fingerprint as one
rollback-safe operation. The training row cites the BREAKER certificate and remains distinct from
allowlisted third-party corpus rows. An identical retry is idempotent.

After the first held-out confirmation, rerun the benchmark, intentionally update the published result, and
record the dated measurement. There is no public confirmation or training-promotion API, and neither review
is automatic.

Optional paid model tiers have separate guarded evaluation modes:

```powershell
python scripts/benchmark_recall.py --mode embedding-only --json
python scripts/benchmark_recall.py --mode semantic-only --json
python scripts/benchmark_recall.py --mode combined --json
```

Each mode requires exactly the named provider configuration documented in the repository README, forces
every case through paid `thorough` orchestration, and reports both the configured execution order and the
tier responsible for each counted detection or false positive. `embedding-only` rejects an enabled semantic
tier, `semantic-only` rejects an enabled embedding tier, and `combined` requires both. This prevents a
combined run from being labeled as an isolated model result.

The fixed `0.82` embedding-similarity and `0.80` semantic-confidence thresholds are both explicitly
`uncalibrated`; no independent labeled calibration data exists for either threshold. Claiming a calibrated
threshold requires a real provider/key and a separate independently labeled calibration set; the held-out
evaluation cases must not be used for tuning. Temporary synthetic fixtures verify harness routing and
accounting only, never model performance. Model-tier runs cannot use `--record` and therefore cannot update
`history.jsonl` or the public evaluation file. Keep both network tiers disabled unless a real
provider-backed held-out evaluation beats the published deterministic baseline (now saturated at
100%, so in practice: a fresh sealed set) with zero benign false positives and an
independently reviewed public-evidence schema is added.

`scripts/capture_model_calibration.py` accepts only a separate reviewed JSONL dataset outside `benchmark/`
and `corpus/`. It retains case IDs, labels, scores, review records, and provenance but not payloads.
`scripts/select_model_threshold.py` performs the threshold sweep offline and emits a hash-bound candidate;
the candidate states that a production change requires explicit review and does not edit scanner constants.
The committed JSON schemas are
`spec/schemas/model-calibration-capture-v1.schema.json` and
`spec/schemas/model-threshold-candidate-v1.schema.json`.

A semantic-enabled run recorded on 2026-07-16 against the original 28-case set is published separately in
`history.jsonl`: **71.43% recall (20/28)** with **0.00% false positives
(0/16)**. That historical measurement predates both the Decoder Wall pre-pass and the expanded evasion set,
so it is not comparable to the current 94-case deterministic baseline. The deterministic `results.json`
remains the reproducible offline baseline. Repository configuration does not enable the paid semantic
runtime, and reproducing that after-result requires an explicitly configured external model. No
real-provider threshold calibration or current model-tier performance result is published.

`tests/test_d4_benchmark.py` reruns the evaluation and requires byte-equivalent JSON data after
parsing, so detector changes must update the published result intentionally.
