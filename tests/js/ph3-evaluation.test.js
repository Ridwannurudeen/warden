"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { normalizeEvaluation } = require(
  path.join(__dirname, "..", "..", "site", "status.js"),
);

const ROOT = path.join(__dirname, "..", "..");

test("public evaluation data matches the committed held-out benchmark", () => {
  const evaluation = JSON.parse(
    fs.readFileSync(path.join(ROOT, "site", "data", "evaluation.json"), "utf8"),
  );
  const benchmark = JSON.parse(
    fs.readFileSync(path.join(ROOT, "benchmark", "results.json"), "utf8"),
  );
  const history = fs
    .readFileSync(path.join(ROOT, "benchmark", "history.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const latest = history.at(-1);

  const view = normalizeEvaluation(evaluation);

  assert.deepEqual(evaluation.current, latest);
  assert.equal(view.recall, `${latest.attack_recall_percent.toFixed(2)}%`);
  assert.equal(
    view.attacks,
    `${latest.detected_attacks}/${latest.attack_cases}`,
  );
  assert.equal(
    view.falsePositives,
    `${latest.false_positives}/${latest.benign_cases}`,
  );
  assert.match(view.measuredAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.equal(evaluation.methodology.semantic_enabled, false);
  assert.equal(view.mode, "Deterministic; semantic model disabled");
  assert.equal(benchmark.attack_recall_percent, 89.36);
  assert.equal(benchmark.false_positive_rate_percent, 0);
});

test("evaluation normalization rejects inflated or ambiguous evidence", () => {
  const valid = {
    schema_version: 1,
    current: {
      measured_at: "2026-07-16T16:30:00Z",
      mode: "deterministic fast path; thorough only where declared; semantic disabled",
      attack_cases: 28,
      detected_attacks: 18,
      attack_recall_percent: 64.29,
      benign_cases: 16,
      false_positives: 0,
      false_positive_rate_percent: 0,
    },
    methodology: {
      attack_success: "non-ALLOW decision with the expected threat class",
      benign_false_positive: "any non-ALLOW decision",
      held_out: true,
      semantic_enabled: false,
    },
  };

  assert.throws(
    () =>
      normalizeEvaluation({
        ...valid,
        current: { ...valid.current, attack_recall_percent: 101 },
      }),
    /recall/,
  );
  assert.throws(
    () =>
      normalizeEvaluation({
        ...valid,
        methodology: { ...valid.methodology, held_out: false },
      }),
    /held-out/,
  );
  assert.throws(
    () =>
      normalizeEvaluation({
        ...valid,
        current: {
          ...valid.current,
          mode: "paid thorough path; semantic after deterministic layers",
        },
      }),
    /contradicts/,
  );
});

test("status surface publishes the held-out methodology without an external request", () => {
  const html = fs.readFileSync(path.join(ROOT, "site", "status.html"), "utf8");
  const script = fs.readFileSync(path.join(ROOT, "site", "status.js"), "utf8");

  assert.match(html, /Measured security/);
  assert.match(html, /expected\s+threat\s+class/);
  assert.match(html, /published run used the deterministic scanner/i);
  assert.match(script, /fetch\("\/data\/evaluation\.json"/);
  assert.doesNotMatch(script, /fetch\("https?:\/\//);
});
