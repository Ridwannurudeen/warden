"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  EXAMPLES,
  exampleById,
} = require(path.join(__dirname, "..", "..", "site", "home-examples.js"));

test("hero receipt examples cover four implemented attack classes", () => {
  assert.deepEqual(
    EXAMPLES.map(({ id }) => id),
    ["recipient", "injection", "tool", "secret"],
  );
  assert.deepEqual(
    EXAMPLES.map(({ verdict }) => verdict),
    ["BLOCK", "SANITIZE", "BLOCK", "BLOCK"],
  );
  assert.equal(exampleById("recipient").reason, "DRAIN_ADDRESS");
  assert.equal(exampleById("missing"), null);
});

test("hero examples are illustrative and never define a network endpoint", () => {
  for (const example of EXAMPLES) {
    assert.equal(example.sourceState, "ILLUSTRATIVE");
    assert.equal(Object.hasOwn(example, "endpoint"), false);
    assert.match(example.boundary, /before/i);
    assert.ok(example.output.length > 0);
    assert.ok(example.action.length > 0);
  }
});
