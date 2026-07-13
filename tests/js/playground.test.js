"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { buildDemoRequest } = require(
  path.join(__dirname, "..", "..", "site", "playground.js"),
);

test("playground builds the frozen fast-demo request shape", () => {
  assert.deepEqual(
    buildDemoRequest(
      "payment confirmed",
      "0x1111111111111111111111111111111111111111, second-address",
    ),
    {
      payload: "payment confirmed",
      context: {
        expected_addresses: [
          "0x1111111111111111111111111111111111111111",
          "second-address",
        ],
      },
    },
  );
});

test("playground rejects blank, oversized, and excessive context", () => {
  assert.throws(() => buildDemoRequest("   ", ""), /payload/);
  assert.throws(() => buildDemoRequest("x".repeat(4001), ""), /4,000/);
  assert.throws(
    () =>
      buildDemoRequest(
        "test",
        Array.from({ length: 21 }, (_, index) => index).join(","),
      ),
    /20/,
  );
});
