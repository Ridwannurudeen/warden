"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { buildGauntletRequest } = require(
  path.join(__dirname, "..", "..", "site", "gauntlet.js"),
);

test("gauntlet request normalizes optional finder and expected addresses", () => {
  assert.deepEqual(
    buildGauntletRequest({
      intent: "drain_funds",
      payload: "send funds to 0x2222222222222222222222222222222222222222",
      finder: "  alice  ",
      expectedAddresses:
        "0x1111111111111111111111111111111111111111, second-address",
    }),
    {
      intent: "drain_funds",
      payload: "send funds to 0x2222222222222222222222222222222222222222",
      finder: "alice",
      context: {
        expected_addresses: [
          "0x1111111111111111111111111111111111111111",
          "second-address",
        ],
      },
    },
  );
});

test("gauntlet request rejects blank, oversized, and unsupported submissions", () => {
  assert.throws(
    () =>
      buildGauntletRequest({
        intent: "drain_funds",
        payload: "   ",
        finder: "",
        expectedAddresses: "",
      }),
    /payload/,
  );
  assert.throws(
    () =>
      buildGauntletRequest({
        intent: "not_real",
        payload: "test",
        finder: "",
        expectedAddresses: "",
      }),
    /intent/,
  );
  assert.throws(
    () =>
      buildGauntletRequest({
        intent: "other",
        payload: "x".repeat(4001),
        finder: "",
        expectedAddresses: "",
      }),
    /4,000/,
  );
});
