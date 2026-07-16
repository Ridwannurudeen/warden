"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { GENESIS_PREV_HASH, fetchLogPages } = require(
  path.join(__dirname, "..", "..", "site", "log.js"),
);

function entry(seq) {
  return {
    seq,
    ts: 1_789_000_000 + seq,
    event: "issued",
    attestation_id: `attestation-${seq}`,
    endpoint_host: "asp.example.org",
    status: "active",
    record_hash: "a".repeat(64),
    prev_hash: seq === 1 ? GENESIS_PREV_HASH : "b".repeat(64),
  };
}

function response(body) {
  return {
    ok: true,
    status: 200,
    async json() {
      return body;
    },
  };
}

test("browser log loader follows bounded cursor pages", async () => {
  const calls = [];
  const pages = new Map([
    [
      "/apa/log?cursor=0&limit=2",
      { entries: [entry(1), entry(2)], total: 5, next_cursor: 2 },
    ],
    [
      "/apa/log?cursor=2&limit=2",
      { entries: [entry(3), entry(4)], total: 5, next_cursor: 4 },
    ],
    [
      "/apa/log?cursor=4&limit=2",
      { entries: [entry(5)], total: 5, next_cursor: null },
    ],
  ]);

  const entries = await fetchLogPages(async (endpoint) => {
    calls.push(endpoint);
    return response(pages.get(endpoint));
  }, 2);

  assert.deepEqual(calls, [...pages.keys()]);
  assert.deepEqual(
    entries.map((item) => item.seq),
    [1, 2, 3, 4, 5],
  );
});
