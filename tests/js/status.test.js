"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { formatCheckedAt, metadataView, normalizeHealth } = require(
  path.join(__dirname, "..", "..", "site", "status.js"),
);

test("health normalization validates the live response boundary", () => {
  assert.deepEqual(
    normalizeHealth({
      status: "ok",
      version: "0.1.0",
      corpus_size: 122,
      analyzers: ["one", "two", "three", "four"],
    }),
    {
      version: "0.1.0",
      corpusCount: 122,
      analyzerCount: 4,
    },
  );
  assert.throws(
    () => normalizeHealth({ status: "ok", corpus_size: "122", analyzers: [] }),
    /version/,
  );
  assert.throws(
    () =>
      normalizeHealth({
        status: "ok",
        version: "1",
        corpus_size: -1,
        analyzers: [],
      }),
    /corpus_size/,
  );
});

test("checked-at timestamps are exact UTC instants", () => {
  assert.equal(
    formatCheckedAt(new Date("2026-07-13T20:59:01.934Z")),
    "2026-07-13T20:59:01.934Z",
  );
  assert.throws(() => formatCheckedAt(new Date("invalid")), /valid date/);
});

test("metadata view exposes separate listing and repository verification dates", () => {
  const status = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "..", "..", "site", "data", "site-status.json"),
      "utf8",
    ),
  );
  const view = metadataView(status);
  assert.equal(view.verifiedAt, "2026-07-16");
  assert.equal(view.listingVerifiedAt, "2026-07-13");
  assert.equal(view.repositoryTests, 719);
  assert.equal(view.repositoryTestsVerifiedAt, "2026-07-16");
  assert.match(view.repositoryTestsNote, /566 Python/);
  assert.match(view.repositoryTestsNote, /122 site JavaScript/);
  assert.match(view.repositoryTestsNote, /31 TypeScript SDK/);
  assert.equal(
    view.corpusFingerprint,
    "sha256:a3d4b413301dd86ea20da9e6a830e5f676b122ca4c0c266e08a1191a3b6bfc38",
  );
  assert.equal(view.services, "33460 / 33461");
});

test("status page leaves the only health request to status.js", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "status.html"),
    "utf8",
  );
  const script = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "status.js"),
    "utf8",
  );
  assert.match(html, /<body data-status-page>/);
  assert.doesNotMatch(html, /data-health-(?:label|dot)/);
  assert.equal((script.match(/fetch\("\/health"/g) || []).length, 1);
});
