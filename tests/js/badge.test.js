"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const { isValidAuditId, resolveAuditId } = require(
  path.join(__dirname, "..", "..", "site", "badge.js"),
);

test("badge detail resolves query and plural clean-route ids", () => {
  assert.equal(resolveAuditId("?id=query-id", "/badge.html"), "query-id");
  assert.equal(resolveAuditId("", "/badges/path-id"), "path-id");
  assert.equal(resolveAuditId("", "/badges"), "");
});

test("badge detail accepts only issued 16-character lowercase hex ids", () => {
  assert.equal(isValidAuditId("0123456789abcdef"), true);
  assert.equal(isValidAuditId("0123456789abcde"), false);
  assert.equal(isValidAuditId("0123456789abcdeF"), false);
  assert.equal(isValidAuditId("0123456789abcdef0"), false);
  assert.equal(isValidAuditId("../../etc/passwd"), false);
});
