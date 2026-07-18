"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  EXAMPLE_RESULT,
  LIVE_REQUEST,
  createShowcaseState,
  transitionShowcase,
} = require(path.join(__dirname, "..", "..", "site", "showcase.js"));

test("showcase resets to a predictable no-scan state", () => {
  const initial = createShowcaseState();
  assert.deepEqual(initial, {
    scene: 0,
    scanning: false,
    source: "none",
    result: null,
    checkedAt: null,
    error: "",
  });
  assert.deepEqual(
    transitionShowcase(
      { ...initial, scene: 2, result: EXAMPLE_RESULT },
      { type: "RESET" },
    ),
    initial,
  );
});

test("showcase cannot pass the action gate before an explicit result", () => {
  let state = createShowcaseState();
  state = transitionShowcase(state, { type: "NEXT" });
  assert.equal(state.scene, 1);
  assert.equal(transitionShowcase(state, { type: "NEXT" }), state);
});

test("live success and labeled fallback both unlock the verdict scene", () => {
  const gate = { ...createShowcaseState(), scene: 1 };
  const scanning = transitionShowcase(gate, { type: "START_SCAN" });
  assert.equal(scanning.scanning, true);

  const live = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: EXAMPLE_RESULT,
    checkedAt: "2026-07-17T12:00:00.000Z",
  });
  assert.equal(live.scene, 2);
  assert.equal(live.source, "live");
  assert.equal(live.result.verdict, "BLOCK");
  assert.equal(live.checkedAt, "2026-07-17T12:00:00.000Z");

  const failed = transitionShowcase(gate, {
    type: "SCAN_ERROR",
    message: "offline",
  });
  assert.equal(failed.scene, 1);
  assert.equal(failed.error, "offline");
  const fallback = transitionShowcase(failed, { type: "USE_FALLBACK" });
  assert.equal(fallback.scene, 2);
  assert.equal(fallback.source, "example");
  assert.equal(fallback.checkedAt, null);
});

test("showcase rejects a valid response that does not prove the scripted stop", () => {
  const scanning = {
    ...createShowcaseState(),
    scene: 1,
    scanning: true,
  };
  const wrongVerdict = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: { ...EXAMPLE_RESULT, verdict: "ALLOW" },
  });
  assert.equal(wrongVerdict.scene, 1);
  assert.equal(wrongVerdict.result, null);
  assert.match(wrongVerdict.error, /unexpected outcome/i);

  const wrongReason = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: { ...EXAMPLE_RESULT, threat_classes: ["TOOL_HIJACK"] },
  });
  assert.equal(wrongReason.scene, 1);
  assert.equal(wrongReason.result, null);
  assert.match(wrongReason.error, /unexpected outcome/i);
});

test("showcase live request uses the frozen drain-address demo shape", () => {
  assert.equal(
    LIVE_REQUEST.payload.includes("0x2222222222222222222222222222222222222222"),
    true,
  );
  assert.deepEqual(LIVE_REQUEST.context.expected_addresses, [
    "0x1111111111111111111111111111111111111111",
  ]);
});

test("showcase keeps the product tour compact and bounds caller enforcement", () => {
  const page = fs.readFileSync(
    path.join(__dirname, "..", "..", "site", "showcase.html"),
    "utf8",
  );

  assert.equal((page.match(/data-showcase-scene=/g) || []).length, 3);
  assert.match(
    page,
    /does not invoke\s+a wallet or prove that a downstream caller withheld/,
  );
  assert.match(page, /Recommended caller action/);
  assert.doesNotMatch(page, /data-showcase-auto/);
  assert.doesNotMatch(page, /showcase-progress--sticky/);
  assert.doesNotMatch(page, /class="verdict-badge"/);
  assert.doesNotMatch(page, /data-product-proof/);
  assert.doesNotMatch(page, /The instruction stops before wallet execution/);
  assert.doesNotMatch(page, /<dt>Prevented action<\/dt>/);
});
