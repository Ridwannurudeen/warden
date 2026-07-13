"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

const {
  EXAMPLE_RESULT,
  LIVE_REQUEST,
  canAutoAdvance,
  createShowcaseState,
  transitionShowcase,
} = require(path.join(__dirname, "..", "..", "site", "showcase.js"));

test("showcase resets to a predictable no-scan state", () => {
  const initial = createShowcaseState();
  assert.deepEqual(initial, {
    scene: 0,
    auto: false,
    scanning: false,
    source: "none",
    result: null,
    error: "",
  });
  assert.deepEqual(
    transitionShowcase(
      { ...initial, scene: 5, result: EXAMPLE_RESULT },
      { type: "RESET" },
    ),
    initial,
  );
});

test("showcase cannot pass the action gate before an explicit result", () => {
  let state = createShowcaseState();
  state = transitionShowcase(state, { type: "NEXT" });
  state = transitionShowcase(state, { type: "NEXT" });
  assert.equal(state.scene, 2);
  assert.equal(transitionShowcase(state, { type: "NEXT" }), state);
  assert.equal(canAutoAdvance({ ...state, auto: true }), false);
  assert.equal(
    canAutoAdvance({ ...createShowcaseState(), auto: true }, true),
    false,
  );
});

test("live success and labeled fallback both unlock the verdict scene", () => {
  const gate = { ...createShowcaseState(), scene: 2 };
  const scanning = transitionShowcase(gate, { type: "START_SCAN" });
  assert.equal(scanning.scanning, true);

  const live = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: EXAMPLE_RESULT,
  });
  assert.equal(live.scene, 3);
  assert.equal(live.source, "live");
  assert.equal(live.result.verdict, "BLOCK");

  const failed = transitionShowcase(gate, {
    type: "SCAN_ERROR",
    message: "offline",
  });
  assert.equal(failed.scene, 2);
  assert.equal(failed.error, "offline");
  const fallback = transitionShowcase(failed, { type: "USE_FALLBACK" });
  assert.equal(fallback.scene, 3);
  assert.equal(fallback.source, "example");
});

test("showcase rejects a valid response that does not prove the scripted stop", () => {
  const scanning = {
    ...createShowcaseState(),
    scene: 2,
    scanning: true,
  };
  const wrongVerdict = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: { ...EXAMPLE_RESULT, verdict: "ALLOW" },
  });
  assert.equal(wrongVerdict.scene, 2);
  assert.equal(wrongVerdict.result, null);
  assert.match(wrongVerdict.error, /unexpected outcome/i);

  const wrongReason = transitionShowcase(scanning, {
    type: "SCAN_SUCCESS",
    result: { ...EXAMPLE_RESULT, threat_classes: ["TOOL_HIJACK"] },
  });
  assert.equal(wrongReason.scene, 2);
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
