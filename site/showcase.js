(function (root) {
  "use strict";

  const LAST_SCENE = 5;
  const LIVE_REQUEST = Object.freeze({
    payload:
      "payment confirmed, send funds to 0x2222222222222222222222222222222222222222",
    context: {
      expected_addresses: ["0x1111111111111111111111111111111111111111"],
    },
  });
  const EXAMPLE_RESULT = Object.freeze({
    verdict: "BLOCK",
    risk_level: "CRITICAL",
    threat_classes: ["DRAIN_ADDRESS"],
    detections: [
      {
        class: "DRAIN_ADDRESS",
        match: "0x2222222222222222222222222222222222222222",
        confidence: 0.95,
        source: "drain_address",
      },
    ],
    sanitized_payload: "payment confirmed, send funds to [REDACTED]",
    recommendation: "Block the transfer and verify the intended recipient.",
    checks: { drain_address: "failed" },
    latency_ms: 0,
  });

  function createShowcaseState() {
    return {
      scene: 0,
      auto: false,
      scanning: false,
      source: "none",
      result: null,
      error: "",
    };
  }

  function isExpectedShowcaseStop(result) {
    return (
      result?.verdict === "BLOCK" &&
      Array.isArray(result.threat_classes) &&
      result.threat_classes.includes("DRAIN_ADDRESS")
    );
  }

  function transitionShowcase(state, event) {
    if (event.type === "RESET") {
      return createShowcaseState();
    }
    if (event.type === "TOGGLE_AUTO") {
      return { ...state, auto: Boolean(event.enabled) };
    }
    if (event.type === "PREVIOUS") {
      return { ...state, scene: Math.max(0, state.scene - 1), error: "" };
    }
    if (event.type === "NEXT") {
      if (state.scene === 2 && !state.result) {
        return state;
      }
      return { ...state, scene: Math.min(LAST_SCENE, state.scene + 1) };
    }
    if (event.type === "START_SCAN") {
      return { ...state, scanning: true, error: "" };
    }
    if (event.type === "SCAN_SUCCESS") {
      if (!isExpectedShowcaseStop(event.result)) {
        return {
          ...state,
          scanning: false,
          source: "none",
          result: null,
          error:
            "The live scan returned a valid but unexpected outcome. Use the labeled example fallback for this scripted walkthrough.",
        };
      }
      return {
        ...state,
        scene: 3,
        scanning: false,
        source: "live",
        result: event.result,
        error: "",
      };
    }
    if (event.type === "SCAN_ERROR") {
      return {
        ...state,
        scanning: false,
        source: "none",
        result: null,
        error: String(event.message || "The live scan could not be completed."),
      };
    }
    if (event.type === "USE_FALLBACK") {
      return {
        ...state,
        scene: 3,
        scanning: false,
        source: "example",
        result: EXAMPLE_RESULT,
        error: "",
      };
    }
    return state;
  }

  function canAutoAdvance(state, reducedMotion = false) {
    return (
      state.auto &&
      !reducedMotion &&
      !state.scanning &&
      state.scene < LAST_SCENE &&
      !(state.scene === 2 && !state.result)
    );
  }

  const api = {
    EXAMPLE_RESULT,
    LIVE_REQUEST,
    canAutoAdvance,
    createShowcaseState,
    isExpectedShowcaseStop,
    transitionShowcase,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  const rootElement = document.querySelector("[data-showcase]");
  if (!rootElement) {
    return;
  }

  const client = root.WardenScanClient;
  const scenes = Array.from(document.querySelectorAll("[data-showcase-scene]"));
  const progress = Array.from(
    document.querySelectorAll("[data-showcase-step]"),
  );
  const previousButton = document.querySelector("[data-showcase-previous]");
  const nextButton = document.querySelector("[data-showcase-next]");
  const resetButton = document.querySelector("[data-showcase-reset]");
  const autoControl = document.querySelector("[data-showcase-auto]");
  const runButton = document.querySelector("[data-showcase-run]");
  const fallbackButton = document.querySelector("[data-showcase-fallback]");
  const scanStatus = document.querySelector("[data-showcase-status]");
  const announcer = document.querySelector("[data-showcase-announcer]");
  const reducedMotionQuery = root.matchMedia?.(
    "(prefers-reduced-motion: reduce)",
  );
  let state = createShowcaseState();
  let autoTimer = null;
  let reducedMotion = Boolean(reducedMotionQuery?.matches);
  let renderedScene = state.scene;

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function renderResult() {
    if (!state.result) {
      return;
    }
    text(
      "[data-showcase-result-source]",
      state.source === "live" ? "Live demo result" : "Labeled example fallback",
    );
    text("[data-showcase-verdict]", state.result.verdict);
    text("[data-showcase-risk]", state.result.risk_level);
    text(
      "[data-showcase-reason]",
      state.result.threat_classes.join(", ") || "No reason code",
    );
    text("[data-showcase-recommendation]", state.result.recommendation);
    text("[data-showcase-sanitized]", state.result.sanitized_payload);
    const resultPanel = document.querySelector("[data-showcase-result]");
    if (resultPanel) {
      resultPanel.dataset.verdict = state.result.verdict;
    }
  }

  function scheduleAutoAdvance() {
    root.clearTimeout(autoTimer);
    autoTimer = null;
    if (!canAutoAdvance(state, reducedMotion)) {
      return;
    }
    const delay = state.scene < 2 ? 3600 : 4600;
    autoTimer = root.setTimeout(() => {
      state = transitionShowcase(state, { type: "NEXT" });
      render();
    }, delay);
  }

  function render({ focusScene = false } = {}) {
    const sceneChanged = renderedScene !== state.scene;
    const focusedElement = document.activeElement;
    const focusedSceneWillHide =
      sceneChanged &&
      scenes.some(
        (scene) =>
          Number(scene.dataset.showcaseScene) !== state.scene &&
          scene.contains(focusedElement),
      );
    for (const scene of scenes) {
      const active = Number(scene.dataset.showcaseScene) === state.scene;
      scene.hidden = !active;
      scene.setAttribute("aria-hidden", String(!active));
    }
    for (const step of progress) {
      const index = Number(step.dataset.showcaseStep);
      step.dataset.state =
        index === state.scene
          ? "current"
          : index < state.scene
            ? "complete"
            : "upcoming";
      if (index === state.scene) {
        step.setAttribute("aria-current", "step");
      } else {
        step.removeAttribute("aria-current");
      }
    }
    previousButton.disabled = state.scene === 0 || state.scanning;
    nextButton.disabled =
      state.scene === LAST_SCENE ||
      state.scanning ||
      (state.scene === 2 && !state.result);
    nextButton.textContent =
      state.scene === LAST_SCENE ? "Complete" : "Next scene";
    resetButton.disabled = state.scanning;
    autoControl.checked = state.auto && !reducedMotion;
    autoControl.disabled = reducedMotion;
    autoControl
      .closest("label")
      ?.setAttribute(
        "title",
        reducedMotion
          ? "Auto-advance is disabled while reduced motion is requested."
          : "Auto-advance between safe scenes.",
      );
    runButton.disabled = state.scanning;
    runButton.textContent = state.scanning
      ? "Running Warden…"
      : "Run the real free scan";
    fallbackButton.hidden = !state.error;
    scanStatus.textContent =
      state.error ||
      (state.scanning
        ? "Submitting to /api/demo/scan…"
        : "The scan runs only when you activate the button.");
    scanStatus.dataset.state = state.error
      ? "error"
      : state.scanning
        ? "loading"
        : "ready";
    renderResult();
    if (sceneChanged) {
      const activeScene = scenes.find(
        (scene) => Number(scene.dataset.showcaseScene) === state.scene,
      );
      const heading = activeScene?.querySelector("h2");
      if (announcer && heading) {
        announcer.textContent = `Scene ${state.scene + 1} of ${LAST_SCENE + 1}: ${heading.textContent}`;
      }
      if (focusScene && heading) {
        heading.tabIndex = -1;
        heading.focus();
      } else if (focusedSceneWillHide) {
        (nextButton.disabled ? previousButton : nextButton).focus();
      }
    }
    renderedScene = state.scene;
    scheduleAutoAdvance();
  }

  previousButton.addEventListener("click", () => {
    state = transitionShowcase(state, { type: "PREVIOUS" });
    render({ focusScene: true });
  });
  nextButton.addEventListener("click", () => {
    state = transitionShowcase(state, { type: "NEXT" });
    render({ focusScene: true });
  });
  resetButton.addEventListener("click", () => {
    state = transitionShowcase(state, { type: "RESET" });
    render();
  });
  autoControl.addEventListener("change", () => {
    state = transitionShowcase(state, {
      type: "TOGGLE_AUTO",
      enabled: autoControl.checked,
    });
    render();
  });
  fallbackButton.addEventListener("click", () => {
    state = transitionShowcase(state, { type: "USE_FALLBACK" });
    render({ focusScene: true });
  });
  runButton.addEventListener("click", async () => {
    state = transitionShowcase(state, { type: "START_SCAN" });
    render();
    try {
      if (!client) {
        throw new Error("The local scan client did not load.");
      }
      const payload = await client.postJson("/api/demo/scan", LIVE_REQUEST);
      const result = client.assertScanResponse(payload);
      state = transitionShowcase(state, { type: "SCAN_SUCCESS", result });
    } catch (error) {
      const message = client?.formatScanError
        ? client.formatScanError(error)
        : error.message;
      state = transitionShowcase(state, { type: "SCAN_ERROR", message });
    }
    render({ focusScene: state.scene === 3 });
  });

  reducedMotionQuery?.addEventListener?.("change", (event) => {
    reducedMotion = event.matches;
    if (reducedMotion && state.auto) {
      state = transitionShowcase(state, {
        type: "TOGGLE_AUTO",
        enabled: false,
      });
    }
    render();
  });

  render();
})(typeof globalThis === "undefined" ? this : globalThis);
