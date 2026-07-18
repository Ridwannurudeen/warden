(function (root) {
  "use strict";

  const LAST_SCENE = 2;
  const SCENE_LABELS = ["Input and context", "Live scan", "Decision"];
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
      scanning: false,
      source: "none",
      result: null,
      checkedAt: null,
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
    if (event.type === "PREVIOUS") {
      return { ...state, scene: Math.max(0, state.scene - 1), error: "" };
    }
    if (event.type === "NEXT") {
      if (state.scene === 1 && !state.result) {
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
          checkedAt: null,
          error:
            "The live scan returned a valid but unexpected outcome. Use the labeled example fallback for this scripted walkthrough.",
        };
      }
      return {
        ...state,
        scene: 2,
        scanning: false,
        source: "live",
        result: event.result,
        checkedAt: typeof event.checkedAt === "string" ? event.checkedAt : null,
        error: "",
      };
    }
    if (event.type === "SCAN_ERROR") {
      return {
        ...state,
        scanning: false,
        source: "none",
        result: null,
        checkedAt: null,
        error: String(event.message || "The live scan could not be completed."),
      };
    }
    if (event.type === "USE_FALLBACK") {
      return {
        ...state,
        scene: 2,
        scanning: false,
        source: "example",
        result: EXAMPLE_RESULT,
        checkedAt: null,
        error: "",
      };
    }
    return state;
  }

  const api = {
    EXAMPLE_RESULT,
    LIVE_REQUEST,
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
  const position = document.querySelector("[data-showcase-position]");
  const previousButton = document.querySelector("[data-showcase-previous]");
  const nextButton = document.querySelector("[data-showcase-next]");
  const resetButton = document.querySelector("[data-showcase-reset]");
  const runButton = document.querySelector("[data-showcase-run]");
  const fallbackButton = document.querySelector("[data-showcase-fallback]");
  const scanStatus = document.querySelector("[data-showcase-status]");
  const requestSource = document.querySelector(
    "[data-showcase-request-source]",
  );
  const announcer = document.querySelector("[data-showcase-announcer]");
  let state = createShowcaseState();
  let renderedScene = state.scene;

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function renderSourceStamp(element, sourceState, message) {
    element.dataset.sourceState = sourceState;
    element.className = `source-stamp source-stamp--${sourceState}`;
    element.replaceChildren();
    const sourceLabel = document.createElement("strong");
    sourceLabel.textContent = sourceState.toUpperCase();
    element.append(sourceLabel, ` ${message}`);
  }

  function renderResult() {
    if (!state.result) {
      return;
    }
    const sourceStamp = document.querySelector("[data-showcase-source-stamp]");
    const sourceState = state.source === "live" ? "live" : "illustrative";
    const sourceMessage =
      state.source === "live"
        ? state.checkedAt
          ? `Validated response received at ${state.checkedAt}.`
          : "Validated response received during this session."
        : "Safe local example; no production response is claimed.";
    renderSourceStamp(sourceStamp, sourceState, sourceMessage);
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
    if (position) {
      position.textContent = `Step ${state.scene + 1} of ${LAST_SCENE + 1} · ${SCENE_LABELS[state.scene]}`;
    }
    previousButton.disabled = state.scene === 0 || state.scanning;
    nextButton.disabled =
      state.scene === LAST_SCENE ||
      state.scanning ||
      (state.scene === 1 && !state.result);
    nextButton.textContent = state.scene === LAST_SCENE ? "Done" : "Next";
    resetButton.disabled = state.scanning;
    runButton.disabled = state.scanning;
    runButton.textContent = state.scanning
      ? "Running scan…"
      : "Run a live scan";
    fallbackButton.hidden = !state.error;
    scanStatus.textContent =
      state.error ||
      (state.scanning
        ? "Submitting to /api/demo/scan…"
        : "Ready. The request starts only when you select Run a live scan.");
    scanStatus.dataset.state = state.error
      ? "error"
      : state.scanning
        ? "loading"
        : "ready";
    if (state.error) {
      renderSourceStamp(
        requestSource,
        "degraded",
        "The live request did not produce the scripted result. No live outcome is shown.",
      );
    } else if (state.scanning) {
      renderSourceStamp(
        requestSource,
        "unknown",
        "Request in progress; no result has been accepted.",
      );
    } else if (state.source === "live") {
      renderSourceStamp(
        requestSource,
        "live",
        state.checkedAt
          ? `Validated response received at ${state.checkedAt}.`
          : "Validated response received during this session.",
      );
    } else if (state.source === "example") {
      renderSourceStamp(
        requestSource,
        "illustrative",
        "Safe local example selected; no production response is claimed.",
      );
    } else {
      renderSourceStamp(
        requestSource,
        "unknown",
        "No verdict exists until you run the scan.",
      );
    }
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
      state = transitionShowcase(state, {
        type: "SCAN_SUCCESS",
        result,
        checkedAt: new Date().toISOString(),
      });
    } catch (error) {
      const message = client?.formatScanError
        ? client.formatScanError(error)
        : error.message;
      state = transitionShowcase(state, { type: "SCAN_ERROR", message });
    }
    render({ focusScene: state.scene === 2 });
  });

  rootElement.addEventListener("keydown", (event) => {
    if (
      event.altKey ||
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey ||
      ["INPUT", "SELECT", "TEXTAREA", "BUTTON", "A"].includes(
        event.target?.tagName,
      )
    ) {
      return;
    }
    if (event.key === "ArrowLeft" && !previousButton.disabled) {
      event.preventDefault();
      state = transitionShowcase(state, { type: "PREVIOUS" });
      render({ focusScene: true });
    } else if (event.key === "ArrowRight" && !nextButton.disabled) {
      event.preventDefault();
      state = transitionShowcase(state, { type: "NEXT" });
      render({ focusScene: true });
    }
  });

  render();
})(typeof globalThis === "undefined" ? this : globalThis);
