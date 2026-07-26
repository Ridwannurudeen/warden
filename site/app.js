(function (root) {
  "use strict";

  function resolveTheme(storedTheme, prefersLight) {
    if (storedTheme === "light" || storedTheme === "dark") {
      return storedTheme;
    }
    return "dark";
  }

  function cycleFocusIndex(currentIndex, direction, count) {
    if (!Number.isInteger(count) || count < 1) {
      return -1;
    }
    const step = direction === "backward" ? -1 : 1;
    const start =
      Number.isInteger(currentIndex) &&
      currentIndex >= 0 &&
      currentIndex < count
        ? currentIndex
        : direction === "backward"
          ? 0
          : -1;
    return (start + step + count) % count;
  }

  function catalogServiceByKey(catalog, key) {
    if (!Array.isArray(catalog?.services)) {
      return null;
    }
    return catalog.services.find((service) => service?.key === key) || null;
  }

  function isOutsideNavigationPointer(siteNav, navToggle, target) {
    return !siteNav?.contains?.(target) && !navToggle?.contains?.(target);
  }

  function focusStatusTarget(element) {
    if (!element || typeof element.focus !== "function") {
      return false;
    }
    element.tabIndex = -1;
    element.focus();
    return true;
  }

  function copyButtonBaseLabel(button) {
    if (!button?.dataset) {
      return "";
    }
    if (!("copyBaseLabel" in button.dataset)) {
      button.dataset.copyBaseLabel = button.textContent;
    }
    return button.dataset.copyBaseLabel;
  }

  function normalizeEvidenceCount(value, label) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative integer`);
    }
    return value;
  }

  function normalizeMarketplaceSummary(value) {
    const capturedAt = value?.capturedAt;
    if (
      typeof capturedAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(capturedAt) ||
      !Number.isFinite(Date.parse(capturedAt)) ||
      new Date(capturedAt).toISOString() !== capturedAt.replace("Z", ".000Z")
    ) {
      throw new Error("marketplace capturedAt must be a valid UTC timestamp");
    }
    if (value?.schemaVersion !== 2) {
      throw new Error("marketplace summary schemaVersion must be 2");
    }
    const query = value?.query;
    if (
      typeof query !== "string" ||
      !query ||
      query !== query.trim() ||
      query.length > 100
    ) {
      throw new Error("marketplace query must be a non-empty trimmed string");
    }
    const sampled = normalizeEvidenceCount(
      value.sampled,
      "marketplace sampled count",
    );
    const expected = normalizeEvidenceCount(
      value.expected,
      "marketplace expected count",
    );
    const dropped = normalizeEvidenceCount(
      value.dropped,
      "marketplace dropped count",
    );
    const matchedCount = normalizeEvidenceCount(
      value.matchedCount,
      "marketplace matched count",
    );
    const auditedCount = normalizeEvidenceCount(
      value.auditedCount,
      "marketplace audited count",
    );
    if (dropped !== Math.max(expected - sampled, 0)) {
      throw new Error(
        "marketplace dropped count does not match sampled coverage",
      );
    }
    if (matchedCount > sampled || auditedCount > sampled) {
      throw new Error(
        "marketplace evidence counts cannot exceed sampled coverage",
      );
    }
    return {
      schemaVersion: 2,
      capturedAt,
      query,
      sampled,
      expected,
      dropped,
      matchedCount,
      auditedCount,
      complete: sampled === expected && dropped === 0,
    };
  }

  function marketplaceCoverageText(summary) {
    const query = JSON.stringify(summary.query);
    if (summary.complete) {
      return `Complete discovery response for marketplace query ${query}: ${summary.sampled.toLocaleString()} unique agents sampled; highest reported result total ${summary.expected.toLocaleString()}.`;
    }
    if (summary.sampled > summary.expected) {
      return `Partial/degraded discovery response for marketplace query ${query}: ${summary.sampled.toLocaleString()} unique agents sampled; the sample exceeded the highest reported result total ${summary.expected.toLocaleString()}, so upstream counts disagree.`;
    }
    return `Partial/degraded discovery response for marketplace query ${query}: ${summary.sampled.toLocaleString()} unique agents sampled; highest reported result total ${summary.expected.toLocaleString()}; ${summary.dropped.toLocaleString()} expected agents not present in this response.`;
  }

  function normalizeProductProof(value) {
    if (value?.schemaVersion !== 1) {
      throw new Error("product proof schemaVersion must be 1");
    }
    if (
      typeof value.verifiedAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(value.verifiedAt) ||
      !Number.isFinite(Date.parse(`${value.verifiedAt}T00:00:00Z`))
    ) {
      throw new Error("product proof verifiedAt must be a valid date");
    }

    const marketplace = value.marketplace;
    if (!/^\d+$/.test(marketplace?.agentId || "")) {
      throw new Error("product proof agentId must be numeric");
    }
    const reviewCount = normalizeEvidenceCount(
      marketplace.rating?.reviews,
      "product proof review count",
    );
    const ratingValue = marketplace.rating?.value;
    const ratingOutOf = marketplace.rating?.outOf;
    if (
      !Number.isFinite(ratingValue) ||
      !Number.isFinite(ratingOutOf) ||
      ratingOutOf <= 0 ||
      ratingValue < 0 ||
      ratingValue > ratingOutOf
    ) {
      throw new Error("product proof rating must fit its scale");
    }
    if (
      marketplace.url !== "https://www.okx.ai/" ||
      marketplace.listingUrlAvailable !== false ||
      marketplace.instruction !== `Search Agent #${marketplace.agentId}`
    ) {
      throw new Error("product proof marketplace destination is invalid");
    }

    const benchmark = value.checkoutBenchmark;
    if (!Number.isFinite(benchmark?.p50Ms) || benchmark.p50Ms <= 0) {
      throw new Error("product proof latency must be positive");
    }
    const payloadCount = normalizeEvidenceCount(
      benchmark.payloadCount,
      "product proof benchmark payload count",
    );
    if (
      typeof benchmark.measuredAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(benchmark.measuredAt) ||
      !Number.isFinite(Date.parse(benchmark.measuredAt)) ||
      // The benchmark is dated independently of the marketplace verification: the
      // latency run and the listing snapshot are separate facts measured on their
      // own days, so measuredAt is validated as a timestamp but not tied to
      // verifiedAt. corpus.snapshotAt below still binds to this run.
      typeof benchmark.method !== "string" ||
      !benchmark.method.trim()
    ) {
      throw new Error("product proof benchmark metadata is invalid");
    }

    const corpus = value.evaluationCorpus;
    const total = normalizeEvidenceCount(
      corpus?.total,
      "product proof corpus total",
    );
    const attacks = normalizeEvidenceCount(
      corpus?.attacks,
      "product proof attack count",
    );
    const benign = normalizeEvidenceCount(
      corpus?.benign,
      "product proof benign count",
    );
    if (
      attacks + benign !== total ||
      payloadCount !== total ||
      corpus.snapshotAt !== benchmark.measuredAt
    ) {
      throw new Error("product proof corpus counts are inconsistent");
    }

    return {
      schemaVersion: 1,
      verifiedAt: value.verifiedAt,
      marketplace: {
        agentId: marketplace.agentId,
        rating: {
          value: ratingValue,
          outOf: ratingOutOf,
          reviews: reviewCount,
        },
        url: marketplace.url,
        listingUrlAvailable: false,
        instruction: marketplace.instruction,
      },
      checkoutBenchmark: {
        p50Ms: benchmark.p50Ms,
        payloadCount,
        measuredAt: benchmark.measuredAt,
        method: benchmark.method,
      },
      evaluationCorpus: {
        total,
        attacks,
        benign,
        snapshotAt: corpus.snapshotAt,
      },
    };
  }

  function isHealthyResponse(value) {
    return value?.status === "ok";
  }

  const SOURCE_STAMP_PRESENTATIONS = Object.freeze({
    LIVE: Object.freeze({
      label: "LIVE",
      description: "Observed live in this browser session.",
    }),
    DATED: Object.freeze({
      label: "DATED",
      description: "Dated snapshot; not a live claim.",
    }),
    ILLUSTRATIVE: Object.freeze({
      label: "ILLUSTRATIVE",
      description: "Illustrative example; not observed evidence.",
    }),
    DEGRADED: Object.freeze({
      label: "DEGRADED",
      description: "Source is incomplete or currently degraded.",
    }),
    UNKNOWN: Object.freeze({
      label: "UNKNOWN",
      description: "Source state has not been established.",
    }),
  });

  function sourceStampPresentation(value) {
    const state =
      typeof value === "string" ? value.trim().toUpperCase() : "UNKNOWN";
    const presentation =
      SOURCE_STAMP_PRESENTATIONS[state] || SOURCE_STAMP_PRESENTATIONS.UNKNOWN;
    return {
      state: presentation.label,
      label: presentation.label,
      description: presentation.description,
    };
  }

  function applySourceStamp(element, value) {
    if (!element?.dataset) {
      return null;
    }
    const presentation = sourceStampPresentation(
      value || element.dataset.sourceState || element.dataset.sourceStamp,
    );
    element.dataset.sourceState = presentation.state;
    element.dataset.sourceStamp = presentation.state;
    const modifierClasses = Object.keys(SOURCE_STAMP_PRESENTATIONS).map(
      (state) => `source-stamp--${state.toLowerCase()}`,
    );
    element.classList?.remove(...modifierClasses);
    element.classList?.add(`source-stamp--${presentation.state.toLowerCase()}`);
    const label = element.querySelector?.("[data-source-stamp-label]");
    if (label) {
      label.textContent = presentation.label;
    }
    if (
      !element.getAttribute?.("aria-label") ||
      element.dataset.sourceAriaManaged === "true"
    ) {
      element.setAttribute?.(
        "aria-label",
        `Source state: ${presentation.label}. ${presentation.description}`,
      );
      element.dataset.sourceAriaManaged = "true";
    }
    return presentation;
  }

  const ASYNC_PANEL_STATES = new Set([
    "idle",
    "loading",
    "ready",
    "empty",
    "error",
    "degraded",
    "unknown",
  ]);

  function normalizeAsyncPanelState(value) {
    const state =
      typeof value === "string" ? value.trim().toLowerCase() : "unknown";
    return ASYNC_PANEL_STATES.has(state) ? state : "unknown";
  }

  function applyAsyncPanelState(element, value, message) {
    if (!element?.dataset) {
      return null;
    }
    const state = normalizeAsyncPanelState(value);
    element.dataset.state = state;
    element.dataset.asyncState = state;
    if (state === "loading") {
      element.setAttribute?.("aria-busy", "true");
    } else {
      element.removeAttribute?.("aria-busy");
    }
    const status = element.querySelector?.("[data-async-status]");
    if (status && typeof message === "string") {
      status.textContent = message;
    }
    return state;
  }

  function healthStatusPresentation(value, detailed) {
    if (value === "live") {
      return {
        state: "live",
        label: detailed ? "API ok" : "API live",
        ariaLabel: "API status: live",
        dotClass: "is-ok",
      };
    }
    if (value === "unavailable") {
      return {
        state: "unavailable",
        label: "API unavailable",
        ariaLabel: "API status: unavailable",
        dotClass: "is-offline",
      };
    }
    return {
      state: "unknown",
      label: detailed ? "API status unknown" : "Status unknown",
      ariaLabel: "Service status: unknown",
      dotClass: "is-unknown",
    };
  }

  function homeProofEvidence(result, checkedAt) {
    return {
      attestationId: result.material.attestation.attestation_id,
      chainHead: result.honestChain.headHash,
      tamperIndex: `Entry ${result.tamper.entryIndex + 1}`,
      keyId: result.material.issuerDocument.keys[0].kid,
      freshness: result.attestation.freshness,
      checkedAt,
    };
  }

  const api = {
    applyAsyncPanelState,
    applySourceStamp,
    catalogServiceByKey,
    copyButtonBaseLabel,
    cycleFocusIndex,
    focusStatusTarget,
    healthStatusPresentation,
    homeProofEvidence,
    isHealthyResponse,
    isOutsideNavigationPointer,
    marketplaceCoverageText,
    normalizeAsyncPanelState,
    normalizeEvidenceCount,
    normalizeMarketplaceSummary,
    normalizeProductProof,
    resolveTheme,
    sourceStampPresentation,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenUI = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  document.documentElement.classList.add("js-enabled");

  for (const stamp of document.querySelectorAll(
    "[data-source-stamp], .source-stamp[data-source-state]",
  )) {
    applySourceStamp(stamp);
  }
  for (const panel of document.querySelectorAll("[data-async-panel]")) {
    applyAsyncPanelState(panel, panel.dataset.state || "unknown");
  }

  const themeButtons = Array.from(
    document.querySelectorAll("[data-theme-toggle]"),
  );
  const initialTheme = resolveTheme(
    document.documentElement.dataset.theme,
    false,
  );

  function setTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    for (const button of themeButtons) {
      const next = theme === "dark" ? "light" : "dark";
      button.textContent = `${next[0].toUpperCase()}${next.slice(1)} theme`;
      button.setAttribute("aria-label", `Switch to ${next} theme`);
    }
    if (persist) {
      try {
        root.localStorage.setItem("warden-theme", theme);
      } catch {
        return;
      }
    }
  }

  setTheme(initialTheme, false);
  for (const button of themeButtons) {
    button.addEventListener("click", () => {
      const next =
        document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      setTheme(next, true);
    });
  }

  const navToggle = document.querySelector("[data-nav-toggle]");
  const siteNav = document.querySelector("[data-site-nav]");
  if (navToggle && siteNav) {
    siteNav.dataset.state = "closed";
    const navClose = document.createElement("button");
    navClose.className = "nav-close";
    navClose.type = "button";
    navClose.textContent = "Close menu";
    siteNav.prepend(navClose);

    function setNavigationIsolation(isolated) {
      for (const element of document.querySelectorAll(
        ".skip-link, .site-header > :not([data-site-nav]), main, .site-footer",
      )) {
        element.inert = isolated;
      }
    }

    function focusableNavigationElements() {
      const candidates = Array.from(
        siteNav.querySelectorAll("a[href], button:not([disabled])"),
      );
      return candidates.filter(
        (element) => element.getClientRects().length > 0,
      );
    }

    function setNavigation(open, restoreFocus) {
      siteNav.classList.toggle("is-open", open);
      siteNav.dataset.state = open ? "open" : "closed";
      document.body.classList.toggle("nav-open", open);
      navToggle.setAttribute("aria-expanded", String(open));
      setNavigationIsolation(open);
      if (open) {
        const first = focusableNavigationElements()[0];
        first?.focus();
      } else {
        if (restoreFocus) {
          navToggle.focus();
        }
      }
    }

    navToggle.addEventListener("click", () => {
      const open = !siteNav.classList.contains("is-open");
      setNavigation(open, false);
    });
    navClose.addEventListener("click", () => {
      setNavigation(false, true);
    });
    siteNav.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        setNavigation(false, false);
      }
    });
    document.addEventListener("pointerdown", (event) => {
      if (!isOutsideNavigationPointer(siteNav, navToggle, event.target)) {
        return;
      }
      if (siteNav.classList.contains("is-open")) {
        setNavigation(false, false);
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (siteNav.classList.contains("is-open")) {
          setNavigation(false, true);
        }
        return;
      }
      if (event.key === "Tab" && siteNav.classList.contains("is-open")) {
        const focusable = focusableNavigationElements();
        const current = focusable.indexOf(document.activeElement);
        const next = cycleFocusIndex(
          current,
          event.shiftKey ? "backward" : "forward",
          focusable.length,
        );
        event.preventDefault();
        focusable[next]?.focus();
      }
    });
    root.addEventListener("resize", () => {
      if (
        root.matchMedia?.("(min-width: 1061px)").matches &&
        siteNav.classList.contains("is-open")
      ) {
        setNavigation(false, false);
      }
    });
  }

  const healthLabels = Array.from(
    document.querySelectorAll("[data-health-label]"),
  );
  const healthDots = Array.from(document.querySelectorAll("[data-health-dot]"));

  function renderHealthStatus(state) {
    for (const label of healthLabels) {
      const presentation = healthStatusPresentation(
        state,
        label.dataset.healthDetail === "full",
      );
      label.textContent = presentation.label;
      const link = label.closest("a");
      if (link) {
        link.dataset.healthState = presentation.state;
        link.setAttribute("aria-label", presentation.ariaLabel);
      }
    }
    for (const dot of healthDots) {
      const presentation = healthStatusPresentation(state, false);
      dot.classList.remove("is-unknown", "is-ok", "is-offline");
      dot.classList.add(presentation.dotClass);
    }
  }

  renderHealthStatus("unknown");
  if (
    !document.querySelector("[data-status-page]") &&
    (healthLabels.length || healthDots.length)
  ) {
    root
      .fetch("/health", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((health) => {
        if (!isHealthyResponse(health)) {
          throw new Error("Malformed health response");
        }
        renderHealthStatus("live");
      })
      .catch(() => {
        renderHealthStatus("unavailable");
      });
  }

  const productProof = document.querySelector("[data-product-proof]");
  if (productProof) {
    const productProofStatus = document.querySelector(
      "[data-product-proof-status]",
    );
    root
      .fetch("/data/product-proof.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((source) => {
        const proof = normalizeProductProof(source);
        const fields = {
          "agent-id": `#${proof.marketplace.agentId}`,
          rating: `${proof.marketplace.rating.value} / ${proof.marketplace.rating.outOf}`,
          reviews: `${proof.marketplace.rating.reviews.toLocaleString()} external buyer reviews`,
          latency: `${proof.checkoutBenchmark.p50Ms} ms`,
          "latency-sample": `${proof.checkoutBenchmark.payloadCount.toLocaleString()} payloads`,
          "latency-method": proof.checkoutBenchmark.method,
          "verified-at": `Verified ${proof.verifiedAt}`,
          "corpus-total": proof.evaluationCorpus.total.toLocaleString(),
          "corpus-breakdown": `${proof.evaluationCorpus.attacks.toLocaleString()} attacks · ${proof.evaluationCorpus.benign.toLocaleString()} benign`,
          "okx-instruction": proof.marketplace.instruction,
        };
        for (const [field, text] of Object.entries(fields)) {
          for (const element of document.querySelectorAll(
            `[data-proof-field="${field}"]`,
          )) {
            element.textContent = text;
          }
        }
        productProof.dataset.state = "ready";
        if (productProofStatus) {
          applySourceStamp(productProofStatus, "DATED");
          productProofStatus.textContent = `DATED · product proof loaded ${proof.verifiedAt}`;
        }
      })
      .catch(() => {
        productProof.dataset.state = "unavailable";
        if (productProofStatus) {
          applySourceStamp(productProofStatus, "DEGRADED");
          productProofStatus.textContent =
            "DEGRADED · dated product proof unavailable";
        }
      });
  }

  const evalStats = document.querySelector("[data-eval-stats]");
  if (evalStats) {
    root
      .fetch("/data/evaluation.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((source) => {
        const current = source && source.current;
        if (
          !current ||
          typeof current.attack_recall_percent !== "number" ||
          typeof current.false_positive_rate_percent !== "number" ||
          typeof current.benign_cases !== "number" ||
          typeof current.attack_cases !== "number"
        ) {
          throw new Error("Malformed evaluation snapshot");
        }
        const fields = {
          recall: `${current.attack_recall_percent}%`,
          "fp-rate": `${current.false_positive_rate_percent}%`,
          "benign-cases": `${current.benign_cases.toLocaleString()} held-out benign cases`,
        };
        for (const [field, text] of Object.entries(fields)) {
          for (const element of evalStats.querySelectorAll(
            `[data-eval-stat="${field}"]`,
          )) {
            element.textContent = text;
          }
        }
        evalStats.dataset.state = "ready";
      })
      .catch(() => {
        evalStats.dataset.state = "unavailable";
        const unavailableCopy = {
          recall: "Recall unavailable",
          "fp-rate": "False-positive rate unavailable",
          "benign-cases": "Evaluation corpus unavailable",
        };
        for (const element of evalStats.querySelectorAll("[data-eval-stat]")) {
          element.textContent =
            unavailableCopy[element.dataset.evalStat] ||
            "Evaluation metric unavailable";
        }
      });
  }

  function bindHomeProof() {
    const proofRoot = document.querySelector("[data-home-proof]");
    if (!proofRoot || proofRoot.dataset.bound === "true") {
      return;
    }
    const runButton = proofRoot.querySelector("[data-home-proof-run]");
    const status = proofRoot.querySelector("[data-home-proof-status]");
    const signature = proofRoot.querySelector("[data-home-proof-signature]");
    const chain = proofRoot.querySelector("[data-home-proof-chain]");
    const tamper = proofRoot.querySelector("[data-home-proof-tamper]");
    const attestationId = proofRoot.querySelector(
      "[data-home-proof-attestation-id]",
    );
    const chainHead = proofRoot.querySelector("[data-home-proof-chain-head]");
    const tamperIndex = proofRoot.querySelector(
      "[data-home-proof-tamper-index]",
    );
    const keyId = proofRoot.querySelector("[data-home-proof-key-id]");
    const freshness = proofRoot.querySelector("[data-home-proof-freshness]");
    const checkedAt = proofRoot.querySelector("[data-home-proof-checked-at]");
    if (!runButton || !status) {
      return;
    }
    proofRoot.dataset.bound = "true";

    function renderCheck(element, check) {
      if (!element) {
        return;
      }
      element.dataset.state = check.state;
      const label = element.querySelector("strong");
      const detail = element.querySelector("p");
      if (label) {
        label.textContent = check.label;
      }
      if (detail) {
        detail.textContent = check.detail;
      }
    }

    runButton.addEventListener("click", async () => {
      runButton.disabled = true;
      proofRoot.dataset.state = "running";
      proofRoot.setAttribute("aria-busy", "true");
      status.textContent =
        "Running the bundled proof entirely in this browser.";
      try {
        const proofApi = root.WardenHomeProof;
        if (
          !proofApi ||
          typeof proofApi.runOfflineProof !== "function" ||
          typeof proofApi.proofPresentation !== "function"
        ) {
          throw new Error("Offline verifier did not load.");
        }
        const result = await proofApi.runOfflineProof();
        const presentation = proofApi.proofPresentation(result);
        renderCheck(signature, presentation.signature);
        renderCheck(chain, presentation.honestChain);
        renderCheck(tamper, presentation.tamperedChain);
        status.textContent = presentation.summary;
        proofRoot.dataset.state = presentation.passed ? "verified" : "rejected";
        const evidence = homeProofEvidence(result, new Date().toISOString());
        if (attestationId) {
          attestationId.textContent = evidence.attestationId;
        }
        if (chainHead) {
          chainHead.textContent = evidence.chainHead;
        }
        if (tamperIndex) {
          tamperIndex.textContent = evidence.tamperIndex;
        }
        if (keyId) {
          keyId.textContent = evidence.keyId;
        }
        if (freshness) {
          freshness.textContent = evidence.freshness;
        }
        if (checkedAt) {
          checkedAt.textContent = evidence.checkedAt;
        }
      } catch (error) {
        proofRoot.dataset.state = "error";
        status.textContent = `Offline verification failed: ${error.message}`;
      } finally {
        proofRoot.removeAttribute("aria-busy");
        runButton.disabled = false;
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindHomeProof, {
      once: true,
    });
  } else {
    bindHomeProof();
  }

  const serviceCatalog = document.querySelector("[data-service-catalog]");
  if (serviceCatalog) {
    const serviceSnapshot = document.querySelector("[data-service-snapshot]");
    const serviceStamp = document.querySelector("[data-service-stamp]");
    root
      .fetch("/data/warden-services.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((catalog) => {
        for (const card of serviceCatalog.querySelectorAll(
          "[data-service-key]",
        )) {
          const service = catalogServiceByKey(catalog, card.dataset.serviceKey);
          if (!service) {
            continue;
          }
          const price = card.querySelector('[data-service-field="price"]');
          const id = card.querySelector('[data-service-field="id"]');
          if (price) {
            price.textContent = `${service.feeAmount} USDT`;
          }
          if (id) {
            id.textContent = `#${service.serviceId}`;
          }
        }
        serviceCatalog.dataset.snapshot = String(catalog.snapshotFetchedAt);
        if (serviceSnapshot) {
          serviceSnapshot.textContent = `Catalog snapshot ${catalog.snapshotFetchedAt}`;
        }
        applySourceStamp(serviceStamp, "DATED");
      })
      .catch(() => {
        serviceCatalog.dataset.snapshot = "dated-fallback";
        if (serviceSnapshot) {
          serviceSnapshot.textContent = `Committed catalog snapshot ${serviceSnapshot.dataset.fallbackSnapshot}`;
        }
        applySourceStamp(serviceStamp, "DEGRADED");
      });
  }

  const homeBadgeCount = document.querySelector("[data-home-badge-count]");
  const homeBadgeSource = document.querySelector("[data-home-badge-source]");
  const homeBadgeStamp = document.querySelector("[data-home-badge-stamp]");
  if (homeBadgeCount) {
    root
      .fetch("/api/badges", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((registry) => {
        homeBadgeCount.textContent = normalizeEvidenceCount(
          registry.total,
          "badge count",
        ).toLocaleString();
        if (homeBadgeSource) {
          homeBadgeSource.textContent = "Live signed-record registry";
        }
        applySourceStamp(homeBadgeStamp, "LIVE");
      })
      .catch(() => {
        homeBadgeCount.textContent = "Unavailable";
        if (homeBadgeSource) {
          homeBadgeSource.textContent = "Live registry unavailable";
        }
        applySourceStamp(homeBadgeStamp, "DEGRADED");
      });
  }

  const homeBypassCount = document.querySelector("[data-home-bypass-count]");
  const homeBypassSource = document.querySelector("[data-home-bypass-source]");
  const homeBypassStamp = document.querySelector("[data-home-bypass-stamp]");
  if (homeBypassCount) {
    root
      .fetch("/api/demo/gauntlet/stats", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((stats) => {
        homeBypassCount.textContent = normalizeEvidenceCount(
          stats.confirmed_bypasses,
          "confirmed bypass count",
        ).toLocaleString();
        if (homeBypassSource) {
          homeBypassSource.textContent = "Live human-confirmed Gauntlet count";
        }
        applySourceStamp(homeBypassStamp, "LIVE");
      })
      .catch(() => {
        homeBypassCount.textContent = "Unavailable";
        if (homeBypassSource) {
          homeBypassSource.textContent = "Live Gauntlet count unavailable";
        }
        applySourceStamp(homeBypassStamp, "DEGRADED");
      });
  }

  let toastRegion = document.querySelector("[data-toast-region]");
  if (!toastRegion) {
    toastRegion = document.createElement("div");
    toastRegion.className = "toast-region";
    toastRegion.dataset.toastRegion = "";
    toastRegion.setAttribute("aria-live", "polite");
    toastRegion.setAttribute("aria-atomic", "true");
    document.body.append(toastRegion);
  }

  for (const button of document.querySelectorAll("[data-copy-target]")) {
    const baseLabel = copyButtonBaseLabel(button);
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) {
        return;
      }
      try {
        await root.navigator.clipboard.writeText(target.textContent);
        button.textContent = "Copied";
        toastRegion.textContent = "Copied to clipboard.";
        root.setTimeout(() => {
          button.textContent = baseLabel;
          toastRegion.textContent = "";
        }, 1200);
      } catch (error) {
        button.textContent = baseLabel;
        toastRegion.textContent = `Copy failed: ${error.message}`;
      }
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis);
