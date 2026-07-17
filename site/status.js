(function (root) {
  "use strict";

  function normalizeHealth(payload) {
    if (!payload || typeof payload !== "object") {
      throw new Error("Health response must be an object");
    }
    if (typeof payload.version !== "string" || !payload.version.trim()) {
      throw new Error("Health response omitted version");
    }
    if (!Number.isInteger(payload.corpus_size) || payload.corpus_size < 0) {
      throw new Error(
        "Health response corpus_size must be a nonnegative integer",
      );
    }
    if (!Array.isArray(payload.analyzers)) {
      throw new Error("Health response analyzers must be an array");
    }
    if (payload.status !== "ok") {
      throw new Error("Health response status is not ok");
    }
    return {
      version: payload.version,
      corpusCount: payload.corpus_size,
      analyzerCount: payload.analyzers.length,
    };
  }

  function formatCheckedAt(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
      throw new Error("Checked-at value must be a valid date");
    }
    return date.toISOString();
  }

  function metadataView(status) {
    if (!status || typeof status !== "object") {
      throw new Error("Status metadata must be an object");
    }
    return {
      agentId: String(status.agentId || "Unavailable"),
      listingStatus: String(status.listingStatus || "Unavailable"),
      verifiedAt: String(status.verifiedAt || "Unavailable"),
      listingVerifiedAt: String(status.listingVerifiedAt || "Unavailable"),
      repositoryTests: Number.isFinite(Number(status.repositoryTests))
        ? Number(status.repositoryTests)
        : null,
      repositoryTestsVerifiedAt: String(
        status.repositoryTestsVerifiedAt || "Unavailable",
      ),
      repositoryTestsNote: String(
        status.repositoryTestsNote || "No repository test note is available.",
      ),
      corpusFingerprint: String(status.corpusFingerprint || "Unavailable"),
      services: Array.isArray(status.services)
        ? status.services
            .map((service) => String(service.serviceId || ""))
            .filter(Boolean)
            .join(" / ") || "Unavailable"
        : "Unavailable",
      paymentActivity:
        status.paymentActivity && typeof status.paymentActivity === "object"
          ? status.paymentActivity
          : {},
    };
  }

  function normalizeEvaluation(payload) {
    if (
      !payload ||
      typeof payload !== "object" ||
      payload.schema_version !== 1 ||
      !payload.current ||
      typeof payload.current !== "object" ||
      !payload.methodology ||
      typeof payload.methodology !== "object"
    ) {
      throw new Error("Evaluation data must be a schema-v1 object");
    }
    const current = payload.current;
    const methodology = payload.methodology;
    const integerFields = [
      "attack_cases",
      "detected_attacks",
      "benign_cases",
      "false_positives",
    ];
    for (const field of integerFields) {
      if (!Number.isInteger(current[field]) || current[field] < 0) {
        throw new Error(`Evaluation ${field} must be a nonnegative integer`);
      }
    }
    if (
      current.detected_attacks > current.attack_cases ||
      current.false_positives > current.benign_cases
    ) {
      throw new Error("Evaluation counts are inconsistent");
    }
    for (const field of [
      "attack_recall_percent",
      "false_positive_rate_percent",
    ]) {
      if (
        !Number.isFinite(current[field]) ||
        current[field] < 0 ||
        current[field] > 100
      ) {
        throw new Error(`Evaluation ${field} must be a percentage`);
      }
    }
    const recall = current.attack_cases
      ? Math.round((current.detected_attacks / current.attack_cases) * 10000) /
        100
      : 0;
    const falsePositiveRate = current.benign_cases
      ? Math.round((current.false_positives / current.benign_cases) * 10000) /
        100
      : 0;
    if (
      recall !== current.attack_recall_percent ||
      falsePositiveRate !== current.false_positive_rate_percent
    ) {
      throw new Error("Evaluation recall or false-positive rate is inconsistent");
    }
    if (
      typeof current.measured_at !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(current.measured_at) ||
      Number.isNaN(Date.parse(current.measured_at))
    ) {
      throw new Error("Evaluation measured_at must be exact UTC seconds");
    }
    if (
      methodology.held_out !== true ||
      methodology.attack_success !==
        "non-ALLOW decision with the expected threat class" ||
      methodology.benign_false_positive !== "any non-ALLOW decision" ||
      typeof methodology.semantic_enabled !== "boolean"
    ) {
      throw new Error("Evaluation methodology must describe the held-out contract");
    }
    const expectedMode = methodology.semantic_enabled
      ? "paid thorough path; semantic after deterministic layers"
      : "deterministic fast path; thorough only where declared; semantic disabled";
    if (current.mode !== expectedMode) {
      throw new Error("Evaluation mode contradicts its methodology");
    }
    return {
      recall: `${current.attack_recall_percent.toFixed(2)}%`,
      attacks: `${current.detected_attacks}/${current.attack_cases}`,
      falsePositives: `${current.false_positives}/${current.benign_cases}`,
      falsePositiveRate: `${current.false_positive_rate_percent.toFixed(2)}%`,
      measuredAt: current.measured_at,
      mode: methodology.semantic_enabled
        ? "Paid thorough with semantic model"
        : "Deterministic; semantic model disabled",
    };
  }

  function normalizeMonitor(payload) {
    if (
      !payload ||
      typeof payload !== "object" ||
      payload.schema_version !== 1 ||
      !Array.isArray(payload.samples) ||
      !["not_running", "collecting"].includes(payload.status)
    ) {
      throw new Error("Monitor data must be a schema-v1 object");
    }
    if (payload.status === "not_running") {
      if (payload.samples.length) {
        throw new Error("A stopped monitor cannot publish samples");
      }
      return {
        state: "Not measured",
        window: "No recorded readiness samples",
        availability: "Not measured",
        latest: "No probe recorded",
      };
    }
    if (!payload.samples.length) {
      throw new Error("A collecting monitor must publish at least one sample");
    }

    const samples = payload.samples.map((sample) => {
      if (
        !sample ||
        typeof sample !== "object" ||
        typeof sample.checked_at !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(sample.checked_at) ||
        Number.isNaN(Date.parse(sample.checked_at)) ||
        !["ready", "not_ready", "error"].includes(sample.status) ||
        (sample.http_status !== null &&
          (!Number.isInteger(sample.http_status) ||
            sample.http_status < 100 ||
            sample.http_status > 599)) ||
        !Number.isFinite(sample.latency_ms) ||
        sample.latency_ms < 0
      ) {
        throw new Error("Monitor sample is malformed");
      }
      return { ...sample, timestamp: Date.parse(sample.checked_at) };
    });
    for (let index = 1; index < samples.length; index += 1) {
      if (samples[index].timestamp <= samples[index - 1].timestamp) {
        throw new Error("Monitor samples must be in chronological order");
      }
    }

    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    const cadenceComplete = samples.every(
      (sample, index) =>
        index === 0 || sample.timestamp - samples[index - 1].timestamp <= 10 * 60 * 1000,
    );
    const complete =
      samples.length >= 8640 &&
      samples[samples.length - 1].timestamp - samples[0].timestamp >=
        thirtyDaysMs &&
      cadenceComplete;
    const readyCount = samples.filter((sample) => sample.status === "ready").length;
    const latest = samples[samples.length - 1];
    return {
      state: complete ? "30-day window measured" : "Collecting evidence",
      window: `${samples.length.toLocaleString("en-US")} recorded readiness samples; 30-day window ${complete ? "complete" : "incomplete"}`,
      availability: complete
        ? `${((readyCount / samples.length) * 100).toFixed(2)}%`
        : "Not measured",
      latest: `${latest.checked_at} — ${latest.status.replace("_", " ")}`,
    };
  }

  const api = {
    formatCheckedAt,
    metadataView,
    normalizeEvaluation,
    normalizeHealth,
    normalizeMonitor,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  const healthState = document.querySelector("[data-status-api]");
  const healthRetry = document.querySelector("[data-status-health-retry]");
  const checkedAt = document.querySelector("[data-status-checked-at]");
  const headerLabel = document.querySelector("[data-status-header-label]");
  const headerDot = document.querySelector("[data-status-header-dot]");

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function sourceStamp(selector, state, message) {
    const element = document.querySelector(selector);
    if (!element) {
      return;
    }
    element.dataset.sourceStamp = state;
    element.className = `source-stamp source-stamp--${state}`;
    root.WardenUI?.applySourceStamp(element, state);
    element.textContent = `${state.toUpperCase()} · ${message}`;
    element.setAttribute(
      "aria-label",
      `Source state: ${state.toUpperCase()}. ${message}`,
    );
  }

  function setCheckedAt(value) {
    if (!checkedAt) {
      return;
    }
    checkedAt.textContent = value;
    checkedAt.dateTime = value;
  }

  function setHealthVisual(state, label) {
    if (healthState) {
      healthState.textContent = label;
      healthState.className =
        state === "ok" ? "status-value--ok" : "status-value--warn";
    }
    if (headerLabel) {
      headerLabel.textContent = state === "ok" ? "API live" : "API unavailable";
    }
    const statusLink = headerLabel?.closest("a");
    if (statusLink) {
      statusLink.dataset.healthState = state === "ok" ? "live" : "degraded";
      statusLink.setAttribute(
        "aria-label",
        state === "ok"
          ? "Service status: API reachable now"
          : "Service status: API unavailable now",
      );
    }
    if (headerDot) {
      headerDot.classList.remove("is-ok", "is-offline");
      headerDot.classList.add(state === "ok" ? "is-ok" : "is-offline");
    }
  }

  async function loadHealth() {
    healthRetry.disabled = true;
    healthState.textContent = "Unknown while check runs";
    healthState.className = "";
    sourceStamp(
      "[data-status-live-source]",
      "unknown",
      "health check in progress",
    );
    text(
      "[data-status-live-note]",
      "Health request in progress. Historical uptime is not measured by this page.",
    );
    try {
      const response = await root.fetch("/health", {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const health = normalizeHealth(await response.json());
      const observedAt = formatCheckedAt(new Date());
      setCheckedAt(observedAt);
      setHealthVisual("ok", "Reachable now");
      sourceStamp(
        "[data-status-live-source]",
        "live",
        `GET /health answered ${observedAt}`,
      );
      text("[data-status-version]", health.version);
      text("[data-status-corpus]", health.corpusCount.toLocaleString());
      text("[data-status-analyzers]", health.analyzerCount.toLocaleString());
      text(
        "[data-status-live-note]",
        `The API answered this browser at ${observedAt}. This establishes current reachability only; historical uptime remains unmeasured.`,
      );
    } catch (error) {
      const observedAt = formatCheckedAt(new Date());
      setCheckedAt(observedAt);
      setHealthVisual("error", "Unavailable now");
      sourceStamp(
        "[data-status-live-source]",
        "degraded",
        `GET /health unavailable ${observedAt}`,
      );
      text("[data-status-version]", "Unavailable");
      text("[data-status-corpus]", "Unavailable");
      text("[data-status-analyzers]", "Unavailable");
      text(
        "[data-status-live-note]",
        `The API did not answer this browser at ${observedAt}: ${error.message}. Historical uptime remains unmeasured.`,
      );
    } finally {
      healthRetry.disabled = false;
    }
  }

  async function loadBuildMetadata() {
    try {
      const response = await root.fetch("/data/site-status.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const status = metadataView(await response.json());
      text("[data-status-agent]", `#${status.agentId}`);
      text("[data-status-listing]", status.listingStatus);
      text("[data-status-metadata-date]", status.verifiedAt);
      text("[data-status-listing-date]", status.listingVerifiedAt);
      text(
        "[data-status-tests]",
        status.repositoryTests === null
          ? "Unavailable"
          : status.repositoryTests.toLocaleString(),
      );
      text("[data-status-tests-date]", status.repositoryTestsVerifiedAt);
      text("[data-status-tests-note]", status.repositoryTestsNote);
      text("[data-status-corpus-fingerprint]", status.corpusFingerprint);
      text("[data-status-services]", status.services);
      sourceStamp(
        "[data-status-metadata-source]",
        "dated",
        `build metadata verified ${status.verifiedAt}`,
      );
      sourceStamp(
        "[data-status-marketplace-source]",
        "dated",
        `listing verified ${status.listingVerifiedAt}`,
      );
      sourceStamp(
        "[data-status-corpus-source]",
        "dated",
        `build fingerprint verified ${status.verifiedAt}`,
      );
      sourceStamp(
        "[data-payment-source]",
        "dated",
        `address-level evidence metadata verified ${status.verifiedAt}`,
      );

      // Service IDs are reassigned on every `agent update`, so overlay the live
      // IDs from the build-generated catalog instead of the static snapshot.
      try {
        const catalogResponse = await root.fetch("/data/warden-services.json", {
          headers: { accept: "application/json" },
          cache: "no-store",
          signal: root.AbortSignal?.timeout?.(10_000),
        });
        if (catalogResponse.ok) {
          const catalog = await catalogResponse.json();
          const liveIds = (
            Array.isArray(catalog.services) ? catalog.services : []
          )
            .map((service) => String(service.serviceId || ""))
            .filter(Boolean)
            .join(" / ");
          if (liveIds) {
            text("[data-status-services]", liveIds);
          }
        }
      } catch (error) {
        text(
          "[data-status-services]",
          `${status.services} (dated snapshot; catalog unavailable: ${error.message})`,
        );
      }

      const payment = status.paymentActivity;
      text(
        "[data-payment-note]",
        String(payment.note || "No transaction-specific proof is available."),
      );
      const paymentLink = document.querySelector("[data-payment-activity]");
      const url = String(payment.url || "");
      if (
        paymentLink &&
        url.startsWith("https://www.oklink.com/xlayer/address/")
      ) {
        paymentLink.href = url;
      }
    } catch (error) {
      sourceStamp(
        "[data-status-metadata-source]",
        "degraded",
        "build metadata unavailable",
      );
      sourceStamp(
        "[data-status-marketplace-source]",
        "degraded",
        "marketplace snapshot unavailable",
      );
      sourceStamp(
        "[data-status-corpus-source]",
        "degraded",
        "corpus fingerprint unavailable",
      );
      sourceStamp(
        "[data-payment-source]",
        "degraded",
        "payment evidence metadata unavailable",
      );
      text("[data-status-metadata-date]", "Metadata unavailable");
      text("[data-status-listing]", "Metadata unavailable");
      text("[data-status-listing-date]", "Metadata unavailable");
      text("[data-status-tests]", "Metadata unavailable");
      text("[data-status-tests-date]", "Metadata unavailable");
      text(
        "[data-status-tests-note]",
        `Metadata load failed: ${error.message}.`,
      );
      text("[data-status-corpus-fingerprint]", "Metadata unavailable");
    }
  }

  async function loadEvaluation() {
    try {
      const response = await root.fetch("/data/evaluation.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const evaluation = normalizeEvaluation(await response.json());
      text("[data-evaluation-recall]", evaluation.recall);
      text("[data-evaluation-attacks]", evaluation.attacks);
      text("[data-evaluation-false-positives]", evaluation.falsePositives);
      text("[data-evaluation-fp-rate]", evaluation.falsePositiveRate);
      text("[data-evaluation-measured-at]", evaluation.measuredAt);
      text("[data-evaluation-mode]", evaluation.mode);
      sourceStamp(
        "[data-evaluation-source]",
        "dated",
        `benchmark measured ${evaluation.measuredAt}`,
      );
    } catch (error) {
      sourceStamp(
        "[data-evaluation-source]",
        "degraded",
        `evaluation unavailable: ${error.message}`,
      );
      for (const selector of [
        "[data-evaluation-recall]",
        "[data-evaluation-attacks]",
        "[data-evaluation-false-positives]",
        "[data-evaluation-fp-rate]",
        "[data-evaluation-measured-at]",
        "[data-evaluation-mode]",
      ]) {
        text(selector, "Evaluation unavailable");
      }
    }
  }

  async function loadMonitor() {
    try {
      const response = await root.fetch("/data/service-monitor.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const monitor = normalizeMonitor(await response.json());
      text("[data-monitor-state]", monitor.state);
      text("[data-monitor-window]", monitor.window);
      text("[data-monitor-availability]", monitor.availability);
      text("[data-monitor-latest]", monitor.latest);
      sourceStamp(
        "[data-monitor-source]",
        monitor.state === "Not measured" ? "unknown" : "dated",
        monitor.state === "Not measured"
          ? "no readiness samples or snapshot timestamp are published"
          : `latest readiness evidence ${monitor.latest}`,
      );
    } catch (error) {
      sourceStamp(
        "[data-monitor-source]",
        "degraded",
        `readiness evidence unavailable: ${error.message}`,
      );
      text("[data-monitor-state]", "Evidence unavailable");
      text("[data-monitor-window]", "Evidence unavailable");
      text("[data-monitor-availability]", "Not measured");
      text("[data-monitor-latest]", "Evidence unavailable");
    }
  }

  healthRetry?.addEventListener("click", loadHealth);
  loadHealth();
  loadBuildMetadata();
  loadEvaluation();
  loadMonitor();
})(typeof globalThis === "undefined" ? this : globalThis);
