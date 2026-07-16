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

  const api = {
    formatCheckedAt,
    metadataView,
    normalizeEvaluation,
    normalizeHealth,
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
    if (headerDot) {
      headerDot.classList.remove("is-ok", "is-offline");
      headerDot.classList.add(state === "ok" ? "is-ok" : "is-offline");
    }
  }

  async function loadHealth() {
    healthRetry.disabled = true;
    healthState.textContent = "Checking now";
    healthState.className = "";
    text(
      "[data-status-live-note]",
      "Checking current reachability. Historical uptime is not measured by this page.",
    );
    try {
      const response = await root.fetch("/health", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const health = normalizeHealth(await response.json());
      const observedAt = formatCheckedAt(new Date());
      setCheckedAt(observedAt);
      setHealthVisual("ok", "Reachable now");
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

      // Service IDs are reassigned on every `agent update`, so overlay the live
      // IDs from the build-generated catalog instead of the static snapshot.
      try {
        const catalogResponse = await root.fetch("/data/warden-services.json", {
          headers: { accept: "application/json" },
          cache: "no-store",
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
      } catch {
        // Keep the committed-snapshot service IDs on any fetch failure.
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
    } catch (error) {
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

  healthRetry?.addEventListener("click", loadHealth);
  loadHealth();
  loadBuildMetadata();
  loadEvaluation();
})(typeof globalThis === "undefined" ? this : globalThis);
