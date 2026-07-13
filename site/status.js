(function (root) {
  "use strict";

  if (!root.document) {
    return;
  }

  const document = root.document;

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  async function loadHealth() {
    const state = document.querySelector("[data-status-api]");
    try {
      const response = await root.fetch("/health", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const health = await response.json();
      if (state) {
        state.textContent = "Reachable now";
        state.className = "status-value--ok";
      }
      text("[data-status-version]", String(health.version || "Unavailable"));
      text("[data-status-corpus]", Number(health.corpus_size).toLocaleString());
      text(
        "[data-status-analyzers]",
        Array.isArray(health.analyzers)
          ? health.analyzers.length.toLocaleString()
          : "Unavailable",
      );
      text(
        "[data-status-live-note]",
        "The API answered this browser now. Historical uptime remains unmeasured.",
      );
    } catch {
      if (state) {
        state.textContent = "Unavailable now";
        state.className = "status-value--warn";
      }
      text(
        "[data-status-live-note]",
        "The API did not answer this browser. Historical uptime remains unmeasured.",
      );
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
      const status = await response.json();
      text("[data-status-agent]", `#${String(status.agentId)}`);
      text("[data-status-listing]", String(status.listingStatus));
      text("[data-status-listing-date]", String(status.listingVerifiedAt));
      text(
        "[data-status-tests]",
        Number(status.repositoryTests).toLocaleString(),
      );
      text(
        "[data-status-corpus-fingerprint]",
        String(status.corpusFingerprint),
      );
      text(
        "[data-status-services]",
        Array.isArray(status.services)
          ? status.services
              .map((service) => String(service.serviceId))
              .join(" / ")
          : "Unavailable",
      );

      const payment = status.paymentActivity || {};
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
    } catch {
      text("[data-status-listing]", "Metadata unavailable");
      text("[data-status-tests]", "Metadata unavailable");
      text("[data-status-corpus-fingerprint]", "Metadata unavailable");
    }
  }

  loadHealth();
  loadBuildMetadata();
})(typeof globalThis === "undefined" ? this : globalThis);
