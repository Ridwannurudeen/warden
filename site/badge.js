(function (root) {
  "use strict";

  function resolveAuditId(search, pathname) {
    const fromQuery = new URLSearchParams(search || "").get("id");
    if (fromQuery && fromQuery.trim()) {
      return fromQuery.trim();
    }

    const parts = String(pathname || "")
      .split("/")
      .filter(Boolean);
    const badgeIndex = parts.lastIndexOf("badges");
    if (badgeIndex === -1 || badgeIndex === parts.length - 1) {
      return "";
    }
    try {
      return decodeURIComponent(parts[badgeIndex + 1]).trim();
    } catch {
      return "";
    }
  }

  function isValidAuditId(auditId) {
    return /^[0-9a-f]{16}$/.test(auditId);
  }

  function badgeValue(value, fallback) {
    return value === null || value === undefined || value === ""
      ? fallback
      : String(value);
  }

  function scoreLabel(value) {
    if (value === null || value === undefined || value === "") {
      return "Unavailable";
    }
    const score = Number(value);
    return Number.isFinite(score) ? `${score.toFixed(2)} / 100` : "Unavailable";
  }

  function badgeViewModel(entry) {
    const badge =
      entry?.badge && typeof entry.badge === "object" ? entry.badge : {};
    return {
      auditId: badgeValue(badge.audit_id, "Unavailable"),
      target: badgeValue(badge.target_host, "Unavailable"),
      grade: badgeValue(badge.grade, "Unavailable"),
      score: scoreLabel(badge.score),
      blocked: `${badgeValue(badge.blocked, "Unavailable")} / ${badgeValue(badge.total, "Unavailable")}`,
      issuedAt: badgeValue(badge.issued_at, "Unavailable"),
      signature: badgeValue(badge.signature, "Unavailable"),
      verified: entry?.verified === true,
    };
  }

  const BADGE_STATES = {
    loading: {
      heading: "Requesting audit record",
      integrity: "Unknown until checked",
      className: "status-label status-label--pending",
    },
    invalid: {
      heading: "Invalid audit ID",
      integrity: "Not checked",
      className: "status-label",
    },
    empty: {
      heading: "Badge not issued",
      integrity: "No issued record",
      className: "status-label",
    },
    error: {
      heading: "Badge lookup unavailable",
      integrity: "Unavailable",
      className: "status-label",
    },
    verified: {
      heading: "Issued audit record",
      integrity: "Signature verified",
      className: "status-label status-label--allow",
    },
    "signature-invalid": {
      heading: "Issued record with invalid signature",
      integrity: "Signature invalid",
      className: "status-label",
    },
  };

  function badgeState(state) {
    const value = BADGE_STATES[state];
    if (!value) {
      throw new Error(`Unknown badge state: ${state}`);
    }
    return { ...value };
  }

  function safeBadgeShareUrl(currentUrl, auditId) {
    if (!isValidAuditId(auditId)) {
      throw new Error("A valid audit ID is required to share a badge");
    }
    let parsed;
    try {
      parsed = new URL(currentUrl);
    } catch (error) {
      throw new Error("Badge sharing requires a valid HTTP origin", {
        cause: error,
      });
    }
    if (!/^https?:$/.test(parsed.protocol)) {
      throw new Error("Badge sharing requires a valid HTTP origin");
    }
    return new URL(`/badges/${auditId}`, parsed.origin).href;
  }

  const api = {
    badgeState,
    badgeViewModel,
    isValidAuditId,
    resolveAuditId,
    safeBadgeShareUrl,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  let detailShareUrl = "";
  let registryEntries = [];

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function verificationLabel(element, stateName) {
    if (!element) {
      return;
    }
    const state = badgeState(stateName);
    element.textContent = state.integrity;
    element.className = state.className;
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

  function createFact(label, value, numeric) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    if (numeric) {
      description.className = "num";
    }
    wrapper.append(term, description);
    return wrapper;
  }

  function createBadgeCard(entry) {
    const view = badgeViewModel(entry);
    const card = document.createElement("a");
    card.className = "badge-card";
    card.href = isValidAuditId(view.auditId)
      ? `/badges/${view.auditId}`
      : "/badges";

    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = `Record ${view.auditId}`;

    const heading = document.createElement("h3");
    heading.textContent = view.target;

    const facts = document.createElement("dl");
    facts.className = "badge-card-facts";
    facts.append(
      createFact("Audit outcome", `Grade ${view.grade} · ${view.score}`, false),
      createFact("Issued", view.issuedAt, true),
      createFact("Target", view.target, false),
    );

    const integrity = document.createElement("span");
    verificationLabel(
      integrity,
      view.verified ? "verified" : "signature-invalid",
    );
    card.append(eyebrow, heading, facts, integrity);
    return card;
  }

  function registryMessage(container, message) {
    const list = container.querySelector("[data-badge-list]");
    const state = document.createElement("p");
    state.className = "empty-state";
    state.textContent = message;
    list.replaceChildren(state);
  }

  function filteredRegistryEntries() {
    const query = String(
      document.querySelector("[data-badge-search]")?.value || "",
    )
      .trim()
      .toLocaleLowerCase("en-US");
    const integrity =
      document.querySelector("[data-badge-integrity-filter]")?.value || "all";
    return registryEntries.filter((entry) => {
      const view = badgeViewModel(entry);
      const matchesQuery =
        !query ||
        `${view.auditId} ${view.target} ${view.grade}`
          .toLocaleLowerCase("en-US")
          .includes(query);
      const matchesIntegrity =
        integrity === "all" ||
        (integrity === "verified" && view.verified) ||
        (integrity === "invalid" && !view.verified);
      return matchesQuery && matchesIntegrity;
    });
  }

  function renderRegistryFilters(container) {
    const visible = filteredRegistryEntries();
    const list = container.querySelector("[data-badge-list]");
    if (visible.length === 0) {
      registryMessage(
        container,
        registryEntries.length === 0
          ? "No endpoint audit records have been issued."
          : "No endpoint audit records match these filters.",
      );
    } else {
      list.replaceChildren(...visible.map(createBadgeCard));
    }
    text(
      "[data-badge-filter-status]",
      `${visible.length.toLocaleString()} of ${registryEntries.length.toLocaleString()} records shown.`,
    );
  }

  async function loadRegistry(container) {
    const status = document.querySelector("[data-badge-registry-status]");
    const retry = document.querySelector("[data-badge-registry-retry]");
    container.dataset.state = "loading";
    status.textContent =
      "Requesting endpoint audit records. No integrity conclusion is available yet.";
    sourceStamp(
      "[data-badge-registry-source]",
      "unknown",
      "request in progress",
    );
    retry.hidden = true;
    retry.disabled = true;
    registryMessage(
      container,
      "Registry request in progress. No record or integrity result is implied.",
    );
    try {
      const response = await root.fetch("/api/badges", {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      });
      if (!response.ok) {
        throw new Error(`Registry request failed with HTTP ${response.status}`);
      }
      const payload = await response.json();
      if (!Array.isArray(payload.badges)) {
        throw new Error("Registry response omitted the badges array");
      }
      if (
        !Number.isInteger(payload.total) ||
        payload.total !== payload.badges.length
      ) {
        throw new Error("Registry response total does not match its records");
      }
      const badges = payload.badges;
      registryEntries = badges;
      const observedAt = new Date().toISOString();
      sourceStamp(
        "[data-badge-registry-source]",
        "live",
        `API response checked ${observedAt}`,
      );
      if (badges.length === 0) {
        container.dataset.state = "empty";
        status.textContent =
          "The live registry response contains no issued endpoint audit records.";
        renderRegistryFilters(container);
        return;
      }
      container.dataset.state = "ready";
      renderRegistryFilters(container);
      status.textContent = `${badges.length.toLocaleString()} issued endpoint audit record${badges.length === 1 ? "" : "s"}. Stored-record integrity was checked by the API for this request.`;
    } catch (error) {
      container.dataset.state = "error";
      registryEntries = [];
      sourceStamp(
        "[data-badge-registry-source]",
        "degraded",
        `registry unavailable ${new Date().toISOString()}`,
      );
      status.textContent = `${error.message}.`;
      registryMessage(
        container,
        "Registry unavailable. No verification result is implied.",
      );
      text(
        "[data-badge-filter-status]",
        "Filters are unavailable because the registry did not respond.",
      );
      retry.hidden = false;
      retry.disabled = false;
    }
  }

  function setDetailState(container, stateName, statusMessage) {
    const state = badgeState(stateName);
    container.dataset.state = stateName;
    text("[data-badge-heading]", state.heading);
    text("[data-badge-status]", statusMessage);
    verificationLabel(
      document.querySelector("[data-badge-verification]"),
      stateName,
    );
  }

  function resetDetailValues(auditId) {
    const unavailable = "Not available until requested";
    text("[data-badge-audit-id]", auditId || unavailable);
    text("[data-badge-target]", unavailable);
    text("[data-badge-grade]", unavailable);
    text("[data-badge-score]", unavailable);
    text("[data-badge-blocked]", unavailable);
    text("[data-badge-issued]", unavailable);
    text("[data-badge-signature]", unavailable);
    text(
      "[data-badge-raw-json]",
      "Record JSON is unavailable until the lookup succeeds.",
    );
    text("[data-badge-action-status]", "");
    detailShareUrl = "";
    for (const button of document.querySelectorAll(
      "[data-badge-share], [data-badge-print]",
    )) {
      button.disabled = true;
    }
  }

  function renderDetail(view, rawRecord) {
    text("[data-badge-audit-id]", view.auditId);
    text("[data-badge-target]", view.target);
    text("[data-badge-grade]", view.grade);
    text("[data-badge-score]", view.score);
    text("[data-badge-blocked]", view.blocked);
    text("[data-badge-issued]", view.issuedAt);
    text("[data-badge-signature]", view.signature);
    text("[data-badge-raw-json]", JSON.stringify(rawRecord, null, 2));
  }

  async function loadDetail() {
    const container = document.querySelector("[data-badge-detail]");
    const retry = document.querySelector("[data-badge-detail-retry]");
    const auditId = resolveAuditId(
      root.location.search,
      root.location.pathname,
    );
    resetDetailValues(auditId);
    sourceStamp(
      "[data-badge-detail-source]",
      "unknown",
      "record not requested",
    );
    retry.hidden = true;
    retry.disabled = true;

    if (!auditId) {
      sourceStamp(
        "[data-badge-detail-source]",
        "unknown",
        "audit identifier missing",
      );
      setDetailState(
        container,
        "invalid",
        "Open a badge from the registry. A verification URL must contain one audit ID.",
      );
      return;
    }
    if (!isValidAuditId(auditId)) {
      sourceStamp(
        "[data-badge-detail-source]",
        "unknown",
        "audit identifier is invalid",
      );
      setDetailState(
        container,
        "invalid",
        "Warden audit IDs contain exactly 16 lowercase hexadecimal characters.",
      );
      return;
    }

    setDetailState(
      container,
      "loading",
      "Requesting the issued record. No integrity conclusion is available yet.",
    );
    sourceStamp(
      "[data-badge-detail-source]",
      "unknown",
      "request in progress",
    );
    try {
      const response = await root.fetch(
        `/badge/${encodeURIComponent(auditId)}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
          signal: root.AbortSignal?.timeout?.(10_000),
        },
      );
      if (response.status === 404) {
        setDetailState(
          container,
          "empty",
          "No issued badge record exists for this audit ID.",
        );
        sourceStamp(
          "[data-badge-detail-source]",
          "live",
          `no record found ${new Date().toISOString()}`,
        );
        retry.hidden = false;
        retry.disabled = false;
        return;
      }
      if (!response.ok) {
        throw new Error(`Badge lookup failed with HTTP ${response.status}`);
      }

      const payload = await response.json();
      const view = badgeViewModel(payload);
      if (!isValidAuditId(view.auditId) || view.auditId !== auditId) {
        throw new Error("Badge response did not match the requested audit ID");
      }
      renderDetail(view, payload.badge);
      const stateName = view.verified ? "verified" : "signature-invalid";
      setDetailState(
        container,
        stateName,
        view.verified
          ? "The stored public record matches its server-side signature."
          : "The stored public record does not match its server-side signature.",
      );
      sourceStamp(
        "[data-badge-detail-source]",
        "live",
        `integrity checked ${new Date().toISOString()}`,
      );
      detailShareUrl = safeBadgeShareUrl(root.location.href, auditId);
      for (const button of document.querySelectorAll(
        "[data-badge-share], [data-badge-print]",
      )) {
        button.disabled = false;
      }
    } catch (error) {
      setDetailState(container, "error", `${error.message}.`);
      sourceStamp(
        "[data-badge-detail-source]",
        "degraded",
        `lookup unavailable ${new Date().toISOString()}`,
      );
      retry.hidden = false;
      retry.disabled = false;
    }
  }

  const registry = document.querySelector("[data-badge-registry]");
  if (registry) {
    document
      .querySelector("[data-badge-registry-retry]")
      ?.addEventListener("click", () => {
        root.WardenUI?.focusStatusTarget(
          document.querySelector("[data-badge-registry-status]"),
        );
        loadRegistry(registry);
      });
    loadRegistry(registry);
    for (const control of document.querySelectorAll(
      "[data-badge-search], [data-badge-integrity-filter]",
    )) {
      control.addEventListener("input", () => renderRegistryFilters(registry));
      control.addEventListener("change", () =>
        renderRegistryFilters(registry),
      );
    }
  }

  const detail = document.querySelector("[data-badge-detail]");
  if (detail) {
    document
      .querySelector("[data-badge-detail-retry]")
      ?.addEventListener("click", () => {
        root.WardenUI?.focusStatusTarget(
          document.querySelector("[data-badge-status]"),
        );
        loadDetail();
      });
    document
      .querySelector("[data-badge-share]")
      ?.addEventListener("click", async () => {
        if (!detailShareUrl) {
          return;
        }
        try {
          await root.navigator.clipboard.writeText(detailShareUrl);
          text("[data-badge-action-status]", "Verification URL copied.");
        } catch (error) {
          text("[data-badge-action-status]", `Copy failed: ${error.message}`);
        }
      });
    document
      .querySelector("[data-badge-print]")
      ?.addEventListener("click", () => {
        if (!detailShareUrl) {
          return;
        }
        root.print();
      });
    loadDetail();
  }
})(typeof globalThis === "undefined" ? this : globalThis);
