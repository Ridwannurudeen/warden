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
      blocked: `${badgeValue(badge.blocked, "--")} / ${badgeValue(badge.total, "--")}`,
      issuedAt: badgeValue(badge.issued_at, "Unavailable"),
      signature: badgeValue(badge.signature, "Unavailable"),
      verified: entry?.verified === true,
    };
  }

  const BADGE_STATES = {
    loading: {
      heading: "Checking badge",
      integrity: "Pending",
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
    eyebrow.textContent = `Audit ${view.auditId}`;

    const heading = document.createElement("h3");
    heading.textContent = view.target;

    const facts = document.createElement("dl");
    facts.className = "badge-card-facts";
    facts.append(
      createFact("Result", `Grade ${view.grade} · ${view.score}`, false),
      createFact("Time", view.issuedAt, true),
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

  async function loadRegistry(container) {
    const status = document.querySelector("[data-badge-registry-status]");
    const list = container.querySelector("[data-badge-list]");
    const retry = document.querySelector("[data-badge-registry-retry]");
    container.dataset.state = "loading";
    status.textContent = "Loading signed badge records...";
    retry.hidden = true;
    retry.disabled = true;
    registryMessage(container, "Loading registry...");
    try {
      const response = await root.fetch("/api/badges", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`Registry request failed with HTTP ${response.status}`);
      }
      const payload = await response.json();
      if (!Array.isArray(payload.badges)) {
        throw new Error("Registry response omitted the badges array");
      }
      const badges = payload.badges;
      if (badges.length === 0) {
        container.dataset.state = "empty";
        status.textContent =
          "No issued badge records are currently in the registry.";
        registryMessage(
          container,
          "Empty registry. A badge appears only after an eligible completed endpoint audit is issued and stored.",
        );
        return;
      }
      container.dataset.state = "ready";
      list.replaceChildren(...badges.map(createBadgeCard));
      status.textContent = `${badges.length.toLocaleString()} issued badge record${badges.length === 1 ? "" : "s"}. Integrity was checked by the API for this request.`;
    } catch (error) {
      container.dataset.state = "error";
      status.textContent = `${error.message}.`;
      registryMessage(
        container,
        "Registry unavailable. No verification result is implied.",
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
    text("[data-badge-audit-id]", auditId || "--");
    text("[data-badge-target]", "--");
    text("[data-badge-grade]", "--");
    text("[data-badge-score]", "--");
    text("[data-badge-blocked]", "--");
    text("[data-badge-issued]", "--");
    text("[data-badge-signature]", "--");
    text("[data-badge-action-status]", "");
    detailShareUrl = "";
    for (const button of document.querySelectorAll(
      "[data-badge-share], [data-badge-print]",
    )) {
      button.disabled = true;
    }
  }

  function renderDetail(view) {
    text("[data-badge-audit-id]", view.auditId);
    text("[data-badge-target]", view.target);
    text("[data-badge-grade]", view.grade);
    text("[data-badge-score]", view.score);
    text("[data-badge-blocked]", view.blocked);
    text("[data-badge-issued]", view.issuedAt);
    text("[data-badge-signature]", view.signature);
  }

  async function loadDetail() {
    const container = document.querySelector("[data-badge-detail]");
    const retry = document.querySelector("[data-badge-detail-retry]");
    const auditId = resolveAuditId(
      root.location.search,
      root.location.pathname,
    );
    resetDetailValues(auditId);
    retry.hidden = true;
    retry.disabled = true;

    if (!auditId) {
      setDetailState(
        container,
        "invalid",
        "Open a badge from the registry. A verification URL must contain one audit ID.",
      );
      return;
    }
    if (!isValidAuditId(auditId)) {
      setDetailState(
        container,
        "invalid",
        "Warden audit IDs contain exactly 16 lowercase hexadecimal characters.",
      );
      return;
    }

    setDetailState(container, "loading", "Checking the issued record...");
    try {
      const response = await root.fetch(
        `/badge/${encodeURIComponent(auditId)}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
        },
      );
      if (response.status === 404) {
        setDetailState(
          container,
          "empty",
          "No issued badge record exists for this audit ID.",
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
      renderDetail(view);
      const stateName = view.verified ? "verified" : "signature-invalid";
      setDetailState(
        container,
        stateName,
        view.verified
          ? "The stored public record matches its server-side signature."
          : "The stored public record does not match its server-side signature.",
      );
      detailShareUrl = safeBadgeShareUrl(root.location.href, auditId);
      for (const button of document.querySelectorAll(
        "[data-badge-share], [data-badge-print]",
      )) {
        button.disabled = false;
      }
    } catch (error) {
      setDetailState(container, "error", `${error.message}.`);
      retry.hidden = false;
      retry.disabled = false;
    }
  }

  const registry = document.querySelector("[data-badge-registry]");
  if (registry) {
    document
      .querySelector("[data-badge-registry-retry]")
      ?.addEventListener("click", () => loadRegistry(registry));
    loadRegistry(registry);
  }

  const detail = document.querySelector("[data-badge-detail]");
  if (detail) {
    document
      .querySelector("[data-badge-detail-retry]")
      ?.addEventListener("click", loadDetail);
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
