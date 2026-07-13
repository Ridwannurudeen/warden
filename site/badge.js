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

  const api = { isValidAuditId, resolveAuditId };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

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

  function verificationLabel(element, verified) {
    if (!element) {
      return;
    }
    element.textContent = verified ? "Signature verified" : "Signature invalid";
    element.className = verified
      ? "status-label status-label--allow"
      : "status-label";
  }

  function createBadgeCard(entry) {
    const badge =
      entry?.badge && typeof entry.badge === "object" ? entry.badge : {};
    const auditId = badgeValue(badge.audit_id, "unknown");
    const card = document.createElement("a");
    card.className = "badge-card";
    card.href = isValidAuditId(auditId) ? `/badges/${auditId}` : "/badges";

    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = `Audit ${auditId}`;

    const heading = document.createElement("h3");
    heading.textContent = badgeValue(badge.target_host, "Target unavailable");

    const summary = document.createElement("p");
    summary.textContent = `Grade ${badgeValue(badge.grade, "--")} | ${scoreLabel(badge.score)} | ${badgeValue(badge.blocked, "--")}/${badgeValue(badge.total, "--")} payloads blocked | issued ${badgeValue(badge.issued_at, "date unavailable")}`;

    const state = document.createElement("span");
    verificationLabel(state, entry?.verified === true);
    card.append(eyebrow, heading, summary, state);
    return card;
  }

  async function loadRegistry(container) {
    const status = document.querySelector("[data-badge-registry-status]");
    const list = container.querySelector("[data-badge-list]");
    try {
      const response = await root.fetch("/api/badges", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const payload = await response.json();
      const badges = Array.isArray(payload.badges) ? payload.badges : [];
      list.replaceChildren(...badges.map(createBadgeCard));
      if (badges.length === 0) {
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.textContent = "No issued badges are currently in the registry.";
        list.replaceChildren(empty);
      }
      if (status) {
        status.textContent = `${badges.length.toLocaleString()} issued badge record${badges.length === 1 ? "" : "s"}. Each result below was verified by the API for this request.`;
      }
    } catch {
      if (status) {
        status.textContent =
          "The badge registry could not be loaded. Try again after API access is restored.";
      }
      if (list) {
        const error = document.createElement("p");
        error.className = "empty-state";
        error.textContent = "Registry unavailable.";
        list.replaceChildren(error);
      }
    }
  }

  async function loadDetail() {
    const auditId = resolveAuditId(
      root.location.search,
      root.location.pathname,
    );
    const verification = document.querySelector("[data-badge-verification]");
    if (!auditId) {
      text("[data-badge-heading]", "Audit ID required");
      text(
        "[data-badge-status]",
        "Open a badge from the registry or append ?id=<audit_id> to this page.",
      );
      verificationLabel(verification, false);
      return;
    }
    if (!isValidAuditId(auditId)) {
      text("[data-badge-heading]", "Invalid audit ID");
      text(
        "[data-badge-status]",
        "Warden audit IDs contain exactly 16 lowercase hexadecimal characters.",
      );
      verificationLabel(verification, false);
      return;
    }

    text("[data-badge-heading]", `Audit ${auditId}`);
    text("[data-badge-status]", "Checking the signed record...");
    try {
      const response = await root.fetch(
        `/badge/${encodeURIComponent(auditId)}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
        },
      );
      if (!response.ok) {
        if (response.status === 404) {
          text(
            "[data-badge-status]",
            "No issued badge record exists for this audit ID.",
          );
        } else {
          text(
            "[data-badge-status]",
            `Badge lookup failed with HTTP ${response.status}.`,
          );
        }
        verificationLabel(verification, false);
        return;
      }

      const payload = await response.json();
      const badge =
        payload?.badge && typeof payload.badge === "object"
          ? payload.badge
          : {};
      verificationLabel(verification, payload.verified === true);
      text(
        "[data-badge-status]",
        payload.verified === true
          ? "The stored record matches its signature."
          : "The stored record does not match its signature.",
      );
      text("[data-badge-audit-id]", badgeValue(badge.audit_id, auditId));
      text("[data-badge-target]", badgeValue(badge.target_host, "Unavailable"));
      text("[data-badge-grade]", badgeValue(badge.grade, "Unavailable"));
      text("[data-badge-score]", scoreLabel(badge.score));
      text(
        "[data-badge-blocked]",
        `${badgeValue(badge.blocked, "--")} / ${badgeValue(badge.total, "--")}`,
      );
      text("[data-badge-issued]", badgeValue(badge.issued_at, "Unavailable"));
      text(
        "[data-badge-signature]",
        badgeValue(badge.signature, "Unavailable"),
      );
    } catch {
      text(
        "[data-badge-status]",
        "The badge API could not be reached from this browser.",
      );
      verificationLabel(verification, false);
    }
  }

  const registry = document.querySelector("[data-badge-registry]");
  if (registry) {
    loadRegistry(registry);
  }
  if (document.querySelector("[data-badge-detail]")) {
    loadDetail();
  }
})(typeof globalThis === "undefined" ? this : globalThis);
