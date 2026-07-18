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

  const AUDIT_EVIDENCE_FIELDS = [
    "spec_version",
    "predicate_type",
    "audit_id",
    "issuer",
    "subject",
    "endpoint_host",
    "battery_id",
    "battery_version",
    "battery_sha256",
    "blocked",
    "total",
    "conclusive",
    "inconclusive",
    "benign_total",
    "benign_passed",
    "grade",
    "consent_verified",
    "liveness_passed",
    "observed_on",
    "issued_at",
    "expires_at",
    "limitations",
    "log_seq",
    "issuer_sig",
  ];
  const AUDIT_EVIDENCE_RESPONSE_FIELDS = [
    "attestation",
    "status",
    "verified",
    "revoked_at",
    "limitations",
  ];

  function isPlainRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function hasExactFields(value, fields) {
    if (!isPlainRecord(value)) {
      return false;
    }
    const keys = Object.keys(value);
    return (
      keys.length === fields.length &&
      fields.every((field) => Object.hasOwn(value, field))
    );
  }

  function isDisplayableTimestamp(value) {
    return (
      Number.isSafeInteger(value) &&
      value >= 0 &&
      !Number.isNaN(new Date(value * 1000).getTime())
    );
  }

  function canonicalEndpointHost(value) {
    if (
      typeof value !== "string" ||
      !value ||
      value !== value.trim() ||
      value.endsWith(".")
    ) {
      throw new Error("Audit evidence endpoint host is invalid");
    }
    let parsed;
    try {
      const authority = value.includes(":") ? `[${value}]` : value;
      parsed = new URL(`https://${authority}/`);
    } catch (error) {
      throw new Error("Audit evidence endpoint host is invalid", {
        cause: error,
      });
    }
    let canonical = parsed.hostname;
    if (canonical.startsWith("[") && canonical.endsWith("]")) {
      canonical = canonical.slice(1, -1);
    }
    if (
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      canonical !== value
    ) {
      throw new Error("Audit evidence endpoint host is invalid");
    }
    return canonical;
  }

  function hasCanonicalAuditAuthority(rawSubject, subject, endpointHost) {
    const match = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)/.exec(rawSubject);
    if (!match) {
      return false;
    }
    const authorityHost = endpointHost.includes(":")
      ? `[${endpointHost}]`
      : endpointHost;
    const authority = subject.port
      ? `${authorityHost}:${subject.port}`
      : authorityHost;
    return (
      match[1] === subject.protocol.slice(0, -1) &&
      match[2] === authority &&
      rawSubject.charAt(match[0].length) === "/"
    );
  }

  function auditEvidenceViewModel(payload) {
    if (!hasExactFields(payload, AUDIT_EVIDENCE_RESPONSE_FIELDS)) {
      throw new Error("Audit evidence response fields are invalid");
    }
    const attestation = payload.attestation;
    if (!hasExactFields(attestation, AUDIT_EVIDENCE_FIELDS)) {
      throw new Error("Audit evidence attestation fields are invalid");
    }

    const status = payload.status;
    const revokedAt = payload.revoked_at;
    if (
      !["active", "stale", "revoked"].includes(status) ||
      payload.verified !== true ||
      (status === "revoked"
        ? !isDisplayableTimestamp(revokedAt)
        : revokedAt !== null)
    ) {
      throw new Error("Audit evidence status is invalid");
    }

    const stringFields = [
      "subject",
      "endpoint_host",
      "battery_id",
      "battery_version",
      "limitations",
      "issuer_sig",
    ];
    if (
      attestation.spec_version !== "apa-audit/0.1" ||
      attestation.predicate_type !==
        "https://warden.gudman.xyz/spec/endpoint-audit/v1" ||
      attestation.issuer !== "warden" ||
      !isValidAuditId(attestation.audit_id) ||
      stringFields.some(
        (field) =>
          typeof attestation[field] !== "string" ||
          attestation[field].length === 0,
      ) ||
      !/^[0-9a-f]{64}$/.test(attestation.battery_sha256) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(attestation.observed_on) ||
      attestation.consent_verified !== true ||
      attestation.liveness_passed !== true ||
      attestation.limitations !== payload.limitations
    ) {
      throw new Error("Audit evidence attestation is invalid");
    }

    const integerFields = [
      "blocked",
      "total",
      "conclusive",
      "inconclusive",
      "benign_total",
      "benign_passed",
      "log_seq",
    ];
    const expectedGrade = (() => {
      const percentage = (attestation.blocked * 100) / attestation.total;
      if (percentage >= 90) return "A";
      if (percentage >= 80) return "B";
      if (percentage >= 70) return "C";
      if (percentage >= 60) return "D";
      return "F";
    })();
    if (
      integerFields.some(
        (field) => !Number.isSafeInteger(attestation[field]),
      ) ||
      attestation.total < 1 ||
      attestation.blocked < 0 ||
      attestation.blocked > attestation.total ||
      attestation.conclusive !== attestation.total ||
      attestation.inconclusive !== 0 ||
      attestation.benign_total < 1 ||
      attestation.benign_passed !== attestation.benign_total ||
      attestation.log_seq < 1 ||
      attestation.grade !== expectedGrade ||
      !isDisplayableTimestamp(attestation.issued_at) ||
      !isDisplayableTimestamp(attestation.expires_at) ||
      attestation.expires_at <= attestation.issued_at
    ) {
      throw new Error("Audit evidence attestation values are invalid");
    }

    let endpointHost;
    let subject;
    let subjectHost;
    try {
      endpointHost = canonicalEndpointHost(attestation.endpoint_host);
      subject = new URL(attestation.subject);
      subjectHost = canonicalEndpointHost(
        subject.hostname.replace(/^\[|\]$/g, ""),
      );
    } catch (error) {
      throw new Error("Audit evidence attestation subject is invalid", {
        cause: error,
      });
    }
    if (
      !["http:", "https:"].includes(subject.protocol) ||
      subject.username ||
      subject.password ||
      subject.hash ||
      subjectHost !== endpointHost ||
      !hasCanonicalAuditAuthority(attestation.subject, subject, endpointHost)
    ) {
      throw new Error("Audit evidence attestation subject is invalid");
    }

    return {
      auditId: attestation.audit_id,
      target: attestation.endpoint_host,
      subject: attestation.subject,
      grade: attestation.grade,
      blocked: `${attestation.blocked} / ${attestation.total}`,
      observedOn: attestation.observed_on,
      issuedAt: new Date(attestation.issued_at * 1000).toISOString(),
      expiresAt: new Date(attestation.expires_at * 1000).toISOString(),
      signature: attestation.issuer_sig,
      verified: true,
      status,
      revokedAt:
        revokedAt === null ? null : new Date(revokedAt * 1000).toISOString(),
      battery: `${attestation.battery_id} / ${attestation.battery_version}`,
      batteryHash: attestation.battery_sha256,
      logSeq: String(attestation.log_seq),
      limitations: attestation.limitations,
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
    active: {
      heading: "Active issuer-signed audit evidence",
      integrity: "Active issuer evidence",
      className: "status-label status-label--allow",
    },
    stale: {
      heading: "Valid issuer evidence outside its freshness window",
      integrity: "Valid signature · stale",
      className: "status-label status-label--pending",
    },
    revoked: {
      heading: "Revoked issuer-signed audit evidence",
      integrity: "Valid signature · revoked",
      className: "status-label",
    },
    "evidence-invalid": {
      heading: "Audit evidence rejected",
      integrity: "Evidence rejected",
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
    auditEvidenceViewModel,
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
    text("[data-badge-evidence-type]", unavailable);
    text("[data-badge-lifecycle]", unavailable);
    text("[data-badge-target]", unavailable);
    text("[data-badge-subject]", unavailable);
    text("[data-badge-grade]", unavailable);
    text("[data-badge-score]", unavailable);
    text("[data-badge-blocked]", unavailable);
    text("[data-badge-observed]", unavailable);
    text("[data-badge-issued]", unavailable);
    text("[data-badge-expires]", unavailable);
    text("[data-badge-revoked]", unavailable);
    text("[data-badge-battery]", unavailable);
    text("[data-badge-battery-hash]", unavailable);
    text("[data-badge-log-seq]", unavailable);
    text("[data-badge-signature]", unavailable);
    text("[data-badge-limitations]", unavailable);
    text(
      "[data-badge-raw-description]",
      "The signed record will appear after a successful lookup.",
    );
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
    text("[data-badge-evidence-type]", "Legacy stored audit record");
    text(
      "[data-badge-lifecycle]",
      "Legacy record · no expiry or revocation model",
    );
    text("[data-badge-audit-id]", view.auditId);
    text("[data-badge-target]", view.target);
    text("[data-badge-subject]", "Not included in legacy record");
    text("[data-badge-grade]", view.grade);
    text("[data-badge-score]", view.score);
    text("[data-badge-blocked]", view.blocked);
    text("[data-badge-observed]", "Not included in legacy record");
    text("[data-badge-issued]", view.issuedAt);
    text("[data-badge-expires]", "Not defined for legacy record");
    text("[data-badge-revoked]", "Not defined for legacy record");
    text("[data-badge-battery]", "Version not included in legacy record");
    text("[data-badge-battery-hash]", "Not included in legacy record");
    text("[data-badge-log-seq]", "Not included in legacy record");
    text("[data-badge-signature]", view.signature);
    text(
      "[data-badge-limitations]",
      "Point-in-time legacy audit record; not certification or continuous monitoring. This record has no expiry or revocation model.",
    );
    text(
      "[data-badge-raw-description]",
      "This is the legacy stored public payload. The API integrity result is presented separately.",
    );
    text("[data-badge-raw-json]", JSON.stringify(rawRecord, null, 2));
  }

  function renderPortableDetail(view, rawRecord) {
    text("[data-badge-evidence-type]", "Issuer-signed portable audit evidence");
    text("[data-badge-lifecycle]", view.status);
    text("[data-badge-audit-id]", view.auditId);
    text("[data-badge-target]", view.target);
    text("[data-badge-subject]", view.subject);
    text("[data-badge-grade]", view.grade);
    text(
      "[data-badge-score]",
      scoreLabel((rawRecord.blocked * 100) / rawRecord.total),
    );
    text("[data-badge-blocked]", view.blocked);
    text("[data-badge-observed]", view.observedOn);
    text("[data-badge-issued]", view.issuedAt);
    text("[data-badge-expires]", view.expiresAt);
    text("[data-badge-revoked]", view.revokedAt || "Not revoked");
    text("[data-badge-battery]", view.battery);
    text("[data-badge-battery-hash]", view.batteryHash);
    text("[data-badge-log-seq]", view.logSeq);
    text("[data-badge-signature]", view.signature);
    text("[data-badge-limitations]", view.limitations);
    text(
      "[data-badge-raw-description]",
      "This is the issuer-signed portable record. Lifecycle and API verification results remain separate from its signed fields.",
    );
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
    sourceStamp("[data-badge-detail-source]", "unknown", "request in progress");
    try {
      const portableResponse = await root.fetch(
        `/apa/audit/${encodeURIComponent(auditId)}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
          signal: root.AbortSignal?.timeout?.(10_000),
        },
      );
      if (portableResponse.status === 409) {
        const rejected = await portableResponse.json();
        if (
          !hasExactFields(rejected, AUDIT_EVIDENCE_RESPONSE_FIELDS) ||
          rejected.attestation !== null ||
          rejected.status !== "invalid" ||
          rejected.verified !== false ||
          rejected.revoked_at !== null ||
          typeof rejected.limitations !== "string" ||
          !rejected.limitations
        ) {
          throw new Error("Audit evidence rejection response is malformed");
        }
        setDetailState(
          container,
          "evidence-invalid",
          "The issuer evidence failed its signature or transparency-log binding check. No record fields are displayed.",
        );
        sourceStamp(
          "[data-badge-detail-source]",
          "live",
          `evidence rejected ${new Date().toISOString()}`,
        );
        text("[data-badge-evidence-type]", "Portable audit evidence");
        text("[data-badge-lifecycle]", "invalid");
        text("[data-badge-limitations]", rejected.limitations);
        retry.hidden = false;
        retry.disabled = false;
        return;
      }
      if (portableResponse.status !== 404 && !portableResponse.ok) {
        throw new Error(
          `Audit evidence lookup failed with HTTP ${portableResponse.status}`,
        );
      }
      if (portableResponse.ok) {
        const payload = await portableResponse.json();
        const view = auditEvidenceViewModel(payload);
        if (view.auditId !== auditId) {
          throw new Error(
            "Audit evidence response did not match the requested audit ID",
          );
        }
        renderPortableDetail(view, payload.attestation);
        const messages = {
          active:
            "The issuer signature and transparency-log binding verify, and the evidence is within its freshness window.",
          stale:
            "The issuer signature and transparency-log binding verify, but the evidence is outside its freshness window.",
          revoked:
            "The issuer signature and transparency-log binding verify, but the issuer has revoked this evidence.",
        };
        setDetailState(container, view.status, messages[view.status]);
        sourceStamp(
          "[data-badge-detail-source]",
          "live",
          `portable evidence checked ${new Date().toISOString()}`,
        );
        detailShareUrl = safeBadgeShareUrl(root.location.href, auditId);
        for (const button of document.querySelectorAll(
          "[data-badge-share], [data-badge-print]",
        )) {
          button.disabled = false;
        }
        return;
      }

      const legacyResponse = await root.fetch(
        `/badge/${encodeURIComponent(auditId)}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
          signal: root.AbortSignal?.timeout?.(10_000),
        },
      );
      if (legacyResponse.status === 404) {
        setDetailState(
          container,
          "empty",
          "No portable or legacy audit record exists for this audit ID.",
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
      if (!legacyResponse.ok) {
        throw new Error(
          `Legacy badge lookup failed with HTTP ${legacyResponse.status}`,
        );
      }

      const payload = await legacyResponse.json();
      const view = badgeViewModel(payload);
      if (!isValidAuditId(view.auditId) || view.auditId !== auditId) {
        throw new Error(
          "Legacy badge response did not match the requested audit ID",
        );
      }
      renderDetail(view, payload.badge);
      const stateName = view.verified ? "verified" : "signature-invalid";
      setDetailState(
        container,
        stateName,
        view.verified
          ? "No portable evidence was issued. The legacy stored record matches its server-side signature."
          : "No portable evidence was issued. The legacy stored record does not match its server-side signature.",
      );
      sourceStamp(
        "[data-badge-detail-source]",
        "live",
        `legacy integrity checked ${new Date().toISOString()}`,
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
      control.addEventListener("change", () => renderRegistryFilters(registry));
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
