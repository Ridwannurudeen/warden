(function (root) {
  "use strict";

  const TARGET_ID = /^[A-Za-z0-9._-]{1,64}$/;
  const AUDIT_ID = /^[0-9a-f]{16}$/;
  const COMPARISONS = new Set([
    "initial",
    "unchanged",
    "improved",
    "regressed",
    "inconclusive",
  ]);
  const STATUSES = new Set(["active", "stale", "revoked"]);
  const MAX_ENTRIES = 1_000;

  function normalizeLineage(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("lineage payload is not an object");
    }
    if (payload.schema_version !== 1) {
      throw new Error("unsupported lineage schema version");
    }
    if (
      typeof payload.target_id !== "string" ||
      !TARGET_ID.test(payload.target_id)
    ) {
      throw new Error("lineage target id is invalid");
    }
    if (!Array.isArray(payload.entries)) {
      throw new Error("lineage entries are missing");
    }
    if (payload.entries.length > MAX_ENTRIES) {
      throw new Error("lineage entry count exceeds the display bound");
    }
    if (payload.total !== payload.entries.length) {
      throw new Error("lineage total does not match the returned entries");
    }
    const entries = payload.entries.map(normalizeEntry);
    // The API returns observation order; a lineage that is not monotonic in time
    // cannot be rendered as a trajectory without misrepresenting it.
    for (let index = 1; index < entries.length; index += 1) {
      if (entries[index].occurredAt < entries[index - 1].occurredAt) {
        throw new Error("lineage entries are not in observation order");
      }
    }
    return {
      targetId: payload.target_id,
      total: payload.total,
      limitations:
        typeof payload.limitations === "string" ? payload.limitations : "",
      entries,
    };
  }

  function normalizeEntry(entry) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("lineage entry is not an object");
    }
    if (!COMPARISONS.has(entry.comparison)) {
      throw new Error("lineage entry has an unknown comparison");
    }
    if (!STATUSES.has(entry.status)) {
      throw new Error("lineage entry has an unknown status");
    }
    if (entry.verified !== true) {
      throw new Error("lineage entry is not verified");
    }
    if (!Number.isSafeInteger(entry.occurred_at) || entry.occurred_at < 0) {
      throw new Error("lineage entry has an invalid observation time");
    }
    const attestation = entry.attestation;
    if (!attestation || typeof attestation !== "object") {
      throw new Error("lineage entry has no attestation");
    }
    if (
      typeof attestation.audit_id !== "string" ||
      !AUDIT_ID.test(attestation.audit_id)
    ) {
      throw new Error("lineage entry has an invalid audit id");
    }
    if (!Number.isSafeInteger(attestation.log_seq) || attestation.log_seq < 1) {
      throw new Error("lineage entry has an invalid log sequence");
    }
    return {
      comparison: entry.comparison,
      reason: typeof entry.reason === "string" ? entry.reason : "",
      occurredAt: entry.occurred_at,
      acceptedAsBaseline: entry.accepted_as_baseline === true,
      enrollmentRevision:
        Number.isSafeInteger(entry.enrollment_revision) &&
        entry.enrollment_revision >= 1
          ? entry.enrollment_revision
          : null,
      status: entry.status,
      revokedAt: Number.isSafeInteger(entry.revoked_at)
        ? entry.revoked_at
        : null,
      auditId: attestation.audit_id,
      grade: typeof attestation.grade === "string" ? attestation.grade : "",
      blocked: attestation.blocked,
      total: attestation.total,
      logSeq: attestation.log_seq,
      observedOn:
        typeof attestation.observed_on === "string"
          ? attestation.observed_on
          : "",
    };
  }

  function gradeTrajectory(lineage) {
    const grades = lineage.entries.map((entry) => entry.grade).filter(Boolean);
    if (!grades.length) {
      return "";
    }
    return grades.join(" → ");
  }

  async function fetchLineage(targetId, fetchImpl) {
    if (typeof targetId !== "string" || !TARGET_ID.test(targetId)) {
      throw new Error(
        "enter a target id of up to 64 letters, digits, dot, dash or underscore",
      );
    }
    const response = await fetchImpl(
      `/api/shield/${encodeURIComponent(targetId)}/lineage`,
      { headers: { accept: "application/json" } },
    );
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`lineage lookup failed with HTTP ${response.status}`);
    }
    return normalizeLineage(await response.json());
  }

  // Inclusion is checked against the public log the visitor fetches themselves,
  // using the shared chain verifier — this page adds no crypto of its own.
  async function verifyLogInclusion(lineage, log, fetchImpl, cryptoImpl) {
    if (!log || typeof log.fetchLogPages !== "function") {
      throw new Error("the transparency-log verifier is unavailable");
    }
    const payload = await log.fetchLogPages(fetchImpl);
    const entries =
      payload && Array.isArray(payload.entries) ? payload.entries : [];
    const chain = await log.verifyLogChain(entries, cryptoImpl);
    if (!chain || chain.ok !== true) {
      return {
        ok: false,
        reason:
          chain && chain.reason
            ? chain.reason
            : "the public log chain did not verify",
        checked: 0,
      };
    }
    const sequences = new Set(
      entries
        .map((entry) => entry.seq)
        .filter((seq) => Number.isSafeInteger(seq)),
    );
    const missing = lineage.entries
      .filter((entry) => !sequences.has(entry.logSeq))
      .map((entry) => entry.auditId);
    if (missing.length) {
      return {
        ok: false,
        reason: `not present in the verified log: ${missing.join(", ")}`,
        checked: lineage.entries.length,
      };
    }
    return { ok: true, reason: "", checked: lineage.entries.length };
  }

  const api = {
    MAX_ENTRIES,
    fetchLineage,
    gradeTrajectory,
    normalizeEntry,
    normalizeLineage,
    verifyLogInclusion,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenAuditEvidenceLineage = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  const container = document.querySelector("[data-lineage]");
  if (!container) {
    return;
  }

  const form = document.querySelector("[data-lineage-form]");
  const input = document.querySelector("[data-lineage-target]");
  const verifyButton = document.querySelector("[data-lineage-verify]");
  const entriesElement = document.querySelector("[data-lineage-entries]");
  const emptyElement = document.querySelector("[data-lineage-empty]");
  let loaded = null;

  function text(selector, value) {
    const node = document.querySelector(selector);
    if (node) {
      node.textContent = value;
    }
  }

  function stamp(state, label) {
    const node = document.querySelector("[data-lineage-source]");
    if (!node) {
      return;
    }
    node.dataset.sourceState = state;
    node.className = `source-stamp source-stamp--${state}`;
    node.textContent = label;
  }

  function render(lineage) {
    if (!entriesElement) {
      return;
    }
    entriesElement.textContent = "";
    lineage.entries.forEach((entry) => {
      const item = document.createElement("li");
      item.className = "console-card";
      item.dataset.lineageEntry = entry.auditId;

      const heading = document.createElement("h3");
      heading.textContent = `${entry.grade || "no grade"} · ${entry.comparison}`;
      item.appendChild(heading);

      const list = document.createElement("dl");
      list.className = "data-list";
      const rows = [
        ["Observed on", entry.observedOn || "not recorded"],
        ["Evidence status", entry.status],
        ["Accepted as baseline", entry.acceptedAsBaseline ? "yes" : "no"],
        ["Battery blocked or flagged", `${entry.blocked}/${entry.total}`],
        ["Transparency log sequence", String(entry.logSeq)],
      ];
      if (entry.enrollmentRevision !== null) {
        rows.push(["Enrollment revision", String(entry.enrollmentRevision)]);
      }
      if (entry.revokedAt !== null) {
        rows.push(["Revoked", String(entry.revokedAt)]);
      }
      rows.forEach(([term, value]) => {
        const row = document.createElement("div");
        const dt = document.createElement("dt");
        dt.textContent = term;
        const dd = document.createElement("dd");
        dd.textContent = value;
        row.appendChild(dt);
        row.appendChild(dd);
        list.appendChild(row);
      });
      item.appendChild(list);

      const link = document.createElement("a");
      link.className = "button secondary";
      link.href = `/badge?audit_id=${encodeURIComponent(entry.auditId)}`;
      link.textContent = "Verify this record";
      item.appendChild(link);

      entriesElement.appendChild(item);
    });
    entriesElement.hidden = lineage.entries.length === 0;
    if (emptyElement) {
      emptyElement.hidden = lineage.entries.length !== 0;
    }
  }

  async function load(targetId) {
    text("[data-lineage-verification]", "");
    if (verifyButton) {
      verifyButton.disabled = true;
    }
    try {
      const lineage = await fetchLineage(targetId, root.fetch.bind(root));
      if (lineage === null) {
        loaded = null;
        if (entriesElement) {
          entriesElement.textContent = "";
          entriesElement.hidden = true;
        }
        if (emptyElement) {
          emptyElement.hidden = false;
        }
        container.dataset.state = "empty";
        stamp("unknown", "NOT FOUND · no lineage for that target");
        text("[data-lineage-heading]", "No lineage recorded");
        text(
          "[data-lineage-status]",
          "That target id has no signed recurring audit evidence yet.",
        );
        return;
      }
      loaded = lineage;
      render(lineage);
      container.dataset.state = "loaded";
      stamp("live", `LIVE · ${lineage.total} signed record(s)`);
      const trajectory = gradeTrajectory(lineage);
      text(
        "[data-lineage-heading]",
        trajectory ? `Grade history: ${trajectory}` : "Audit evidence lineage",
      );
      text(
        "[data-lineage-status]",
        `${lineage.total} signed point-in-time record(s) for ${lineage.targetId}.`,
      );
      text(
        "[data-lineage-raw-description]",
        "The lineage response returned by the service:",
      );
      text("[data-lineage-raw-json]", JSON.stringify(lineage, null, 2));
      if (lineage.limitations) {
        text("[data-lineage-limitations]", lineage.limitations);
      }
      if (verifyButton) {
        verifyButton.disabled = false;
      }
    } catch (error) {
      loaded = null;
      container.dataset.state = "error";
      stamp("unknown", "UNAVAILABLE · lineage not loaded");
      text("[data-lineage-heading]", "Lineage unavailable");
      text("[data-lineage-status]", error.message);
    }
  }

  if (form) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      load(input && input.value ? input.value.trim() : "");
    });
  }

  if (verifyButton) {
    verifyButton.addEventListener("click", async () => {
      if (!loaded) {
        return;
      }
      text(
        "[data-lineage-verification]",
        "Verifying transparency-log inclusion…",
      );
      try {
        const result = await verifyLogInclusion(
          loaded,
          root.WardenTransparencyLog,
          root.fetch.bind(root),
          root.crypto,
        );
        text(
          "[data-lineage-verification]",
          result.ok
            ? `Verified: all ${result.checked} record(s) are included in the hash-chained public log.`
            : `Not verified: ${result.reason}`,
        );
      } catch (error) {
        text("[data-lineage-verification]", `Not verified: ${error.message}`);
      }
    });
  }

  const requested = new URLSearchParams(
    root.location ? root.location.search : "",
  ).get("target");
  if (requested) {
    if (input) {
      input.value = requested;
    }
    load(requested);
  }
})(typeof globalThis === "undefined" ? this : globalThis);
