(function (root) {
  "use strict";

  const GENESIS_PREV_HASH = "0".repeat(64);
  const HEX_HASH = /^[0-9a-f]{64}$/;

  function canonicalValue(value) {
    if (Array.isArray(value)) {
      return value.map(canonicalValue);
    }
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, canonicalValue(value[key])]),
      );
    }
    return value;
  }

  function canonicalJson(value) {
    return JSON.stringify(canonicalValue(value));
  }

  function normalizeLogEntry(entry, index) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`Entry ${index + 1} must be an object`);
    }
    if (!Number.isInteger(entry.seq) || entry.seq < 1) {
      throw new Error(`Entry ${index + 1} seq must be a positive integer`);
    }
    if (!Number.isInteger(entry.ts) || entry.ts < 0) {
      throw new Error(`Entry ${index + 1} ts must be a non-negative integer`);
    }
    for (const field of [
      "event",
      "attestation_id",
      "endpoint_host",
      "status",
    ]) {
      if (typeof entry[field] !== "string" || !entry[field]) {
        throw new Error(
          `Entry ${index + 1} ${field} must be a non-empty string`,
        );
      }
    }
    for (const field of ["record_hash", "prev_hash"]) {
      if (typeof entry[field] !== "string" || !HEX_HASH.test(entry[field])) {
        throw new Error(
          `Entry ${index + 1} ${field} must be lowercase SHA-256 hex`,
        );
      }
    }
    return { ...entry };
  }

  function normalizeLogPayload(payload) {
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      throw new Error("Transparency log response must be an object");
    }
    if (!Array.isArray(payload.entries)) {
      throw new Error("Transparency log response omitted entries");
    }
    if (!Number.isInteger(payload.total) || payload.total < 0) {
      throw new Error("Transparency log total must be a non-negative integer");
    }
    if (payload.total !== payload.entries.length) {
      throw new Error("Transparency log total does not match entries length");
    }
    return payload.entries.map(normalizeLogEntry);
  }

  async function sha256Hex(value, cryptoImpl = root.crypto) {
    if (!cryptoImpl?.subtle || typeof root.TextEncoder !== "function") {
      throw new Error("SHA-256 verification is unavailable in this browser");
    }
    const digest = await cryptoImpl.subtle.digest(
      "SHA-256",
      new root.TextEncoder().encode(value),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  }

  async function verifyLogChain(entries, cryptoImpl = root.crypto) {
    const normalized = normalizeLogPayload({ entries, total: entries.length });
    let previousHash = GENESIS_PREV_HASH;

    for (const [index, entry] of normalized.entries()) {
      if (entry.seq !== index + 1) {
        return {
          ok: false,
          index,
          reason: `Entry ${index + 1} breaks the expected sequence.`,
        };
      }
      if (entry.prev_hash !== previousHash) {
        return {
          ok: false,
          index,
          reason:
            index === 0
              ? "Entry 1 does not use the genesis previous hash."
              : `Entry ${index + 1} previous entry hash does not match.`,
        };
      }
      previousHash = await sha256Hex(canonicalJson(entry), cryptoImpl);
    }

    return {
      ok: true,
      total: normalized.length,
      headHash: previousHash,
    };
  }

  function formatTimestamp(seconds) {
    const date = new Date(seconds * 1000);
    if (Number.isNaN(date.getTime())) {
      throw new Error("Log entry timestamp is invalid");
    }
    return date.toISOString();
  }

  const api = {
    GENESIS_PREV_HASH,
    canonicalJson,
    normalizeLogPayload,
    sha256Hex,
    verifyLogChain,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenTransparencyLog = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  const container = document.querySelector("[data-apa-log]");
  if (!container) {
    return;
  }

  const entriesElement = document.querySelector("[data-apa-log-entries]");
  const retryButton = document.querySelector("[data-apa-log-retry]");

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function createFact(label, value, numeric = false) {
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

  function createEntry(entry) {
    const item = document.createElement("li");
    const heading = document.createElement("strong");
    const summary = document.createElement("p");
    const facts = document.createElement("dl");

    heading.textContent = `Entry ${entry.seq}: ${entry.event}`;
    summary.textContent = `${entry.endpoint_host} · status ${entry.status}`;
    facts.className = "data-list";
    facts.append(
      createFact("Observed", formatTimestamp(entry.ts), true),
      createFact("Attestation", entry.attestation_id, true),
      createFact("Record hash", entry.record_hash, true),
      createFact("Previous hash", entry.prev_hash, true),
    );
    item.append(heading, summary, facts);
    return item;
  }

  function renderEntries(entries) {
    if (entries.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty-state";
      empty.textContent = "The issuer has not published any log entries yet.";
      entriesElement.replaceChildren(empty);
      return;
    }
    entriesElement.replaceChildren(...entries.map(createEntry));
  }

  async function loadLog() {
    container.dataset.state = "loading";
    retryButton.disabled = true;
    text("[data-apa-log-status]", "Fetching the current JSON log…");
    text("[data-apa-log-chain]", "Checking");
    try {
      const response = await root.fetch("/apa/log", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`Log request failed with HTTP ${response.status}`);
      }
      const entries = normalizeLogPayload(await response.json());
      const result = await verifyLogChain(entries);
      const observedAt = new Date().toISOString();

      renderEntries(entries);
      text("[data-apa-log-total]", entries.length.toLocaleString());
      text("[data-apa-log-observed]", observedAt);
      if (!result.ok) {
        container.dataset.state = "tampered";
        text("[data-apa-log-chain]", "Chain break detected");
        text("[data-apa-log-head]", "Not accepted");
        text(
          "[data-apa-log-status]",
          `${result.reason} No continuity result is accepted.`,
        );
        return;
      }

      if (entries.length === 0) {
        container.dataset.state = "empty";
        text("[data-apa-log-chain]", "No chain (empty log)");
        text("[data-apa-log-head]", "No entries");
        text(
          "[data-apa-log-status]",
          `The empty log was fetched at ${observedAt}. There is no entry chain to verify.`,
        );
        return;
      }

      container.dataset.state = "verified";
      text("[data-apa-log-chain]", "Continuity verified");
      text("[data-apa-log-head]", result.headHash);
      text(
        "[data-apa-log-status]",
        `${entries.length.toLocaleString()} entries formed one continuous SHA-256 chain at ${observedAt}.`,
      );
    } catch (error) {
      container.dataset.state = "error";
      entriesElement.replaceChildren();
      text("[data-apa-log-total]", "Unavailable");
      text("[data-apa-log-chain]", "Not verified");
      text("[data-apa-log-head]", "Unavailable");
      text("[data-apa-log-observed]", new Date().toISOString());
      text(
        "[data-apa-log-status]",
        `${error.message}. No continuity result is implied.`,
      );
    } finally {
      retryButton.disabled = false;
    }
  }

  retryButton.addEventListener("click", loadLog);
  loadLog();
})(typeof globalThis === "undefined" ? this : globalThis);
