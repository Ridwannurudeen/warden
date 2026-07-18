(function (root) {
  "use strict";

  const AGENT_PAGE_SIZE = 50;

  function normalize(value) {
    return String(value || "")
      .trim()
      .toLowerCase();
  }

  function languageForText(value) {
    const text = String(value || "");
    if (/[\u3040-\u30ff]/u.test(text)) {
      return "ja";
    }
    if (/[\uac00-\ud7af]/u.test(text)) {
      return "ko";
    }
    if (/[\u3400-\u4dbf\u4e00-\u9fff]/u.test(text)) {
      return "zh";
    }
    return "";
  }

  function matchesSearch(haystack, query) {
    const normalizedHaystack = normalize(haystack);
    return normalize(query)
      .split(/\s+/)
      .filter(Boolean)
      .every((term) => normalizedHaystack.includes(term));
  }

  function matchesAgentFilters(
    dataset,
    { query = "", category = "", match = "", audit = "", apa = "" } = {},
  ) {
    const categories = String(dataset.category || "")
      .split("|")
      .filter(Boolean);
    return (
      matchesSearch(dataset.search, query) &&
      (!category || categories.includes(category)) &&
      (!match || dataset.match === match) &&
      (!audit || dataset.audit === audit) &&
      (!apa || dataset.apa === apa)
    );
  }

  function filtersFromSearchParams(value = "") {
    const params =
      value instanceof URLSearchParams
        ? value
        : new URLSearchParams(String(value).replace(/^\?/, ""));
    return {
      query: params.get("q") || "",
      category: params.get("category") || "",
      match: params.get("signal") || "",
      audit: params.get("audit") || "",
      apa: params.get("apa") || "",
      sort: params.get("sort") || "",
    };
  }

  function filtersToSearchParams(filters = {}) {
    const params = new URLSearchParams();
    for (const [parameter, value] of [
      ["q", filters.query],
      ["category", filters.category],
      ["signal", filters.match],
      ["audit", filters.audit],
      ["apa", filters.apa],
      ["sort", filters.sort],
    ]) {
      const normalized = String(value || "").trim();
      if (normalized) {
        params.set(parameter, normalized);
      }
    }
    return params.toString();
  }

  function selectAgentRows(rows, filters = {}, limit = AGENT_PAGE_SIZE) {
    const matchingRows = rows.filter((row) =>
      matchesAgentFilters(row.dataset, filters),
    );
    return {
      matchingRows,
      renderedRows: matchingRows.slice(0, limit),
    };
  }

  function focusIndexAfterAgentExpansion(previousRendered, currentRendered) {
    if (
      !Number.isInteger(previousRendered) ||
      !Number.isInteger(currentRendered) ||
      previousRendered < 0 ||
      currentRendered <= previousRendered
    ) {
      return -1;
    }
    return previousRendered;
  }

  function numeric(value) {
    if (value === "" || value === null || value === undefined) {
      return Number.NEGATIVE_INFINITY;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
  }

  function compareText(left, right) {
    const normalizedLeft = normalize(left);
    const normalizedRight = normalize(right);
    if (normalizedLeft < normalizedRight) {
      return -1;
    }
    if (normalizedLeft > normalizedRight) {
      return 1;
    }
    return 0;
  }

  function compareSoldThenName(left, right) {
    const soldDifference = numeric(right.sold) - numeric(left.sold);
    return (
      soldDifference ||
      compareText(left.name, right.name) ||
      compareText(left.agentId, right.agentId)
    );
  }

  function compareAgentRows(left, right, sort = "sold-desc") {
    if (sort === "name-asc") {
      return (
        compareText(left.name, right.name) ||
        compareText(left.agentId, right.agentId)
      );
    }
    if (sort === "review-desc") {
      return (
        numeric(right.review) - numeric(left.review) ||
        compareSoldThenName(left, right)
      );
    }
    if (sort === "signal-first") {
      const priority = { signal: 2, none: 1, unscanned: 0 };
      return (
        (priority[right.match] || 0) - (priority[left.match] || 0) ||
        compareSoldThenName(left, right)
      );
    }
    if (sort === "audit-first") {
      return (
        Number(right.audit === "audited") - Number(left.audit === "audited") ||
        compareSoldThenName(left, right)
      );
    }
    return compareSoldThenName(left, right);
  }

  function assertAgentIndex(condition, message) {
    if (!condition) {
      throw new TypeError(`Invalid marketplace index: ${message}`);
    }
  }

  function validateAgentIndexPayload(payload) {
    assertAgentIndex(
      payload && typeof payload === "object" && !Array.isArray(payload),
      "payload must be an object",
    );
    assertAgentIndex(payload.schemaVersion === 1, "unsupported schemaVersion");
    assertAgentIndex(
      typeof payload.capturedAt === "string" &&
        /(?:Z|[+-]\d{2}:\d{2})$/.test(payload.capturedAt) &&
        Number.isFinite(Date.parse(payload.capturedAt)),
      "capturedAt must be an ISO timestamp with an offset",
    );
    assertAgentIndex(
      Number.isInteger(payload.sampled) && payload.sampled >= 0,
      "sampled must be a non-negative integer",
    );
    assertAgentIndex(
      typeof payload.hasAudits === "boolean",
      "hasAudits must be a boolean",
    );
    assertAgentIndex(
      typeof payload.hasAttestations === "boolean",
      "hasAttestations must be a boolean",
    );
    assertAgentIndex(
      Array.isArray(payload.records),
      "records must be an array",
    );
    assertAgentIndex(
      payload.sampled === payload.records.length,
      "sampled must equal the record count",
    );

    const agentIds = new Set();
    for (const [index, record] of payload.records.entries()) {
      const prefix = `records[${index}]`;
      assertAgentIndex(
        record && typeof record === "object" && !Array.isArray(record),
        `${prefix} must be an object`,
      );
      assertAgentIndex(
        typeof record.agentId === "string" && /^\d+$/.test(record.agentId),
        `${prefix}.agentId must contain decimal digits only`,
      );
      assertAgentIndex(
        !agentIds.has(record.agentId),
        `${prefix}.agentId must be unique`,
      );
      agentIds.add(record.agentId);
      assertAgentIndex(
        typeof record.name === "string",
        `${prefix}.name must be a string`,
      );
      assertAgentIndex(
        Array.isArray(record.categories) &&
          record.categories.every((category) => typeof category === "string"),
        `${prefix}.categories must contain strings`,
      );
      assertAgentIndex(
        record.sold === null ||
          (Number.isInteger(record.sold) && record.sold >= 0),
        `${prefix}.sold must be a non-negative integer or null`,
      );
      assertAgentIndex(
        record.review === null ||
          (typeof record.review === "number" &&
            Number.isFinite(record.review) &&
            record.review >= 0),
        `${prefix}.review must be a non-negative number or null`,
      );
      assertAgentIndex(
        ["signal", "none", "unscanned"].includes(record.match),
        `${prefix}.match is unsupported`,
      );
      assertAgentIndex(
        typeof record.publicTextLabel === "string",
        `${prefix}.publicTextLabel must be a string`,
      );
      assertAgentIndex(
        record.verdict === null ||
          ["ALLOW", "SANITIZE", "BLOCK"].includes(record.verdict),
        `${prefix}.verdict is unsupported`,
      );
      assertAgentIndex(
        Array.isArray(record.threatClasses) &&
          record.threatClasses.every(
            (threatClass) => typeof threatClass === "string",
          ),
        `${prefix}.threatClasses must contain strings`,
      );
      assertAgentIndex(
        ["audited", "not-audited"].includes(record.audit),
        `${prefix}.audit is unsupported`,
      );
      assertAgentIndex(
        ["attested", "not-attested"].includes(record.apa),
        `${prefix}.apa is unsupported`,
      );
    }
    return payload;
  }

  function agentRecordDataset(record, context = {}) {
    const auditLabel =
      record.audit === "audited"
        ? "Linked signed endpoint audit record"
        : "No linked endpoint audit record";
    const apaLabel =
      record.apa === "attested"
        ? "Linked signed APA guard proof"
        : "No linked APA guard proof";
    const searchParts = [
      record.agentId,
      record.name,
      record.categories.join(", "),
      record.publicTextLabel,
      record.threatClasses.join(" "),
    ];
    if (context.hasAudits) {
      searchParts.push(auditLabel);
    }
    if (context.hasAttestations) {
      searchParts.push(apaLabel);
    }
    return {
      search: searchParts.join(" "),
      category: record.categories.join("|"),
      match: record.match,
      audit: record.audit,
      apa: record.apa,
      name: normalize(record.name),
      agentId: record.agentId,
      sold: record.sold === null ? "" : String(record.sold),
      review: record.review === null ? "" : String(record.review),
    };
  }

  function hydrateAgentRows(payload, rowFactory) {
    const validated = validateAgentIndexPayload(payload);
    assertAgentIndex(
      typeof rowFactory === "function",
      "rowFactory is required",
    );
    const context = {
      capturedAt: validated.capturedAt,
      hasAudits: validated.hasAudits,
      hasAttestations: validated.hasAttestations,
    };
    return validated.records.map((record) => rowFactory(record, context));
  }

  async function fetchAgentIndex(
    fetchImpl = root.fetch?.bind(root),
    url = "/agents/index-data.json",
    {
      timeoutMs = 8000,
      AbortControllerImpl = root.AbortController,
      setTimeoutImpl = root.setTimeout?.bind(root),
      clearTimeoutImpl = root.clearTimeout?.bind(root),
    } = {},
  ) {
    if (typeof fetchImpl !== "function") {
      throw new TypeError("Marketplace index fetch is unavailable");
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError("Marketplace index timeout must be positive");
    }
    if (
      typeof setTimeoutImpl !== "function" ||
      typeof clearTimeoutImpl !== "function"
    ) {
      throw new TypeError("Marketplace index timeout is unavailable");
    }

    const controller =
      typeof AbortControllerImpl === "function"
        ? new AbortControllerImpl()
        : null;
    let timeoutId;
    const timeout = new Promise((_resolve, reject) => {
      timeoutId = setTimeoutImpl(() => {
        reject(
          new Error(
            `Marketplace index request timed out after ${timeoutMs.toLocaleString()}ms`,
          ),
        );
        controller?.abort();
      }, timeoutMs);
    });
    try {
      return await Promise.race([
        Promise.resolve().then(async () => {
          const response = await fetchImpl(url, {
            headers: { Accept: "application/json" },
            ...(controller ? { signal: controller.signal } : {}),
          });
          if (!response?.ok) {
            throw new Error(
              `Marketplace index request failed with HTTP ${response?.status ?? "unknown"}`,
            );
          }
          return validateAgentIndexPayload(await response.json());
        }),
        timeout,
      ]);
    } finally {
      clearTimeoutImpl(timeoutId);
    }
  }

  async function loadAgentRows(
    fetchImpl,
    fallbackRows,
    rowFactory,
    fetchOptions,
  ) {
    try {
      const payload = await fetchAgentIndex(
        fetchImpl,
        "/agents/index-data.json",
        fetchOptions,
      );
      return {
        degraded: false,
        error: null,
        payload,
        rows: hydrateAgentRows(payload, rowFactory),
      };
    } catch (error) {
      return {
        degraded: true,
        error: error instanceof Error ? error : new Error(String(error)),
        payload: null,
        rows: fallbackRows,
      };
    }
  }

  function createAgentIndexLoader({
    fallbackRows,
    expectedTotal,
    expectedCapturedAt,
    loadRows,
  }) {
    assertAgentIndex(
      Array.isArray(fallbackRows),
      "fallbackRows must be an array",
    );
    assertAgentIndex(
      Number.isInteger(expectedTotal) && expectedTotal >= fallbackRows.length,
      "expectedTotal must include every fallback row",
    );
    assertAgentIndex(
      typeof expectedCapturedAt === "string" && expectedCapturedAt,
      "expectedCapturedAt is required",
    );
    assertAgentIndex(typeof loadRows === "function", "loadRows is required");

    let state = expectedTotal > fallbackRows.length ? "fallback" : "loaded";
    let rows = fallbackRows;
    let payload = null;
    let error = null;
    let pending = null;

    function snapshot() {
      return { state, rows, payload, error };
    }

    function degrade(reason) {
      state = "degraded";
      rows = fallbackRows;
      payload = null;
      error = reason instanceof Error ? reason : new Error(String(reason));
      return snapshot();
    }

    async function load() {
      if (state === "loaded" || state === "degraded") {
        return snapshot();
      }
      if (pending) {
        return pending;
      }

      state = "loading";
      pending = (async () => {
        try {
          const loaded = await loadRows();
          if (loaded.degraded) {
            return degrade(loaded.error);
          }
          if (
            loaded.payload.sampled !== expectedTotal ||
            loaded.payload.capturedAt !== expectedCapturedAt
          ) {
            return degrade(
              new Error(
                "Marketplace index metadata does not match the server-rendered snapshot",
              ),
            );
          }
          state = "loaded";
          rows = loaded.rows;
          payload = loaded.payload;
          error = null;
          return snapshot();
        } catch (reason) {
          return degrade(reason);
        } finally {
          pending = null;
        }
      })();
      return pending;
    }

    async function retry() {
      if (state !== "degraded") {
        return load();
      }
      state = "fallback";
      error = null;
      pending = null;
      return load();
    }

    return {
      load,
      retry,
      get error() {
        return error;
      },
      get rows() {
        return rows;
      },
      get state() {
        return state;
      },
    };
  }

  function matchesDocumentFilters(
    dataset,
    { query = "", decision = "", availability = "" } = {},
  ) {
    const decisions = String(dataset.decisions || "")
      .split(/\s+/)
      .filter(Boolean);
    return (
      matchesSearch(dataset.search, query) &&
      (!decision || decisions.includes(decision)) &&
      (!availability || dataset.availability === availability)
    );
  }

  const api = {
    AGENT_PAGE_SIZE,
    agentRecordDataset,
    compareAgentRows,
    createAgentIndexLoader,
    fetchAgentIndex,
    filtersFromSearchParams,
    filtersToSearchParams,
    focusIndexAfterAgentExpansion,
    hydrateAgentRows,
    languageForText,
    loadAgentRows,
    matchesAgentFilters,
    matchesDocumentFilters,
    selectAgentRows,
    validateAgentIndexPayload,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;

  function createAgentRow(record, context) {
    const snapshotDate = context.capturedAt.slice(0, 10);
    const name = record.name || "Unnamed agent";
    const categoriesText = record.categories.join(", ") || "Uncategorized";
    const soldValue =
      record.sold === null ? "Not reported" : record.sold.toLocaleString();
    const reviewValue =
      record.review === null
        ? "No buyer reviews"
        : `${String(record.review.toFixed(2)).replace(/\.?0+$/, "")} / 5`;
    const auditLabel =
      record.audit === "audited"
        ? "Linked signed endpoint audit record"
        : "No linked endpoint audit record";
    const apaLabel =
      record.apa === "attested"
        ? "Linked signed APA guard proof"
        : "No linked APA guard proof";
    const soldLabel =
      record.agentId === "3808" ? `Sold at ${snapshotDate} snapshot` : "Sold";
    const buyerReviewLabel =
      record.agentId === "3808"
        ? `Buyer review at ${snapshotDate} snapshot`
        : "Buyer review average";
    const buyerReviewDataLabel =
      record.agentId === "3808" ? buyerReviewLabel : "Buyer reviews";
    const rowLabelParts = [
      `Agent: ${name}`,
      `Agent ID: ${record.agentId}`,
      `Category: ${categoriesText}`,
      `${soldLabel}: ${soldValue}`,
      `Public listing text: ${record.publicTextLabel}`,
    ];
    if (context.hasAudits) {
      rowLabelParts.push(`Endpoint audit record: ${auditLabel}`);
    }
    if (context.hasAttestations) {
      rowLabelParts.push(`APA attestation: ${apaLabel}`);
    }
    rowLabelParts.push(`${buyerReviewLabel}: ${reviewValue}`);

    const row = document.createElement("a");
    row.className =
      context.hasAudits || context.hasAttestations
        ? "agent-row"
        : "agent-row agent-row--no-evidence";
    row.href = `/agents/${record.agentId}`;
    row.setAttribute("aria-label", rowLabelParts.join("; "));
    row.setAttribute("data-agent-row", "");
    Object.assign(row.dataset, agentRecordDataset(record, context));

    const identity = document.createElement("span");
    const identityName = document.createElement("strong");
    identityName.textContent = name;
    const identityLanguage = languageForText(record.name);
    if (identityLanguage) {
      identityName.lang = identityLanguage;
    }
    const identityId = document.createElement("small");
    identityId.textContent = `Agent #${record.agentId}`;
    identity.append(identityName, identityId);

    const category = document.createElement("span");
    category.dataset.label = "Category";
    category.textContent = categoriesText;

    const sold = document.createElement("span");
    sold.className = "num";
    sold.dataset.label = soldLabel;
    sold.textContent = soldValue;

    const publicText = document.createElement("span");
    publicText.dataset.label = "Public text";
    const publicTextResult = document.createElement("strong");
    publicTextResult.textContent = record.publicTextLabel;
    publicText.append(publicTextResult);

    row.append(identity, category, sold, publicText);
    if (context.hasAudits || context.hasAttestations) {
      const endpointEvidence = document.createElement("span");
      endpointEvidence.dataset.label = "Endpoint evidence";
      const primaryEvidence = document.createElement("strong");
      primaryEvidence.textContent = context.hasAudits ? auditLabel : apaLabel;
      endpointEvidence.append(primaryEvidence);
      if (context.hasAudits && context.hasAttestations) {
        const secondaryEvidence = document.createElement("small");
        secondaryEvidence.textContent = apaLabel;
        endpointEvidence.append(secondaryEvidence);
      }
      row.append(endpointEvidence);
    }

    const buyerReview = document.createElement("span");
    buyerReview.className = "num";
    buyerReview.dataset.label = buyerReviewDataLabel;
    buyerReview.textContent = reviewValue;
    row.append(buyerReview);
    return row;
  }

  const agentResults = document.querySelector("[data-agent-results]");
  if (agentResults) {
    const fallbackRows = Array.from(
      agentResults.querySelectorAll("[data-agent-row]"),
    );
    const search = document.querySelector("[data-agent-search]");
    const category = document.querySelector("[data-agent-category]");
    const match = document.querySelector("[data-agent-match]");
    const audit = document.querySelector("[data-agent-audit]");
    const apa = document.querySelector("[data-agent-apa]");
    const sort = document.querySelector("[data-agent-sort]");
    const reset = document.querySelector("[data-agent-reset]");
    const controls = document.querySelector("[data-agent-controls]");
    const renderedCount = document.querySelector("[data-agent-rendered]");
    const matchingCount = document.querySelector("[data-agent-visible]");
    const more = document.querySelector("[data-agent-more]");
    const empty = document.querySelector("[data-agent-empty]");
    const scope = document.querySelector("[data-agent-scope]");
    const indexState = document.querySelector("[data-agent-index-state]");
    const indexRetry = document.querySelector("[data-agent-index-retry]");
    const expectedTotal = Number(agentResults.dataset.agentTotal);
    const expectedCapturedAt = agentResults.dataset.agentCapturedAt;
    const fullIndexLoader = createAgentIndexLoader({
      fallbackRows,
      expectedTotal,
      expectedCapturedAt,
      loadRows: () =>
        loadAgentRows(root.fetch?.bind(root), fallbackRows, createAgentRow),
    });
    let rows = fullIndexLoader.rows;
    let orderedRows;
    let visibleLimit = AGENT_PAGE_SIZE;

    controls.hidden = false;

    function setSelectValue(control, value) {
      if (
        value &&
        [...control.options].some((option) => option.value === value)
      ) {
        control.value = value;
      }
    }

    const initialFilters = filtersFromSearchParams(root.location?.search);
    search.value = initialFilters.query;
    setSelectValue(category, initialFilters.category);
    setSelectValue(match, initialFilters.match);
    setSelectValue(audit, initialFilters.audit);
    setSelectValue(apa, initialFilters.apa);
    setSelectValue(sort, initialFilters.sort);

    function showIndexState(message = "") {
      indexState.textContent = message;
      indexState.hidden = !message;
    }

    async function ensureFullIndex(retry = false) {
      if (fullIndexLoader.state === "loaded") {
        return true;
      }
      if (fullIndexLoader.state === "degraded" && !retry) {
        return false;
      }

      more.disabled = true;
      indexRetry.hidden = true;
      indexRetry.disabled = true;
      showIndexState("Loading the complete dated index…");
      const result = retry
        ? await fullIndexLoader.retry()
        : await fullIndexLoader.load();
      rows = result.rows;
      if (result.state === "degraded") {
        scope.textContent =
          `Full index unavailable. Search, filters, sorting, and Show more ` +
          `are limited to the first ${fallbackRows.length.toLocaleString()} dated records.`;
        showIndexState(
          "The complete index could not be loaded. The dated server-rendered records remain available.",
        );
        indexRetry.hidden = false;
        indexRetry.disabled = false;
        return false;
      }

      scope.textContent = `All ${rows.length.toLocaleString()} dated snapshot records are loaded.`;
      showIndexState();
      indexRetry.hidden = true;
      indexRetry.disabled = false;
      return true;
    }

    function orderRows() {
      orderedRows = [...rows].sort((left, right) =>
        compareAgentRows(left.dataset, right.dataset, sort.value),
      );
    }

    function renderAgents(resetLimit = false) {
      if (resetLimit) {
        visibleLimit = AGENT_PAGE_SIZE;
      }
      const filters = {
        query: search.value,
        category: category.value,
        match: match.value,
        audit: audit.value,
        apa: apa.value,
      };
      const { matchingRows, renderedRows } = selectAgentRows(
        orderedRows,
        filters,
        visibleLimit,
      );
      agentResults.replaceChildren(...renderedRows);
      renderedCount.textContent = renderedRows.length.toLocaleString();
      matchingCount.textContent = matchingRows.length.toLocaleString();
      const remaining = matchingRows.length - renderedRows.length;
      const completeIndexAvailable =
        fullIndexLoader.state === "fallback" &&
        expectedTotal > fallbackRows.length;
      more.disabled = fullIndexLoader.state === "loading";
      more.hidden =
        (!completeIndexAvailable && remaining === 0) ||
        fullIndexLoader.state === "degraded";
      more.textContent = completeIndexAvailable
        ? `Load ${Math.min(
            AGENT_PAGE_SIZE,
            expectedTotal - fallbackRows.length,
          ).toLocaleString()} more records`
        : `Show ${Math.min(
            AGENT_PAGE_SIZE,
            remaining,
          ).toLocaleString()} more agents`;
      empty.hidden = matchingRows.length !== 0;
      const query = filtersToSearchParams({
        ...filters,
        sort: sort.value === "sold-desc" ? "" : sort.value,
      });
      if (root.history?.replaceState && root.location?.pathname) {
        root.history.replaceState(
          null,
          "",
          `${root.location.pathname}${query ? `?${query}` : ""}`,
        );
      }
    }

    async function loadAndRender(resetLimit = false, reorder = false) {
      await ensureFullIndex();
      if (reorder) {
        orderRows();
      } else if (orderedRows.length !== rows.length) {
        orderRows();
      }
      renderAgents(resetLimit);
    }

    search.addEventListener("input", () => {
      void loadAndRender(true);
    });
    for (const control of [category, match, audit, apa]) {
      control.addEventListener("change", () => {
        void loadAndRender(true);
      });
    }
    sort.addEventListener("change", () => {
      void loadAndRender(true, true);
    });
    more.addEventListener("click", async () => {
      const previousRendered = agentResults.childElementCount;
      await ensureFullIndex();
      orderRows();
      visibleLimit += AGENT_PAGE_SIZE;
      renderAgents();
      const focusIndex = focusIndexAfterAgentExpansion(
        previousRendered,
        agentResults.childElementCount,
      );
      agentResults.children[focusIndex]?.focus();
    });
    indexRetry.addEventListener("click", async () => {
      const recovered = await ensureFullIndex(true);
      orderRows();
      renderAgents();
      if (recovered) {
        search.focus();
      } else {
        indexRetry.focus();
      }
    });
    reset.addEventListener("click", () => {
      search.value = "";
      category.value = "";
      match.value = "";
      audit.value = "";
      apa.value = "";
      sort.value = "sold-desc";
      orderRows();
      renderAgents(true);
      search.focus();
    });
    orderRows();
    renderAgents(true);
    if (
      fullIndexLoader.state === "fallback" &&
      Object.values(initialFilters).some(Boolean)
    ) {
      void loadAndRender(true, true);
    }
  }

  const documentResults = document.querySelector("[data-doc-results]");
  if (documentResults) {
    const entries = Array.from(
      documentResults.querySelectorAll("[data-doc-entry]"),
    );
    const search = document.querySelector("[data-doc-search]");
    const decision = document.querySelector("[data-doc-decision]");
    const availability = document.querySelector("[data-doc-availability]");
    const reset = document.querySelector("[data-doc-reset]");
    const count = document.querySelector("[data-doc-visible]");
    const empty = document.querySelector("[data-doc-empty]");

    function renderDocuments() {
      const filters = {
        query: search.value,
        decision: decision.value,
        availability: availability.value,
      };
      let visible = 0;
      for (const entry of entries) {
        const matches = matchesDocumentFilters(entry.dataset, filters);
        entry.hidden = !matches;
        visible += Number(matches);
      }
      count.textContent = visible.toLocaleString();
      empty.hidden = visible !== 0;
    }

    search.addEventListener("input", renderDocuments);
    decision.addEventListener("change", renderDocuments);
    availability.addEventListener("change", renderDocuments);
    reset.addEventListener("click", () => {
      search.value = "";
      decision.value = "";
      availability.value = "";
      renderDocuments();
      search.focus();
    });
    renderDocuments();
  }
})(typeof globalThis === "undefined" ? this : globalThis);
