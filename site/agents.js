(function (root) {
  "use strict";

  const AGENT_PAGE_SIZE = 50;

  function normalize(value) {
    return String(value || "")
      .trim()
      .toLowerCase();
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
    { query = "", category = "", match = "", audit = "" } = {},
  ) {
    const categories = String(dataset.category || "")
      .split("|")
      .filter(Boolean);
    return (
      matchesSearch(dataset.search, query) &&
      (!category || categories.includes(category)) &&
      (!match || dataset.match === match) &&
      (!audit || dataset.audit === audit)
    );
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
    compareAgentRows,
    focusIndexAfterAgentExpansion,
    matchesAgentFilters,
    matchesDocumentFilters,
    selectAgentRows,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  const agentResults = document.querySelector("[data-agent-results]");
  if (agentResults) {
    const rows = Array.from(agentResults.querySelectorAll("[data-agent-row]"));
    const search = document.querySelector("[data-agent-search]");
    const category = document.querySelector("[data-agent-category]");
    const match = document.querySelector("[data-agent-match]");
    const audit = document.querySelector("[data-agent-audit]");
    const sort = document.querySelector("[data-agent-sort]");
    const reset = document.querySelector("[data-agent-reset]");
    const controls = document.querySelector("[data-agent-controls]");
    const renderedCount = document.querySelector("[data-agent-rendered]");
    const matchingCount = document.querySelector("[data-agent-visible]");
    const more = document.querySelector("[data-agent-more]");
    const empty = document.querySelector("[data-agent-empty]");
    let orderedRows;
    let visibleLimit = AGENT_PAGE_SIZE;

    controls.hidden = false;

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
      more.hidden = remaining === 0;
      more.textContent = `Show ${Math.min(AGENT_PAGE_SIZE, remaining).toLocaleString()} more agents`;
      empty.hidden = matchingRows.length !== 0;
    }

    search.addEventListener("input", () => renderAgents(true));
    for (const control of [category, match, audit]) {
      control.addEventListener("change", () => renderAgents(true));
    }
    sort.addEventListener("change", () => {
      orderRows();
      renderAgents(true);
    });
    more.addEventListener("click", () => {
      const previousRendered = agentResults.childElementCount;
      visibleLimit += AGENT_PAGE_SIZE;
      renderAgents();
      const focusIndex = focusIndexAfterAgentExpansion(
        previousRendered,
        agentResults.childElementCount,
      );
      agentResults.children[focusIndex]?.focus();
    });
    reset.addEventListener("click", () => {
      search.value = "";
      category.value = "";
      match.value = "";
      audit.value = "";
      sort.value = "sold-desc";
      orderRows();
      renderAgents(true);
      search.focus();
    });
    orderRows();
    renderAgents(true);
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
