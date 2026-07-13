(function (root) {
  "use strict";

  function resolveTheme(storedTheme, prefersLight) {
    if (storedTheme === "light" || storedTheme === "dark") {
      return storedTheme;
    }
    return prefersLight ? "light" : "dark";
  }

  function matchesAgentFilters(dataset, categoryFilter, matchFilter) {
    const categories = String(dataset.category || "")
      .split(/\s+/)
      .filter(Boolean);
    const categoryMatches =
      !categoryFilter || categories.includes(categoryFilter);
    const matchMatches = !matchFilter || dataset.match === matchFilter;
    return categoryMatches && matchMatches;
  }

  const api = { matchesAgentFilters, resolveTheme };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  const themeButtons = Array.from(
    document.querySelectorAll("[data-theme-toggle]"),
  );
  let storedTheme = null;
  try {
    storedTheme = root.localStorage.getItem("warden-theme");
  } catch {
    storedTheme = null;
  }
  const initialTheme = resolveTheme(
    storedTheme,
    root.matchMedia?.("(prefers-color-scheme: light)").matches === true,
  );

  function setTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    for (const button of themeButtons) {
      const next = theme === "dark" ? "light" : "dark";
      button.textContent = `${next[0].toUpperCase()}${next.slice(1)} theme`;
      button.setAttribute("aria-label", `Switch to ${next} theme`);
    }
    if (persist) {
      try {
        root.localStorage.setItem("warden-theme", theme);
      } catch {
        return;
      }
    }
  }

  setTheme(initialTheme, false);
  for (const button of themeButtons) {
    button.addEventListener("click", () => {
      const next =
        document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      setTheme(next, true);
    });
  }

  const navToggle = document.querySelector("[data-nav-toggle]");
  const siteNav = document.querySelector("[data-site-nav]");
  if (navToggle && siteNav) {
    navToggle.addEventListener("click", () => {
      const open = !siteNav.classList.contains("is-open");
      siteNav.classList.toggle("is-open", open);
      navToggle.setAttribute("aria-expanded", String(open));
    });
    siteNav.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        siteNav.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        siteNav.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  const healthLabels = Array.from(
    document.querySelectorAll("[data-health-label]"),
  );
  const healthDots = Array.from(document.querySelectorAll("[data-health-dot]"));
  if (healthLabels.length || healthDots.length) {
    root
      .fetch("/health", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((health) => {
        for (const label of healthLabels) {
          label.textContent =
            label.dataset.healthDetail === "full"
              ? `API ${health.status}`
              : "API live";
        }
        for (const dot of healthDots) {
          dot.classList.add("is-ok");
        }
      })
      .catch(() => {
        for (const label of healthLabels) {
          label.textContent = "API unavailable";
        }
        for (const dot of healthDots) {
          dot.classList.add("is-offline");
        }
      });
  }

  const marketplaceCount = document.querySelector("[data-marketplace-count]");
  if (marketplaceCount) {
    root
      .fetch("/data/marketplace-summary.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((summary) => {
        marketplaceCount.textContent = Number(
          summary.agentCount,
        ).toLocaleString();
        const snapshot = document.querySelector("[data-marketplace-snapshot]");
        if (snapshot) {
          snapshot.textContent = `Snapshot ${summary.fetchedAt}`;
        }
      })
      .catch(() => {
        const snapshot = document.querySelector("[data-marketplace-snapshot]");
        if (snapshot) {
          snapshot.textContent = "Committed marketplace snapshot";
        }
      });
  }

  const categoryFilter = document.querySelector("[data-agent-category]");
  const matchFilter = document.querySelector("[data-agent-match]");
  const agentRows = Array.from(
    document.querySelectorAll("[data-category][data-match]"),
  );
  if (agentRows.length && categoryFilter && matchFilter) {
    function filterAgents() {
      let visible = 0;
      for (const row of agentRows) {
        const matches = matchesAgentFilters(
          row.dataset,
          categoryFilter.value,
          matchFilter.value,
        );
        row.hidden = !matches;
        visible += Number(matches);
      }
      const count = document.querySelector("[data-agent-visible]");
      if (count) {
        count.textContent = visible.toLocaleString();
      }
    }
    categoryFilter.addEventListener("change", filterAgents);
    matchFilter.addEventListener("change", filterAgents);
    filterAgents();
  }

  for (const button of document.querySelectorAll("[data-copy-target]")) {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) {
        return;
      }
      try {
        await root.navigator.clipboard.writeText(target.textContent);
        const original = button.textContent;
        button.textContent = "Copied";
        root.setTimeout(() => {
          button.textContent = original;
        }, 1200);
      } catch {
        button.textContent = "Copy failed";
      }
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis);
