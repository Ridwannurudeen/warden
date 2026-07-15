(function (root) {
  "use strict";

  function resolveTheme(storedTheme, prefersLight) {
    if (storedTheme === "light" || storedTheme === "dark") {
      return storedTheme;
    }
    // Luminous Trust: warm light landing is the default welcome.
    return "light";
  }

  function cycleFocusIndex(currentIndex, direction, count) {
    if (!Number.isInteger(count) || count < 1) {
      return -1;
    }
    const step = direction === "backward" ? -1 : 1;
    const start =
      Number.isInteger(currentIndex) &&
      currentIndex >= 0 &&
      currentIndex < count
        ? currentIndex
        : direction === "backward"
          ? 0
          : -1;
    return (start + step + count) % count;
  }

  function catalogServiceByKey(catalog, key) {
    if (!Array.isArray(catalog?.services)) {
      return null;
    }
    return catalog.services.find((service) => service?.key === key) || null;
  }

  function summaryToRestoreOnEscape(activeElement) {
    const group = activeElement?.closest?.("details[open]");
    return group?.querySelector?.("summary") || null;
  }

  function isOutsideNavigationPointer(siteNav, navToggle, target) {
    return !siteNav?.contains?.(target) && !navToggle?.contains?.(target);
  }

  function focusStatusTarget(element) {
    if (!element || typeof element.focus !== "function") {
      return false;
    }
    element.tabIndex = -1;
    element.focus();
    return true;
  }

  function copyButtonBaseLabel(button) {
    if (!button?.dataset) {
      return "";
    }
    if (!("copyBaseLabel" in button.dataset)) {
      button.dataset.copyBaseLabel = button.textContent;
    }
    return button.dataset.copyBaseLabel;
  }

  function normalizeEvidenceCount(value, label) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative integer`);
    }
    return value;
  }

  function isHealthyResponse(value) {
    return value?.status === "ok";
  }

  const api = {
    catalogServiceByKey,
    copyButtonBaseLabel,
    cycleFocusIndex,
    focusStatusTarget,
    isHealthyResponse,
    isOutsideNavigationPointer,
    normalizeEvidenceCount,
    resolveTheme,
    summaryToRestoreOnEscape,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenUI = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  document.documentElement.classList.add("js-enabled");
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
    const navClose = document.createElement("button");
    navClose.className = "nav-close";
    navClose.type = "button";
    navClose.textContent = "Close menu";
    siteNav.prepend(navClose);

    function setNavigationIsolation(isolated) {
      for (const element of document.querySelectorAll(
        ".skip-link, .site-header > :not([data-site-nav]), main, .site-footer",
      )) {
        element.inert = isolated;
      }
    }

    function focusableNavigationElements() {
      const candidates = Array.from(
        siteNav.querySelectorAll(
          "summary, a[href], button:not([disabled]), input:not([disabled]), select:not([disabled])",
        ),
      );
      return candidates.filter((element) => {
        const closedGroup = element.closest("details:not([open])");
        const visibleGroup = !closedGroup || element.tagName === "SUMMARY";
        return visibleGroup && element.getClientRects().length > 0;
      });
    }

    function setNavigation(open, restoreFocus) {
      siteNav.classList.toggle("is-open", open);
      document.body.classList.toggle("nav-open", open);
      navToggle.setAttribute("aria-expanded", String(open));
      setNavigationIsolation(open);
      if (open) {
        const first = focusableNavigationElements()[0];
        first?.focus();
      } else {
        for (const group of siteNav.querySelectorAll("details[open]")) {
          group.open = false;
        }
        if (restoreFocus) {
          navToggle.focus();
        }
      }
    }

    navToggle.addEventListener("click", () => {
      const open = !siteNav.classList.contains("is-open");
      setNavigation(open, false);
    });
    navClose.addEventListener("click", () => {
      setNavigation(false, true);
    });
    siteNav.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        setNavigation(false, false);
      }
    });
    for (const group of siteNav.querySelectorAll("details")) {
      group.addEventListener("toggle", () => {
        if (!group.open) {
          return;
        }
        for (const sibling of siteNav.querySelectorAll("details[open]")) {
          if (sibling !== group) {
            sibling.open = false;
          }
        }
      });
    }
    document.addEventListener("pointerdown", (event) => {
      if (!isOutsideNavigationPointer(siteNav, navToggle, event.target)) {
        return;
      }
      if (siteNav.classList.contains("is-open")) {
        setNavigation(false, false);
        return;
      }
      for (const group of siteNav.querySelectorAll("details[open]")) {
        group.open = false;
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (siteNav.classList.contains("is-open")) {
          setNavigation(false, true);
        } else {
          const summary = summaryToRestoreOnEscape(document.activeElement);
          for (const group of siteNav.querySelectorAll("details[open]")) {
            group.open = false;
          }
          summary?.focus();
        }
        return;
      }
      if (event.key === "Tab" && siteNav.classList.contains("is-open")) {
        const focusable = focusableNavigationElements();
        const current = focusable.indexOf(document.activeElement);
        const next = cycleFocusIndex(
          current,
          event.shiftKey ? "backward" : "forward",
          focusable.length,
        );
        event.preventDefault();
        focusable[next]?.focus();
      }
    });
    root.addEventListener("resize", () => {
      if (
        root.matchMedia?.("(min-width: 1061px)").matches &&
        siteNav.classList.contains("is-open")
      ) {
        setNavigation(false, false);
      }
    });
  }

  const healthLabels = Array.from(
    document.querySelectorAll("[data-health-label]"),
  );
  const healthDots = Array.from(document.querySelectorAll("[data-health-dot]"));
  if (
    !document.querySelector("[data-status-page]") &&
    (healthLabels.length || healthDots.length)
  ) {
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
        if (!isHealthyResponse(health)) {
          throw new Error("Malformed health response");
        }
        for (const label of healthLabels) {
          label.textContent =
            label.dataset.healthDetail === "full"
              ? `API ${health.status}`
              : "API live";
          label.closest("a")?.setAttribute("aria-label", "API status: live");
        }
        for (const dot of healthDots) {
          dot.classList.add("is-ok");
        }
      })
      .catch(() => {
        for (const label of healthLabels) {
          label.textContent = "API unavailable";
          label
            .closest("a")
            ?.setAttribute("aria-label", "API status: unavailable");
        }
        for (const dot of healthDots) {
          dot.classList.add("is-offline");
        }
      });
  }

  const marketplaceCounts = Array.from(
    document.querySelectorAll("[data-marketplace-count]"),
  );
  if (marketplaceCounts.length) {
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
        const count = normalizeEvidenceCount(
          summary.agentCount,
          "marketplace agent count",
        ).toLocaleString();
        for (const element of marketplaceCounts) {
          element.textContent = count;
        }
        const snapshot = document.querySelector("[data-marketplace-snapshot]");
        if (snapshot) {
          snapshot.textContent = `Snapshot ${summary.fetchedAt}`;
        }
      })
      .catch(() => {
        const snapshot = document.querySelector("[data-marketplace-snapshot]");
        if (snapshot) {
          snapshot.textContent = `Committed snapshot ${snapshot.dataset.fallbackSnapshot}`;
        }
      });
  }

  const serviceCatalog = document.querySelector("[data-service-catalog]");
  if (serviceCatalog) {
    const serviceSnapshot = document.querySelector("[data-service-snapshot]");
    root
      .fetch("/data/warden-services.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((catalog) => {
        for (const card of serviceCatalog.querySelectorAll(
          "[data-service-key]",
        )) {
          const service = catalogServiceByKey(catalog, card.dataset.serviceKey);
          if (!service) {
            continue;
          }
          const price = card.querySelector('[data-service-field="price"]');
          const id = card.querySelector('[data-service-field="id"]');
          if (price) {
            price.textContent = `${service.feeAmount} USDT`;
          }
          if (id) {
            id.textContent = `#${service.serviceId}`;
          }
        }
        serviceCatalog.dataset.snapshot = String(catalog.snapshotFetchedAt);
        if (serviceSnapshot) {
          serviceSnapshot.textContent = `Catalog snapshot ${catalog.snapshotFetchedAt}`;
        }
      })
      .catch(() => {
        serviceCatalog.dataset.snapshot = "dated-fallback";
        if (serviceSnapshot) {
          serviceSnapshot.textContent = `Committed catalog snapshot ${serviceSnapshot.dataset.fallbackSnapshot}`;
        }
      });
  }

  const homeBadgeCount = document.querySelector("[data-home-badge-count]");
  const homeBadgeSource = document.querySelector("[data-home-badge-source]");
  if (homeBadgeCount) {
    root
      .fetch("/api/badges", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((registry) => {
        homeBadgeCount.textContent = normalizeEvidenceCount(
          registry.total,
          "badge count",
        ).toLocaleString();
        if (homeBadgeSource) {
          homeBadgeSource.textContent = "Live signed-record registry";
        }
      })
      .catch(() => {
        homeBadgeCount.textContent = "—";
        if (homeBadgeSource) {
          homeBadgeSource.textContent = "Live registry unavailable";
        }
      });
  }

  const homeBypassCount = document.querySelector("[data-home-bypass-count]");
  const homeBypassSource = document.querySelector("[data-home-bypass-source]");
  if (homeBypassCount) {
    root
      .fetch("/api/demo/gauntlet/stats", {
        headers: { accept: "application/json" },
        cache: "no-store",
      })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((stats) => {
        homeBypassCount.textContent = normalizeEvidenceCount(
          stats.confirmed_bypasses,
          "confirmed bypass count",
        ).toLocaleString();
        if (homeBypassSource) {
          homeBypassSource.textContent = "Live human-confirmed Gauntlet count";
        }
      })
      .catch(() => {
        homeBypassCount.textContent = "—";
        if (homeBypassSource) {
          homeBypassSource.textContent = "Live Gauntlet count unavailable";
        }
      });
  }

  let toastRegion = document.querySelector("[data-toast-region]");
  if (!toastRegion) {
    toastRegion = document.createElement("div");
    toastRegion.className = "toast-region";
    toastRegion.dataset.toastRegion = "";
    toastRegion.setAttribute("aria-live", "polite");
    toastRegion.setAttribute("aria-atomic", "true");
    document.body.append(toastRegion);
  }

  for (const button of document.querySelectorAll("[data-copy-target]")) {
    const baseLabel = copyButtonBaseLabel(button);
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) {
        return;
      }
      try {
        await root.navigator.clipboard.writeText(target.textContent);
        button.textContent = "Copied";
        toastRegion.textContent = "Copied to clipboard.";
        root.setTimeout(() => {
          button.textContent = baseLabel;
          toastRegion.textContent = "";
        }, 1200);
      } catch (error) {
        button.textContent = baseLabel;
        toastRegion.textContent = `Copy failed: ${error.message}`;
      }
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis);
