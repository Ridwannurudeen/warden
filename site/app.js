(function () {
  const buttons = Array.from(document.querySelectorAll("[data-tab-target]"));
  const panels = Array.from(document.querySelectorAll("[data-tab-panel]"));
  const tabLinks = Array.from(document.querySelectorAll("[data-link-tab]"));

  function activateTab(tabName, focusPanel) {
    const targetPanel = panels.find((panel) => panel.dataset.tabPanel === tabName) || panels[0];
    const targetName = targetPanel.dataset.tabPanel;

    for (const button of buttons) {
      const isActive = button.dataset.tabTarget === targetName;
      button.classList.toggle("is-active", isActive);
      button.setAttribute("aria-pressed", String(isActive));
    }

    for (const panel of panels) {
      panel.classList.toggle("is-active", panel === targetPanel);
    }

    if (window.location.hash !== `#${targetName}`) {
      history.replaceState(null, "", `#${targetName}`);
    }

    if (focusPanel) {
      targetPanel.focus({ preventScroll: true });
    }
  }

  for (const button of buttons) {
    button.addEventListener("click", () => activateTab(button.dataset.tabTarget, true));
  }

  for (const link of tabLinks) {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      activateTab(link.dataset.linkTab, true);
    });
  }

  window.addEventListener("hashchange", () => {
    const tabName = window.location.hash.replace("#", "");
    if (tabName) {
      activateTab(tabName, false);
    }
  });

  const initialTab = window.location.hash.replace("#", "");
  if (initialTab) {
    activateTab(initialTab, false);
  }

  const healthLabel = document.getElementById("health-label");
  const liveDot = document.querySelector(".live-dot");

  function setHealthState(label, stateClass) {
    if (healthLabel) {
      healthLabel.textContent = label;
    }
    if (liveDot) {
      liveDot.classList.remove("is-ok", "is-offline");
      if (stateClass) {
        liveDot.classList.add(stateClass);
      }
    }
  }

  fetch("/health", { headers: { accept: "application/json" } })
    .then((response) => {
      if (!response.ok) {
        setHealthState("Local preview - API not attached", "is-offline");
        return null;
      }
      return response.json();
    })
    .then((data) => {
      if (!data) {
        return;
      }
      const analyzerCount = Array.isArray(data.analyzers) ? data.analyzers.length : 0;
      setHealthState(
        `Live API ok - ${data.corpus_size} corpus cases - ${analyzerCount} analyzers`,
        "is-ok",
      );
    })
    .catch(() => {
      setHealthState("Local preview - API not attached", "is-offline");
    });
})();
