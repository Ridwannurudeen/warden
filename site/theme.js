(function (root) {
  "use strict";

  if (!root.document) {
    return;
  }

  let storedTheme = null;
  try {
    storedTheme = root.localStorage.getItem("warden-theme");
  } catch {
    storedTheme = null;
  }
  if (storedTheme === "light" || storedTheme === "dark") {
    root.document.documentElement.dataset.theme = storedTheme;
  } else {
    root.document.documentElement.dataset.theme = "dark";
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
