(function (root) {
  "use strict";

  const INTENTS = new Set([
    "drain_funds",
    "hijack_tool_call",
    "exfiltrate_secret",
    "override_instructions",
    "malicious_link",
    "other",
  ]);

  function buildGauntletRequest({ intent, payload, finder, expectedAddresses }) {
    if (!INTENTS.has(intent)) {
      throw new Error("Choose a supported attack intent");
    }
    if (!payload || !payload.trim()) {
      throw new Error("The adversarial payload cannot be blank");
    }
    if (payload.length > 4000) {
      throw new Error("The adversarial payload cannot exceed 4,000 characters");
    }
    const normalizedFinder = String(finder || "").trim();
    if (normalizedFinder.length > 128) {
      throw new Error("Finder credit cannot exceed 128 characters");
    }
    const expected = String(expectedAddresses || "")
      .split(/[\n,]/)
      .map((address) => address.trim())
      .filter(Boolean);
    if (expected.length > 20) {
      throw new Error("Use at most 20 expected addresses");
    }
    const request = {
      intent,
      payload,
      context: { expected_addresses: expected },
    };
    if (normalizedFinder) {
      request.finder = normalizedFinder;
    }
    return request;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { buildGauntletRequest };
  }

  if (!root.document) {
    return;
  }

  const form = root.document.querySelector("[data-gauntlet-form]");
  if (!form) {
    return;
  }

  const status = root.document.querySelector("[data-gauntlet-status]");
  const result = root.document.querySelector("[data-gauntlet-result]");
  const verdict = root.document.querySelector("[data-gauntlet-verdict]");
  const message = root.document.querySelector("[data-gauntlet-message]");
  const output = root.document.querySelector("[data-gauntlet-json]");
  const submitButton = form.querySelector('button[type="submit"]');

  async function loadStats() {
    try {
      const response = await root.fetch("/api/demo/gauntlet/stats", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        return;
      }
      const stats = await response.json();
      for (const [key, value] of Object.entries(stats)) {
        const target = root.document.querySelector(`[data-stat="${key}"]`);
        if (target) {
          target.textContent = Number(value).toLocaleString();
        }
      }
    } catch {
      status.textContent = "Live counters are temporarily unavailable.";
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submitButton.disabled = true;
    status.textContent = "Running the real Warden fast-path scan...";
    result.hidden = true;
    try {
      const formData = new FormData(form);
      const request = buildGauntletRequest({
        intent: formData.get("intent"),
        payload: formData.get("payload"),
        finder: formData.get("finder"),
        expectedAddresses: formData.get("expected_addresses"),
      });
      const response = await root.fetch("/api/demo/gauntlet", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(request),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || `Request failed with HTTP ${response.status}`);
      }
      verdict.textContent = data.verdict;
      if (data.claim_status === "pending") {
        message.textContent = "Candidate queued for human review. It is not a confirmed bypass.";
      } else if (data.claim_status === "duplicate") {
        message.textContent = "This candidate is already in the human-review queue.";
      } else {
        message.textContent = "Warden detected the attack path before action.";
      }
      output.textContent = JSON.stringify(data, null, 2);
      result.hidden = false;
      status.textContent = "Scan complete.";
      await loadStats();
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submitButton.disabled = false;
    }
  });

  loadStats();
  root.setInterval(loadStats, 60000);
})(typeof globalThis === "undefined" ? this : globalThis);
