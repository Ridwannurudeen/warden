(function (root) {
  "use strict";

  function buildDemoRequest(payload, expectedAddresses) {
    if (!payload || !payload.trim()) {
      throw new Error("The payload cannot be blank");
    }
    if (payload.length > 4000) {
      throw new Error("The payload cannot exceed 4,000 characters");
    }
    const expected = String(expectedAddresses || "")
      .split(/[\n,]/)
      .map((address) => address.trim())
      .filter(Boolean);
    if (expected.length > 20) {
      throw new Error("Use at most 20 expected addresses");
    }
    return { payload, context: { expected_addresses: expected } };
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { buildDemoRequest };
  }

  if (!root.document) {
    return;
  }

  const form = root.document.querySelector("[data-playground-form]");
  if (!form) {
    return;
  }

  const exampleSelect = root.document.querySelector("[data-demo-example]");
  const payloadInput = root.document.querySelector("[data-demo-payload]");
  const addressInput = root.document.querySelector("[data-demo-addresses]");
  const clearButton = root.document.querySelector("[data-clear-demo]");
  const status = root.document.querySelector("[data-demo-status]");
  const result = root.document.querySelector("[data-demo-result]");
  const submitButton = form.querySelector('button[type="submit"]');
  const examples = new Map();

  root
    .fetch("/api/demo/examples", { headers: { accept: "application/json" } })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`Examples returned HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((records) => {
      for (const example of records) {
        examples.set(example.id, example);
        const option = root.document.createElement("option");
        option.value = example.id;
        option.textContent = example.reason_code
          ? `${example.label} — ${example.reason_code}`
          : example.label;
        exampleSelect.append(option);
      }
      status.textContent = `${records.length} curated examples loaded.`;
    })
    .catch((error) => {
      status.textContent = `Examples unavailable: ${error.message}`;
    });

  exampleSelect.addEventListener("change", () => {
    const example = examples.get(exampleSelect.value);
    if (!example) {
      return;
    }
    payloadInput.value = example.payload;
    addressInput.value =
      example.id === "drain-001"
        ? "0x1111111111111111111111111111111111111111"
        : "";
  });

  clearButton.addEventListener("click", () => {
    form.reset();
    result.hidden = true;
    status.textContent = "Ready for a new payload.";
    payloadInput.focus();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    result.hidden = true;
    submitButton.disabled = true;
    status.textContent = "Scanning with Warden's fast path...";
    try {
      const request = buildDemoRequest(payloadInput.value, addressInput.value);
      const response = await root.fetch("/api/demo/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(request),
      });
      const data = await response.json();
      if (!response.ok) {
        const retry = response.headers.get("Retry-After");
        throw new Error(
          response.status === 429 && retry
            ? `Public demo rate limit reached. Retry in ${retry} seconds.`
            : data.detail || `Scan returned HTTP ${response.status}`,
        );
      }
      root.document.querySelector("[data-demo-verdict]").textContent =
        data.verdict;
      root.document.querySelector("[data-demo-risk]").textContent =
        data.risk_level;
      root.document.querySelector("[data-demo-classes]").textContent =
        data.threat_classes.join(", ") || "None";
      root.document.querySelector("[data-demo-detections]").textContent =
        String(data.detections.length);
      root.document.querySelector("[data-demo-latency]").textContent =
        `${data.latency_ms} ms`;
      root.document.querySelector("[data-demo-summary]").textContent =
        data.verdict === "ALLOW"
          ? "No implemented fast detector fired. Continue only under your own policy."
          : data.recommendation;
      root.document.querySelector("[data-demo-json]").textContent =
        JSON.stringify(data, null, 2);
      result.hidden = false;
      status.textContent = "Scan complete.";
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submitButton.disabled = false;
    }
  });
})(typeof globalThis === "undefined" ? this : globalThis);
