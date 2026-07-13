(function (root) {
  "use strict";

  function decimalIdentifier(value, label) {
    const normalized = String(value || "").trim();
    if (!/^\d+$/.test(normalized)) {
      throw new Error(`${label} must contain decimal digits only`);
    }
    return normalized.replace(/^0+(?=\d)/, "");
  }

  function shellSingleQuote(value) {
    return `'${String(value).replaceAll("'", `'"'"'`)}'`;
  }

  function buildIntegrationExamples({ providerAgentId, service }) {
    const provider = decimalIdentifier(providerAgentId, "provider agent ID");
    const serviceId = decimalIdentifier(service?.serviceId, "service ID");
    const endpoint = String(service?.endpoint || "");
    const serviceName = String(service?.serviceName || "").trim();
    const price = String(service?.feeAmount || "").trim();
    const serviceKey = String(service?.key || "").trim();
    if (!serviceName || !/^\d+(?:\.\d+)?$/.test(price)) {
      throw new Error("Service name and decimal price are required");
    }
    if (!["scan", "audit"].includes(serviceKey)) {
      throw new Error("Service key must be scan or audit");
    }
    let endpointUrl;
    try {
      endpointUrl = new URL(endpoint);
    } catch (error) {
      throw new Error("Service endpoint must be a valid URL", { cause: error });
    }
    if (endpointUrl.protocol !== "https:") {
      throw new Error("Service endpoint must use HTTPS");
    }
    if (
      !service.requestBody ||
      typeof service.requestBody !== "object" ||
      Array.isArray(service.requestBody)
    ) {
      throw new Error("Service request body must be a JSON object");
    }

    const requestJson = JSON.stringify(service.requestBody);
    const requestPretty = JSON.stringify(service.requestBody, null, 2);
    const pythonResult =
      serviceKey === "audit"
        ? `score = result.get("score")
grade = result.get("grade")
audit_results = result.get("results")
recommendations = result.get("recommendations")
if (
    not isinstance(score, (int, float))
    or not isinstance(grade, str)
    or not isinstance(audit_results, list)
    or not isinstance(recommendations, list)
):
    raise RuntimeError("Malformed Warden audit response")

failed_tests = [item for item in audit_results if item.get("blocked") is not True]
print({
    "score": score,
    "grade": grade,
    "failed_tests": failed_tests,
    "recommendations": recommendations,
    "badge": result.get("badge"),
})`
        : `verdict = result.get("verdict")
if verdict == "ALLOW":
    action_payload = ${JSON.stringify(service.requestBody.payload)}
elif verdict == "SANITIZE":
    action_payload = result.get("sanitized_payload")
    if not isinstance(action_payload, str):
        raise RuntimeError("SANITIZE response omitted sanitized_payload")
elif verdict == "BLOCK":
    raise RuntimeError(result.get("recommendation") or "Warden blocked the action")
else:
    raise RuntimeError(f"Unknown Warden verdict: {verdict!r}")`;
    const typescriptContract =
      serviceKey === "audit"
        ? `type WardenAuditResult = {
  attack_class: string;
  sent: string;
  blocked: boolean;
};

type WardenAuditResponse = {
  score: number;
  grade: string;
  results: WardenAuditResult[];
  badge: string;
  recommendations: string[];
};`
        : `type WardenScanResult =
  | { verdict: "ALLOW"; recommendation: string; sanitized_payload: string }
  | { verdict: "SANITIZE"; recommendation: string; sanitized_payload: string }
  | { verdict: "BLOCK"; recommendation: string; sanitized_payload: string };

function payloadForAction(result: WardenScanResult, original: string): string {
  switch (result.verdict) {
    case "ALLOW":
      return original;
    case "SANITIZE":
      if (typeof result.sanitized_payload !== "string") {
        throw new Error("SANITIZE response omitted sanitized_payload");
      }
      return result.sanitized_payload;
    case "BLOCK":
      throw new Error(result.recommendation || "Warden blocked the action");
    default: {
      const impossible: never = result;
      throw new Error(\`Unknown Warden verdict: \${String(impossible)}\`);
    }
  }
}`;
    const typescriptResult =
      serviceKey === "audit"
        ? `const result: unknown = await response.json();
if (
  !result ||
  typeof result !== "object" ||
  typeof (result as WardenAuditResponse).score !== "number" ||
  typeof (result as WardenAuditResponse).grade !== "string" ||
  !Array.isArray((result as WardenAuditResponse).results) ||
  !Array.isArray((result as WardenAuditResponse).recommendations)
) {
  throw new Error("Malformed Warden audit response");
}

const audit = result as WardenAuditResponse;
const failedTests = audit.results.filter((item) => item.blocked !== true);
console.log({
  score: audit.score,
  grade: audit.grade,
  failedTests,
  recommendations: audit.recommendations,
  badge: audit.badge,
});`
        : `const result = (await response.json()) as WardenScanResult;
const actionPayload = payloadForAction(
  result,
  ${JSON.stringify(service.requestBody.payload)},
);`;
    return {
      onchainos: `Use the installed OnchainOS agent tools to create a reviewable task for Warden provider agent #${provider}, service #${serviceId} (${serviceName}, ${price} USDT). Fetch the x402 accepts terms from ${endpoint}, verify the endpoint, token, network, and amount, then pay through the task-402 flow. Return Warden's full result before completing the task. Do not submit feedback until I have reviewed the result.\n\nRequest body:\n${requestPretty}`,
      curl: `# The first request is free and returns the x402 challenge.
curl -i ${endpoint}

# Run only in the shell process that received an authorized payment signature.
# This replay spends ${price} USDT for service #${serviceId}.
test -n "$PAYMENT_SIGNATURE" || { echo "PAYMENT_SIGNATURE is required" >&2; exit 1; }
curl --fail-with-body -sS ${endpoint} \\
  -H "content-type: application/json" \\
  -H "PAYMENT-SIGNATURE: $PAYMENT_SIGNATURE" \\
  --data ${shellSingleQuote(requestJson)}`,
      python: `import os\n\nimport httpx\n\npayment_signature = os.environ.get("PAYMENT_SIGNATURE")\nif not payment_signature:\n    raise RuntimeError("PAYMENT_SIGNATURE is required in the server or agent runtime")\n\n# This request spends ${price} USDT for Warden service #${serviceId}.\nresponse = httpx.post(\n    "${endpoint}",\n    headers={"PAYMENT-SIGNATURE": payment_signature},\n    json=${requestPretty},\n    timeout=30,\n)\nif response.status_code == 402:\n    raise RuntimeError("Payment was not accepted; refresh and validate the x402 challenge")\nresponse.raise_for_status()\nresult = response.json()\n\n${pythonResult}`,
      typescript: `${typescriptContract}\n\n// Server or agent runtime only. Never bundle this value into browser code.\nconst paymentSignature = process.env.PAYMENT_SIGNATURE;\nif (!paymentSignature) throw new Error("PAYMENT_SIGNATURE is required");\n\n// This request spends ${price} USDT for Warden service #${serviceId}.\nconst response = await fetch("${endpoint}", {\n  method: "POST",\n  headers: {\n    "content-type": "application/json",\n    "PAYMENT-SIGNATURE": paymentSignature,\n  },\n  body: JSON.stringify(${requestPretty}),\n});\nif (response.status === 402) {\n  throw new Error("Payment was not accepted; refresh and validate the x402 challenge");\n}\nif (!response.ok) throw new Error(\`Warden returned HTTP \${response.status}\`);\n\n${typescriptResult}`,
      mcp: `{
  "mcpServers": {
    "warden": {
      "command": "python",
      "args": ["-m", "warden.mcp_server"],
      "cwd": "C:/absolute/path/to/warden"
    }
  }
}

Local MCP does not spend ${price} USDT or call marketplace service #${serviceId} at ${endpoint}. It exposes scan_payload and audit_agent from your local checkout.`,
    };
  }

  function decisionPayload(result, originalPayload) {
    if (!result || typeof result !== "object") {
      throw new Error("Warden result must be an object");
    }
    if (result.verdict === "ALLOW") {
      return originalPayload;
    }
    if (result.verdict === "SANITIZE") {
      if (typeof result.sanitized_payload !== "string") {
        throw new Error("SANITIZE response omitted sanitized_payload");
      }
      return result.sanitized_payload;
    }
    if (result.verdict === "BLOCK") {
      throw new Error(result.recommendation || "Warden blocked the action");
    }
    throw new Error(`Unknown Warden verdict: ${String(result.verdict)}`);
  }

  function nextTabIndex(currentIndex, key, count) {
    if (!Number.isInteger(count) || count < 1) {
      return currentIndex;
    }
    if (key === "ArrowRight") {
      return (currentIndex + 1) % count;
    }
    if (key === "ArrowLeft") {
      return (currentIndex - 1 + count) % count;
    }
    if (key === "Home") {
      return 0;
    }
    if (key === "End") {
      return count - 1;
    }
    return currentIndex;
  }

  const api = { buildIntegrationExamples, decisionPayload, nextTabIndex };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const document = root.document;
  const tabs = Array.from(document.querySelectorAll("[data-surface-tab]"));
  const panels = Array.from(document.querySelectorAll("[data-surface-panel]"));
  const serviceSelect = document.querySelector("[data-integrate-service]");
  const catalogStatus = document.querySelector(
    "[data-integrate-catalog-status]",
  );
  const retryButton = document.querySelector("[data-integrate-retry]");
  let catalog = null;

  function selectTab(tab) {
    const selected = tab.dataset.surfaceTab;
    for (const candidate of tabs) {
      const active = candidate === tab;
      candidate.setAttribute("aria-selected", String(active));
      candidate.tabIndex = active ? 0 : -1;
    }
    for (const panel of panels) {
      panel.hidden = panel.dataset.surfacePanel !== selected;
    }
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      const next = nextTabIndex(index, event.key, tabs.length);
      if (next === index && !["Home", "End"].includes(event.key)) {
        return;
      }
      event.preventDefault();
      selectTab(tabs[next]);
      tabs[next].focus();
    });
  });

  function setText(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function selectedService() {
    return (
      catalog?.services.find(
        (service) => service.serviceId === serviceSelect.value,
      ) || null
    );
  }

  function renderService() {
    const service = selectedService();
    if (!service) {
      return;
    }
    const examples = buildIntegrationExamples({
      providerAgentId: catalog.providerAgentId,
      service,
    });
    setText("[data-integrate-service-name]", service.serviceName);
    setText("[data-integrate-service-id]", `#${service.serviceId}`);
    setText("[data-integrate-service-price]", `${service.feeAmount} USDT`);
    setText("[data-integrate-service-endpoint]", service.endpoint);
    setText("[data-integrate-service-network]", "eip155:196 · X Layer");
    for (const [surface, example] of Object.entries(examples)) {
      setText(`[data-integration-example="${surface}"]`, example);
    }
  }

  async function loadCatalog() {
    retryButton.hidden = true;
    retryButton.disabled = true;
    serviceSelect.disabled = true;
    serviceSelect.replaceChildren();
    catalogStatus.textContent = "Loading the normalized service catalog...";
    try {
      const response = await root.fetch("/data/warden-services.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`Catalog request failed with HTTP ${response.status}`);
      }
      const payload = await response.json();
      if (!Array.isArray(payload.services) || payload.services.length === 0) {
        throw new Error("The service catalog contains no services");
      }
      catalog = payload;
      for (const service of catalog.services) {
        const option = document.createElement("option");
        option.value = service.serviceId;
        option.textContent = `${service.serviceName} · ${service.feeAmount} USDT`;
        serviceSelect.append(option);
      }
      serviceSelect.disabled = false;
      catalogStatus.textContent = `Catalog snapshot ${catalog.snapshotFetchedAt}. Service display values and examples use this source.`;
      renderService();
    } catch (error) {
      catalog = null;
      catalogStatus.textContent = `${error.message}.`;
      retryButton.hidden = false;
      retryButton.disabled = false;
    }
  }

  serviceSelect?.addEventListener("change", renderService);
  retryButton?.addEventListener("click", loadCatalog);
  if (tabs.length > 0) {
    selectTab(tabs[0]);
  }
  if (serviceSelect && catalogStatus && retryButton) {
    loadCatalog();
  }
})(typeof globalThis === "undefined" ? this : globalThis);
