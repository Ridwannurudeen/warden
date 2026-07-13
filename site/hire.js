(function (root) {
  "use strict";

  function decodeBase64(value) {
    if (typeof root.atob === "function") {
      const bytes = Uint8Array.from(root.atob(value), (character) =>
        character.charCodeAt(0),
      );
      return new TextDecoder().decode(bytes);
    }
    return Buffer.from(value, "base64").toString("utf8");
  }

  function decimalIdentifier(value, label, required) {
    const normalized = String(value || "").trim();
    if (!normalized && !required) {
      return "";
    }
    if (!/^\d+$/.test(normalized)) {
      throw new Error(`${label} must contain decimal digits only`);
    }
    return normalized.replace(/^0+(?=\d)/, "");
  }

  function boundedText(value, label, required, maxLength) {
    const normalized = String(value || "").trim();
    if (!normalized && !required) {
      return "";
    }
    if (
      !normalized ||
      normalized.length > maxLength ||
      /[\0\r\n]/.test(normalized)
    ) {
      throw new Error(
        `${label} must be a single line of at most ${maxLength} characters`,
      );
    }
    return normalized;
  }

  function quoteArgument(value, shell) {
    const normalized = String(value);
    if (normalized.includes("\0")) {
      throw new Error("Command arguments cannot contain a null byte");
    }
    if (shell === "powershell") {
      return `'${normalized.replaceAll("'", "''")}'`;
    }
    if (shell === "posix") {
      return `'${normalized.replaceAll("'", `'\"'\"'`)}'`;
    }
    throw new Error("Choose PowerShell or POSIX shell quoting");
  }

  function acceptanceFor(service, accepts) {
    if (!Array.isArray(accepts) || accepts.length === 0) {
      throw new Error("Payment terms do not include a nonempty accepts array");
    }
    const [whole, fraction = ""] = String(service.feeAmount).split(".");
    if (!/^\d+$/.test(whole) || !/^\d{0,6}$/.test(fraction)) {
      throw new Error(
        "Service fee cannot be represented in six-decimal USDT units",
      );
    }
    const expectedAmount = (
      BigInt(whole) * 1000000n +
      BigInt(fraction.padEnd(6, "0") || "0")
    ).toString();
    const acceptance = accepts.find(
      (candidate) =>
        candidate &&
        candidate.scheme === "exact" &&
        candidate.network === "eip155:196" &&
        String(candidate.asset || "").toLowerCase() ===
          service.feeTokenAddress.toLowerCase() &&
        candidate.extra?.name === "USDT" &&
        String(candidate.amount) === expectedAmount,
    );
    if (!acceptance) {
      throw new Error(
        "Payment terms do not match the selected service asset or amount on X Layer",
      );
    }
    return acceptance;
  }

  function parsePaymentRequiredHeader(encoded, service) {
    if (!encoded) {
      throw new Error("The 402 response omitted the payment-required header");
    }
    let challenge;
    try {
      challenge = JSON.parse(decodeBase64(encoded));
    } catch (error) {
      throw new Error("The payment-required header is not valid base64 JSON", {
        cause: error,
      });
    }
    if (
      challenge.x402Version !== 2 ||
      challenge.resource?.url !== service.endpoint
    ) {
      throw new Error(
        "The payment challenge endpoint does not match the selected service",
      );
    }
    acceptanceFor(service, challenge.accepts);
    return challenge;
  }

  function parsePaymentResponse(status, encoded, service) {
    if (status !== 402) {
      throw new Error(
        `Expected a 402 payment challenge but received HTTP ${status}`,
      );
    }
    return parsePaymentRequiredHeader(encoded, service);
  }

  function validateRequestBody(service) {
    const body = service.requestBody;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new Error("Request body must be a JSON object");
    }
    if (service.key === "scan") {
      if (
        typeof body.payload !== "string" ||
        !body.payload ||
        body.payload.length > 100000
      ) {
        throw new Error("Scan payload must contain 1 to 100,000 characters");
      }
      if (
        body.context !== undefined &&
        (!body.context ||
          typeof body.context !== "object" ||
          Array.isArray(body.context))
      ) {
        throw new Error("Scan context must be a JSON object");
      }
      return;
    }
    if (service.key === "audit") {
      if (
        typeof body.target_url !== "string" ||
        body.target_url.length > 2048
      ) {
        throw new Error(
          "Audit target_url must contain at most 2,048 characters",
        );
      }
      let target;
      try {
        target = new URL(body.target_url);
      } catch (error) {
        throw new Error("Audit target_url must be a valid URL", {
          cause: error,
        });
      }
      if (!/^https?:$/.test(target.protocol)) {
        throw new Error("Audit target_url must use HTTP or HTTPS");
      }
      if (target.username || target.password) {
        throw new Error("Audit target_url must not contain credentials");
      }
      if (
        !Array.isArray(body.sample_prompts) ||
        body.sample_prompts.length > 20
      ) {
        throw new Error(
          "Audit sample_prompts must be an array with at most 20 entries",
        );
      }
      return;
    }
    throw new Error(
      "The selected service does not have a supported request body",
    );
  }

  function buildCommands({
    providerAgentId,
    service,
    accepts,
    jobId = "",
    reviewerAgentId = "",
    score = "5",
    shell = "powershell",
    verdictConfirmed = false,
  }) {
    const provider = decimalIdentifier(
      providerAgentId,
      "provider agent ID",
      true,
    );
    const serviceId = decimalIdentifier(service.serviceId, "service ID", true);
    const job = boundedText(jobId, "job ID", false, 256);
    const reviewer = decimalIdentifier(
      reviewerAgentId,
      "reviewer agent ID",
      false,
    );
    if (reviewer && (reviewer === provider || reviewer === "4844")) {
      throw new Error(`Agent #${reviewer} must not review Warden`);
    }
    const normalizedScore = String(score).trim();
    if (!/^(?:[0-4](?:\.\d{1,2})?|5(?:\.0{1,2})?)$/.test(normalizedScore)) {
      throw new Error(
        "Review score must be between 0 and 5 with at most two decimals",
      );
    }
    if (service.serviceType !== "A2MCP") {
      throw new Error("The selected service must use A2MCP");
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(service.feeTokenAddress)) {
      throw new Error("The service fee token address is invalid");
    }
    const amount = String(service.feeAmount);
    if (!/^\d+(\.\d+)?$/.test(amount)) {
      throw new Error("Service fee must be a decimal amount");
    }
    validateRequestBody(service);
    const acceptance = acceptanceFor(service, accepts);
    const tokenSymbol = boundedText(
      acceptance.extra?.name,
      "token symbol",
      true,
      16,
    );
    const taskTitle = boundedText(service.taskTitle, "task title", true, 128);
    const taskDescription = boundedText(
      service.taskDescription,
      "task description",
      true,
      512,
    );
    const serviceParams = boundedText(
      service.serviceParams,
      "service parameters",
      true,
      512,
    );
    const quote = (value) => quoteArgument(value, shell);

    const commands = [
      `onchainos agent create-task --description ${quote(taskDescription)} --budget ${amount} --max-budget ${amount} --currency ${tokenSymbol} --title ${quote(taskTitle)} --provider ${provider} --visibility 1`,
      null,
      null,
      null,
      null,
      null,
    ];
    if (!job) {
      return commands;
    }

    commands[1] = `onchainos agent set-asp ${quote(job)} --provider-agent-id ${provider} --service-id ${serviceId} --service-type A2MCP --service-params ${quote(serviceParams)} --service-token-address ${service.feeTokenAddress} --service-token-amount ${amount} --payment-token-symbol ${tokenSymbol} --payment-token-amount ${amount}`;
    commands[2] = `onchainos agent set-payment-mode ${quote(job)} --payment-mode x402 --token-symbol ${tokenSymbol} --token-amount ${amount} --endpoint ${quote(service.endpoint)}`;
    commands[3] = `onchainos agent task-402-pay ${quote(job)} --provider-agent-id ${provider} --accepts ${quote(JSON.stringify(accepts))} --endpoint ${quote(service.endpoint)} --token-symbol ${tokenSymbol} --token-amount ${amount} --body ${quote(JSON.stringify(service.requestBody))}`;
    if (verdictConfirmed) {
      commands[4] = `onchainos agent complete ${quote(job)}`;
      if (reviewer) {
        commands[5] = `onchainos agent feedback-submit --agent-id ${provider} --creator-id ${reviewer} --score ${normalizedScore} --task-id ${quote(job)}`;
      }
    }
    return commands;
  }

  const api = {
    buildCommands,
    parsePaymentResponse,
    parsePaymentRequiredHeader,
    quoteArgument,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  if (!root.document) {
    return;
  }

  const serviceSelect = root.document.querySelector("[data-hire-service]");
  if (!serviceSelect) {
    return;
  }

  const shellSelect = root.document.querySelector("[data-shell]");
  const jobInput = root.document.querySelector("[data-job-id]");
  const reviewerInput = root.document.querySelector("[data-reviewer-id]");
  const scoreInput = root.document.querySelector("[data-review-score]");
  const requestBody = root.document.querySelector("[data-request-body]");
  const verdictConfirmed = root.document.querySelector(
    "[data-verdict-confirmed]",
  );
  const serviceSummary = root.document.querySelector("[data-service-summary]");
  const acceptsStatus = root.document.querySelector("[data-accepts-status]");
  const acceptsOutput = root.document.querySelector("[data-accepts-output]");
  const refreshButton = root.document.querySelector("[data-refresh-accepts]");
  let catalog = null;
  let challenge = null;

  function selectedService() {
    return (
      catalog?.services.find(
        (service) => service.serviceId === serviceSelect.value,
      ) || null
    );
  }

  function setCommands(commands) {
    commands.forEach((command, index) => {
      const step = index + 1;
      const output = root.document.querySelector(
        `[data-command-step="${step}"]`,
      );
      const button = root.document.querySelector(`[data-copy-step="${step}"]`);
      let lockedMessage = "Enter the job ID above.";
      if (step === 5) {
        lockedMessage =
          "Confirm that you received a verdict to unlock this step.";
      } else if (step === 6) {
        lockedMessage = "Confirm the verdict and enter your reviewer agent ID.";
      }
      output.textContent = command || lockedMessage;
      button.disabled = !command;
      button.dataset.command = command || "";
    });
  }

  function renderCommands() {
    const service = selectedService();
    if (!catalog || !service || !challenge) {
      setCommands([null, null, null, null, null, null]);
      return;
    }
    try {
      const configuredService = {
        ...service,
        requestBody: JSON.parse(requestBody.value),
      };
      const commands = buildCommands({
        providerAgentId: catalog.providerAgentId,
        service: configuredService,
        accepts: challenge.accepts,
        jobId: jobInput.value,
        reviewerAgentId: reviewerInput.value,
        score: scoreInput.value,
        shell: shellSelect.value,
        verdictConfirmed: verdictConfirmed.checked,
      });
      setCommands(commands);
      const acceptance = acceptanceFor(service, challenge.accepts);
      serviceSummary.textContent = `${service.serviceName} | ${service.feeAmount} ${acceptance.extra.name} | marketplace service #${service.serviceId}`;
    } catch (error) {
      setCommands([null, null, null, null, null, null]);
      serviceSummary.textContent = error.message;
    }
  }

  async function loadChallenge() {
    const service = selectedService();
    if (!service) {
      return;
    }
    challenge = null;
    setCommands([null, null, null, null, null, null]);
    acceptsStatus.textContent = "Fetching current payment terms...";
    acceptsOutput.textContent = "[]";
    try {
      const endpointPath = new URL(service.endpoint).pathname;
      const response = await root.fetch(endpointPath, {
        method: "GET",
        cache: "no-store",
      });
      challenge = parsePaymentResponse(
        response.status,
        response.headers.get("payment-required"),
        service,
      );
      acceptsOutput.textContent = JSON.stringify(challenge.accepts, null, 2);
      acceptsStatus.textContent =
        "Current terms loaded and matched to the selected listing.";
      renderCommands();
    } catch (error) {
      acceptsStatus.textContent = `Could not load verified payment terms: ${error.message}`;
    }
  }

  function selectService() {
    const service = selectedService();
    requestBody.value = JSON.stringify(service.requestBody, null, 2);
    verdictConfirmed.checked = false;
    loadChallenge();
  }

  root
    .fetch("/data/warden-services.json", {
      headers: { accept: "application/json" },
    })
    .then((response) => {
      if (!response.ok) {
        throw new Error("The service catalog is unavailable");
      }
      return response.json();
    })
    .then((data) => {
      catalog = data;
      for (const service of catalog.services) {
        const option = root.document.createElement("option");
        option.value = service.serviceId;
        option.textContent = `${service.serviceName} - ${service.feeAmount}`;
        serviceSelect.append(option);
      }
      selectService();
    })
    .catch((error) => {
      serviceSummary.textContent = error.message;
    });

  serviceSelect.addEventListener("change", selectService);
  refreshButton.addEventListener("click", loadChallenge);
  for (const control of [
    shellSelect,
    jobInput,
    reviewerInput,
    scoreInput,
    requestBody,
    verdictConfirmed,
  ]) {
    control.addEventListener("input", renderCommands);
  }
  for (const button of root.document.querySelectorAll("[data-copy-step]")) {
    button.addEventListener("click", async () => {
      if (!button.dataset.command) {
        return;
      }
      try {
        await root.navigator.clipboard.writeText(button.dataset.command);
        const original = button.textContent;
        button.textContent = "Copied";
        root.setTimeout(() => {
          button.textContent = original;
        }, 1200);
      } catch (error) {
        acceptsStatus.textContent = `Copy failed: ${error.message}`;
      }
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis);
