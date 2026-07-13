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

  function isCurrentHireRequest(
    requestId,
    activeRequestId,
    requestedServiceId,
    selectedServiceId,
  ) {
    return (
      requestId === activeRequestId &&
      String(requestedServiceId) === String(selectedServiceId)
    );
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

  function reviewerIdentifier(value, providerAgentId) {
    const reviewer = decimalIdentifier(value, "reviewer agent ID", false);
    const provider = decimalIdentifier(
      providerAgentId,
      "provider agent ID",
      true,
    );
    if (reviewer && (reviewer === provider || reviewer === "4844")) {
      throw new Error(`Agent #${reviewer} must not review Warden`);
    }
    return reviewer;
  }

  function reviewScore(value) {
    const normalized = String(value).trim();
    if (!/^(?:[0-4](?:\.\d{1,2})?|5(?:\.0{1,2})?)$/.test(normalized)) {
      throw new Error(
        "Review score must be between 0 and 5 with at most two decimals",
      );
    }
    return normalized;
  }

  function validateHireInputs({
    providerAgentId,
    service,
    requestBodyText,
    jobId = "",
    reviewerAgentId = "",
    score = "5",
  }) {
    const errors = {};
    let requestBody = null;
    try {
      requestBody = JSON.parse(String(requestBodyText));
      validateRequestBody({ ...service, requestBody });
    } catch (error) {
      errors.requestBody = error.message;
    }
    try {
      boundedText(jobId, "job ID", false, 256);
    } catch (error) {
      errors.jobId = error.message;
    }
    try {
      reviewerIdentifier(reviewerAgentId, providerAgentId);
    } catch (error) {
      errors.reviewerAgentId = error.message;
    }
    try {
      reviewScore(score);
    } catch (error) {
      errors.score = error.message;
    }
    return {
      errors,
      requestBody,
      valid: Object.keys(errors).length === 0,
    };
  }

  function commandAvailability({
    catalogReady,
    paymentTermsReady,
    readinessConfirmed,
    requestValid,
    hasJobId,
    jobValid = true,
    spendConfirmed,
    verdictConfirmed,
    hasReviewerAgentId,
    reviewerValid = true,
    scoreValid = true,
  }) {
    const create = Boolean(
      catalogReady && paymentTermsReady && readinessConfirmed && requestValid,
    );
    const pay = Boolean(create && hasJobId && jobValid && spendConfirmed);
    const complete = Boolean(pay && verdictConfirmed);
    const review = Boolean(
      complete && hasReviewerAgentId && reviewerValid && scoreValid,
    );
    return { create, pay, complete, review };
  }

  function buildCommands({
    providerAgentId,
    service,
    accepts,
    jobId = "",
    reviewerAgentId = "",
    score = "5",
    shell = "powershell",
    spendConfirmed = false,
    verdictConfirmed = false,
  }) {
    const provider = decimalIdentifier(
      providerAgentId,
      "provider agent ID",
      true,
    );
    const serviceId = decimalIdentifier(service.serviceId, "service ID", true);
    const job = boundedText(jobId, "job ID", false, 256);
    const reviewer = reviewerIdentifier(reviewerAgentId, provider);
    const normalizedScore = reviewScore(score);
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
      `onchainos agent create-task --description ${quote(taskDescription)} --budget ${amount} --max-budget ${amount} --currency ${tokenSymbol} --title ${quote(taskTitle)} --provider ${provider} --visibility 1 --payment-mode x402 --service-id ${serviceId} --service-params ${quote(serviceParams)} --service-token-address ${service.feeTokenAddress} --service-token-amount ${amount}`,
      null,
      null,
      null,
    ];
    if (!job || !spendConfirmed) {
      return commands;
    }

    commands[1] = `onchainos agent task-402-pay ${quote(job)} --provider-agent-id ${provider} --accepts ${quote(JSON.stringify(accepts))} --endpoint ${quote(service.endpoint)} --token-symbol ${tokenSymbol} --token-amount ${amount} --body ${quote(JSON.stringify(service.requestBody))}`;
    if (verdictConfirmed) {
      commands[2] = `onchainos agent complete ${quote(job)}`;
      if (reviewer) {
        commands[3] = `onchainos agent feedback-submit --agent-id ${provider} --creator-id ${reviewer} --score ${normalizedScore} --task-id ${quote(job)}`;
      }
    }
    return commands;
  }

  const api = {
    buildCommands,
    commandAvailability,
    isCurrentHireRequest,
    parsePaymentResponse,
    parsePaymentRequiredHeader,
    quoteArgument,
    validateHireInputs,
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

  const shellInputs = Array.from(
    root.document.querySelectorAll('input[name="hire-shell"]'),
  );
  const jobInput = root.document.querySelector("[data-job-id]");
  const reviewerInput = root.document.querySelector("[data-reviewer-id]");
  const scoreInput = root.document.querySelector("[data-review-score]");
  const requestBody = root.document.querySelector("[data-request-body]");
  const spendConfirmed = root.document.querySelector("[data-spend-confirmed]");
  const verdictConfirmed = root.document.querySelector(
    "[data-verdict-confirmed]",
  );
  const readinessChecks = Array.from(
    root.document.querySelectorAll("[data-readiness-check]"),
  );
  const readinessStatus = root.document.querySelector(
    "[data-readiness-status]",
  );
  const catalogStatus = root.document.querySelector("[data-catalog-status]");
  const retryCatalogButton = root.document.querySelector(
    "[data-retry-catalog]",
  );
  const acceptsStatus = root.document.querySelector("[data-accepts-status]");
  const acceptsOutput = root.document.querySelector("[data-accepts-output]");
  const refreshButton = root.document.querySelector("[data-refresh-accepts]");
  let catalog = null;
  let challenge = null;
  let challengeController = null;
  let challengeRequestId = 0;

  function selectedService() {
    return (
      catalog?.services.find(
        (service) => service.serviceId === serviceSelect.value,
      ) || null
    );
  }

  function setText(selector, value) {
    const element = root.document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function selectedShell() {
    return shellInputs.find((input) => input.checked)?.value || "powershell";
  }

  function readinessConfirmed() {
    return (
      readinessChecks.length > 0 &&
      readinessChecks.every((checkbox) => checkbox.checked)
    );
  }

  function updateReadinessStatus() {
    const confirmed = readinessChecks.filter(
      (checkbox) => checkbox.checked,
    ).length;
    readinessStatus.textContent = readinessConfirmed()
      ? "Readiness confirmed. Step 1 can unlock after payment terms validate."
      : `${confirmed} of ${readinessChecks.length} confirmations complete.`;
  }

  function setFieldError(control, selector, message) {
    const error = root.document.querySelector(selector);
    if (error) {
      error.textContent = message || "";
      error.hidden = !message;
    }
    if (control) {
      control.setAttribute("aria-invalid", String(Boolean(message)));
    }
  }

  function showValidation(validation) {
    setFieldError(jobInput, "[data-job-id-error]", validation.errors.jobId);
    setFieldError(
      reviewerInput,
      "[data-reviewer-id-error]",
      validation.errors.reviewerAgentId,
    );
    setFieldError(
      scoreInput,
      "[data-review-score-error]",
      validation.errors.score,
    );
    setFieldError(
      requestBody,
      "[data-request-body-error]",
      validation.errors.requestBody,
    );
  }

  function serviceFacts(service, acceptance) {
    if (!service) {
      return;
    }
    const tokenSymbol = acceptance?.extra?.name || "USDT";
    setText("[data-service-name]", service.serviceName);
    setText("[data-service-id]", `#${service.serviceId}`);
    setText("[data-service-price]", `${service.feeAmount} ${tokenSymbol}`);
    setText(
      "[data-service-token]",
      `${tokenSymbol} · ${service.feeTokenAddress}`,
    );
    setText(
      "[data-service-network]",
      acceptance?.network || "eip155:196 (awaiting live match)",
    );
    setText("[data-service-endpoint]", service.endpoint);
    setText(
      "[data-service-accepts]",
      acceptance
        ? `${challenge.accepts.length} returned · exact term matched`
        : "Waiting for a verified 402 challenge",
    );
    setText("[data-spend-amount]", `${service.feeAmount} ${tokenSymbol}`);
  }

  function lockMessages(availability, validation) {
    let create = "Ready to copy.";
    if (!catalog) {
      create = "Retry the service catalog.";
    } else if (!challenge) {
      create = "Retry current payment terms.";
    } else if (!readinessConfirmed()) {
      create = "Complete the readiness checklist.";
    } else if (validation.errors.requestBody) {
      create = "Fix the request body.";
    }

    let pay = "Ready to copy after reviewing the spend amount.";
    if (!jobInput.value.trim() || validation.errors.jobId) {
      pay = "Paste the job ID returned by step 1.";
    } else if (!spendConfirmed.checked) {
      pay = "Acknowledge the spend boundary.";
    }

    return [
      create,
      pay,
      availability.complete
        ? "Ready to copy."
        : "Receive and confirm the real verdict first.",
      availability.review
        ? "Ready to copy."
        : "Confirm the verdict and enter a valid reviewer ID and score.",
    ];
  }

  function setCommands(commands, availability, messages) {
    const enabled = [
      availability.create,
      availability.pay,
      availability.complete,
      availability.review,
    ];
    commands.forEach((command, index) => {
      const step = index + 1;
      const output = root.document.querySelector(
        `[data-command-step="${step}"]`,
      );
      const button = root.document.querySelector(`[data-copy-step="${step}"]`);
      const stage = root.document.querySelector(
        `[data-command-stage="${step}"]`,
      );
      const state = root.document.querySelector(`[data-stage-state="${step}"]`);
      const available = Boolean(command && enabled[index]);
      output.textContent = available ? command : messages[index];
      button.disabled = !available;
      button.dataset.command = available ? command : "";
      if (stage) {
        stage.dataset.state = available ? "ready" : "locked";
      }
      if (state) {
        state.textContent = available ? "Ready" : "Locked";
      }
    });
  }

  function renderCommands() {
    const service = selectedService();
    if (!service) {
      return;
    }

    const validation = validateHireInputs({
      providerAgentId: catalog.providerAgentId,
      service,
      requestBodyText: requestBody.value,
      jobId: jobInput.value,
      reviewerAgentId: reviewerInput.value,
      score: scoreInput.value,
    });
    showValidation(validation);
    const availability = commandAvailability({
      catalogReady: Boolean(catalog),
      paymentTermsReady: Boolean(challenge),
      readinessConfirmed: readinessConfirmed(),
      requestValid: !validation.errors.requestBody,
      hasJobId: Boolean(jobInput.value.trim()),
      jobValid: !validation.errors.jobId,
      spendConfirmed: spendConfirmed.checked,
      verdictConfirmed: verdictConfirmed.checked,
      hasReviewerAgentId: Boolean(reviewerInput.value.trim()),
      reviewerValid: !validation.errors.reviewerAgentId,
      scoreValid: !validation.errors.score,
    });
    const messages = lockMessages(availability, validation);

    if (!challenge || validation.errors.requestBody) {
      setCommands([null, null, null, null], availability, messages);
      return;
    }
    try {
      const configuredService = {
        ...service,
        requestBody: validation.requestBody,
      };
      const commands = buildCommands({
        providerAgentId: catalog.providerAgentId,
        service: configuredService,
        accepts: challenge.accepts,
        jobId: validation.errors.jobId ? "" : jobInput.value,
        reviewerAgentId: validation.errors.reviewerAgentId
          ? ""
          : reviewerInput.value,
        score: validation.errors.score ? "5" : scoreInput.value,
        shell: selectedShell(),
        spendConfirmed: spendConfirmed.checked,
        verdictConfirmed: verdictConfirmed.checked,
      });
      setCommands(commands, availability, messages);
      const acceptance = acceptanceFor(service, challenge.accepts);
      serviceFacts(service, acceptance);
    } catch (error) {
      setCommands(
        [null, null, null, null],
        { create: false, pay: false, complete: false, review: false },
        [error.message, error.message, error.message, error.message],
      );
    }
  }

  async function loadChallenge() {
    const service = selectedService();
    if (!service) {
      return;
    }
    const requestId = ++challengeRequestId;
    challengeController?.abort();
    const controller = new root.AbortController();
    challengeController = controller;
    const isCurrent = () =>
      isCurrentHireRequest(
        requestId,
        challengeRequestId,
        service.serviceId,
        selectedService()?.serviceId,
      );
    challenge = null;
    acceptsStatus.textContent = "Fetching current payment terms...";
    acceptsOutput.textContent = "[]";
    refreshButton.disabled = true;
    serviceFacts(service, null);
    renderCommands();
    try {
      const endpointPath = new URL(service.endpoint).pathname;
      const response = await root.fetch(endpointPath, {
        method: "GET",
        cache: "no-store",
        signal: controller.signal,
      });
      if (!isCurrent()) {
        return;
      }
      const nextChallenge = parsePaymentResponse(
        response.status,
        response.headers.get("payment-required"),
        service,
      );
      if (!isCurrent()) {
        return;
      }
      challenge = nextChallenge;
      acceptsOutput.textContent = JSON.stringify(challenge.accepts, null, 2);
      acceptsStatus.textContent =
        "Current terms loaded and matched to the selected listing.";
      renderCommands();
    } catch (error) {
      if (!isCurrent()) {
        return;
      }
      acceptsStatus.textContent = `Could not load verified payment terms: ${error.message}`;
      renderCommands();
    } finally {
      if (isCurrent()) {
        challengeController = null;
        refreshButton.disabled = false;
      }
    }
  }

  function selectService() {
    const service = selectedService();
    if (!service) {
      return;
    }
    requestBody.value = JSON.stringify(service.requestBody, null, 2);
    jobInput.value = "";
    spendConfirmed.checked = false;
    verdictConfirmed.checked = false;
    serviceFacts(service, null);
    loadChallenge();
  }

  async function loadCatalog() {
    catalog = null;
    challenge = null;
    retryCatalogButton.hidden = true;
    retryCatalogButton.disabled = true;
    serviceSelect.disabled = true;
    serviceSelect.replaceChildren();
    catalogStatus.textContent = "Loading the normalized service catalog...";
    try {
      const response = await root.fetch("/data/warden-services.json", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error("The service catalog is unavailable");
      }
      const data = await response.json();
      if (!Array.isArray(data.services) || data.services.length === 0) {
        throw new Error("The service catalog contains no services");
      }
      catalog = data;
      for (const service of catalog.services) {
        const option = root.document.createElement("option");
        option.value = service.serviceId;
        option.textContent = `${service.serviceName} · ${service.feeAmount} USDT`;
        serviceSelect.append(option);
      }
      serviceSelect.disabled = false;
      catalogStatus.textContent = `Catalog snapshot ${catalog.snapshotFetchedAt}. Display values below come from this normalized source.`;
      selectService();
    } catch (error) {
      catalogStatus.textContent = `${error.message}.`;
      retryCatalogButton.hidden = false;
      retryCatalogButton.disabled = false;
      const unavailable = {
        create: false,
        pay: false,
        complete: false,
        review: false,
      };
      setCommands(
        [null, null, null, null],
        unavailable,
        Array(4).fill("Retry the service catalog."),
      );
    }
  }

  serviceSelect.addEventListener("change", selectService);
  refreshButton.addEventListener("click", loadChallenge);
  retryCatalogButton.addEventListener("click", loadCatalog);
  for (const control of [
    jobInput,
    reviewerInput,
    scoreInput,
    requestBody,
    spendConfirmed,
    verdictConfirmed,
    ...readinessChecks,
  ]) {
    control.addEventListener("input", renderCommands);
  }
  for (const input of shellInputs) {
    input.addEventListener("change", renderCommands);
  }
  for (const checkbox of readinessChecks) {
    checkbox.addEventListener("change", updateReadinessStatus);
  }
  updateReadinessStatus();
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
  loadCatalog();
})(typeof globalThis === "undefined" ? this : globalThis);
