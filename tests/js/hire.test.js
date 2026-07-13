"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  buildCommands,
  parsePaymentResponse,
  parsePaymentRequiredHeader,
  quoteArgument,
} = require(path.join(__dirname, "..", "..", "site", "hire.js"));

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "fixtures", "payment_required.json"), "utf8"),
);

const services = {
  scan: {
    key: "scan",
    serviceId: "31669",
    serviceName: "Payload Security Scan",
    serviceType: "A2MCP",
    endpoint: "https://warden.gudman.xyz/scan",
    feeAmount: "0.01",
    feeTokenAddress: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
    taskTitle: "Warden payload scan",
    taskDescription: "Scan an untrusted agent response with Warden",
    serviceParams: "Scan one untrusted agent response",
    requestBody: {
      payload: "Review this untrusted agent response",
      context: { expected_addresses: [] },
    },
  },
  audit: {
    key: "audit",
    serviceId: "31670",
    serviceName: "Agent Endpoint Security Audit",
    serviceType: "A2MCP",
    endpoint: "https://warden.gudman.xyz/audit",
    feeAmount: "15",
    feeTokenAddress: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
    taskTitle: "Warden endpoint audit",
    taskDescription: "Audit an agent endpoint with Warden",
    serviceParams: "Audit https://example.com/agent-endpoint",
    requestBody: {
      target_url: "https://example.com/agent-endpoint",
      sample_prompts: [],
    },
  },
};

function encodedChallenge(name) {
  return Buffer.from(JSON.stringify(fixture[name]), "utf8").toString("base64");
}

test("payment-required fixture decodes and validates for both live services", () => {
  for (const name of ["scan", "audit"]) {
    const challenge = parsePaymentRequiredHeader(encodedChallenge(name), services[name]);
    assert.deepEqual(challenge.accepts, fixture[name].accepts);
    assert.equal(challenge.resource.url, services[name].endpoint);
  }
});

test("commands use the selected snapshot service and complete the reviewable task flow", () => {
  for (const name of ["scan", "audit"]) {
    const service = services[name];
    const commands = buildCommands({
      providerAgentId: "3808",
      service,
      accepts: fixture[name].accepts,
      jobId: "job-123456",
      reviewerAgentId: "9876",
      score: "5",
      shell: "powershell",
      verdictConfirmed: true,
    });

    assert.equal(commands.length, 6);
    assert.match(commands[0], /^onchainos agent create-task /);
    assert.match(commands[0], /--provider 3808 --visibility 1/);
    assert.match(commands[1], new RegExp(`set-asp 'job-123456' .*--service-id ${service.serviceId}`));
    assert.match(commands[2], /set-payment-mode 'job-123456' --payment-mode x402/);
    assert.match(commands[3], /task-402-pay 'job-123456' --provider-agent-id 3808/);
    assert.match(
      commands[3],
      new RegExp(`--endpoint '${service.endpoint.replaceAll(".", "\\.")}'`),
    );
    assert.match(commands[3], /--accepts '\[/);
    assert.equal(commands[4], "onchainos agent complete 'job-123456'");
    assert.equal(
      commands[5],
      "onchainos agent feedback-submit --agent-id 3808 --creator-id 9876 --score 5 --task-id 'job-123456'",
    );
    assert.ok(commands.every((command) => !command.includes("18954")));
    assert.ok(commands.every((command) => !command.includes("18955")));
  }
});

test("challenge validation rejects a mismatched endpoint or asset", () => {
  const wrongEndpoint = structuredClone(fixture.scan);
  wrongEndpoint.resource.url = "https://attacker.example/scan";
  assert.throws(
    () =>
      parsePaymentRequiredHeader(
        Buffer.from(JSON.stringify(wrongEndpoint), "utf8").toString("base64"),
        services.scan,
      ),
    /endpoint/,
  );

  const wrongAsset = structuredClone(fixture.scan);
  wrongAsset.accepts[0].asset = "0x0000000000000000000000000000000000000000";
  assert.throws(
    () =>
      parsePaymentRequiredHeader(
        Buffer.from(JSON.stringify(wrongAsset), "utf8").toString("base64"),
        services.scan,
      ),
    /asset/,
  );

  const wrongAmount = structuredClone(fixture.scan);
  wrongAmount.accepts[0].amount = "1";
  assert.throws(
    () =>
      parsePaymentRequiredHeader(
        Buffer.from(JSON.stringify(wrongAmount), "utf8").toString("base64"),
        services.scan,
      ),
    /amount/,
  );
});

test("payment response validation rejects non-402 and missing headers", () => {
  assert.throws(() => parsePaymentResponse(429, encodedChallenge("scan"), services.scan), /429/);
  assert.throws(() => parsePaymentResponse(200, encodedChallenge("scan"), services.scan), /200/);
  assert.throws(() => parsePaymentResponse(402, "", services.scan), /omitted/);
});

test("shell quoting keeps untrusted bodies inside one PowerShell or POSIX argument", () => {
  const dangerous = `don't $(run); \"render\"\nnext`;
  assert.equal(quoteArgument(dangerous, "powershell"), `'don''t $(run); \"render\"\nnext'`);
  assert.equal(quoteArgument(dangerous, "posix"), `'don'\"'\"'t $(run); \"render\"\nnext'`);
});

test("completion and review stay locked until the buyer confirms a verdict", () => {
  const commands = buildCommands({
    providerAgentId: "3808",
    service: services.scan,
    accepts: fixture.scan.accepts,
    jobId: "job-123",
    reviewerAgentId: "9876",
    score: "5",
    shell: "powershell",
    verdictConfirmed: false,
  });
  assert.equal(commands[4], null);
  assert.equal(commands[5], null);
});

test("command generation rejects invalid or self-dealing reviewer identities", () => {
  for (const reviewerAgentId of ["3808", "4844"]) {
    assert.throws(
      () =>
        buildCommands({
          providerAgentId: "3808",
          service: services.scan,
          accepts: fixture.scan.accepts,
          jobId: "job-123",
          reviewerAgentId,
          score: "5",
          shell: "powershell",
          verdictConfirmed: true,
        }),
      /must not review/,
    );
  }
  assert.throws(
    () =>
      buildCommands({
        providerAgentId: "3808",
        service: services.scan,
        accepts: fixture.scan.accepts,
        jobId: "job-123",
        reviewerAgentId: "reviewer",
        score: "5.01",
        shell: "powershell",
        verdictConfirmed: true,
      }),
    /reviewer agent ID/,
  );
  assert.throws(
    () =>
      buildCommands({
        providerAgentId: "3808",
        service: services.scan,
        accepts: fixture.scan.accepts,
        jobId: "job-123",
        reviewerAgentId: "9876",
        score: "5.01",
        shell: "powershell",
        verdictConfirmed: true,
      }),
    /score/,
  );
});

test("audit request validation rejects credentials in the target URL", () => {
  assert.throws(
    () =>
      buildCommands({
        providerAgentId: "3808",
        service: {
          ...services.audit,
          requestBody: {
            target_url: "https://user:password@example.com/agent",
            sample_prompts: [],
          },
        },
        accepts: fixture.audit.accepts,
        jobId: "job-123",
        reviewerAgentId: "9876",
        score: "5",
        shell: "posix",
        verdictConfirmed: true,
      }),
    /credentials/,
  );
});
