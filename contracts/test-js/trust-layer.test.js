import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";
import {
  getAddress,
  keccak256,
  stringToHex,
  zeroAddress,
  zeroHash,
} from "viem";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

function pythonVector(...args) {
  const result = spawnSync(
    "python",
    [`${ROOT}/tests/fixtures/emit_onchain_vector.py`, ...args],
    {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        ...process.env,
        PYTHONPATH: ROOT,
      },
      windowsHide: true,
    },
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

describe("WardenLogAnchor", async function () {
  const { viem } = await network.create();
  const publicClient = await viem.getPublicClient();
  const [publisher, outsider] = await viem.getWalletClients();

  it("matches the reviewed compiler record and bytecode hashes", function () {
    const build = JSON.parse(
      readFileSync(`${ROOT}/contracts/WardenLogAnchor.build.json`, "utf8"),
    );
    const artifact = JSON.parse(
      readFileSync(
        `${ROOT}/contracts/artifacts/src/WardenLogAnchor.sol/WardenLogAnchor.json`,
        "utf8",
      ),
    );
    const source = readFileSync(`${ROOT}/${build.source}`);
    const creation = Buffer.from(artifact.bytecode.slice(2), "hex");
    const runtime = Buffer.from(artifact.deployedBytecode.slice(2), "hex");

    assert.equal(build.compiler.version, "0.8.24");
    assert.equal(build.compiler.long_version, "0.8.24+commit.e11b9ed9");
    assert.equal(sha256Hex(source), build.source_sha256);
    assert.equal(creation.length, build.artifact.creation_bytes);
    assert.equal(sha256Hex(creation), build.artifact.creation_sha256);
    assert.equal(
      runtime.length,
      build.artifact.runtime_bytes_before_immutable_linking,
    );
    assert.equal(
      sha256Hex(runtime),
      build.artifact.runtime_sha256_before_immutable_linking,
    );
  });

  it("rejects a zero publisher", async function () {
    await assert.rejects(
      viem.deployContract("WardenLogAnchor", [zeroAddress]),
      /InvalidPublisher/,
    );
  });

  it("enforces publisher, root, and monotonic sequence boundaries", async function () {
    const anchor = await viem.deployContract("WardenLogAnchor", [
      publisher.account.address,
    ]);
    const outsiderAnchor = await viem.getContractAt(
      "WardenLogAnchor",
      anchor.address,
      { client: { wallet: outsider } },
    );

    assert.equal(
      await anchor.read.publisher(),
      getAddress(publisher.account.address),
    );
    assert.equal(await anchor.read.anchorCount(), 0n);
    assert.equal(await anchor.read.latestLogSequence(), 0n);
    await assert.rejects(
      outsiderAnchor.write.anchor(["0x" + "11".repeat(32), 1n]),
      /UnauthorizedPublisher/,
    );
    await assert.rejects(
      anchor.write.anchor([zeroHash, 1n]),
      /InvalidRoot/,
    );

    const root = "0x" + "22".repeat(32);
    const transactionHash = await anchor.write.anchor([root, 7n]);
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: transactionHash,
    });
    const events = await publicClient.getContractEvents({
      address: anchor.address,
      abi: anchor.abi,
      eventName: "CheckpointAnchored",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
      strict: true,
    });

    assert.equal(await anchor.read.anchorCount(), 1n);
    assert.equal(await anchor.read.latestLogSequence(), 7n);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].args, {
      anchorIndex: 1n,
      seq: 7n,
      root,
    });
    await assert.rejects(
      anchor.write.anchor(["0x" + "33".repeat(32), 7n]),
      /NonIncreasingSequence/,
    );
  });

  it("executes Python-built checkpoint calldata and emits the same evidence", async function () {
    const anchor = await viem.deployContract("WardenLogAnchor", [
      publisher.account.address,
    ]);
    const vector = pythonVector(
      "anchor",
      anchor.address,
      publisher.account.address,
    );
    const transactionHash = await publisher.sendTransaction({
      to: anchor.address,
      data: vector.data,
    });
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: transactionHash,
    });
    const events = await publicClient.getContractEvents({
      address: anchor.address,
      abi: anchor.abi,
      eventName: "CheckpointAnchored",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
      strict: true,
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.root, vector.root);
    assert.equal(events[0].args.seq, BigInt(vector.seq));
  });
});

describe("ERC-8004 ReputationRegistry harness", async function () {
  const { viem } = await network.create();
  const publicClient = await viem.getPublicClient();
  const [owner, reviewer] = await viem.getWalletClients();
  const agentId = 42n;

  async function deployHarness() {
    return viem.deployContract("ReputationRegistryHarness", [
      agentId,
      owner.account.address,
    ]);
  }

  it("rejects unknown agents and owner self-feedback", async function () {
    const registry = await deployHarness();
    const reviewerRegistry = await viem.getContractAt(
      "ReputationRegistryHarness",
      registry.address,
      { client: { wallet: reviewer } },
    );
    const args = [
      5n,
      0,
      "security-audit",
      "sha256:" + "44".repeat(32),
      "https://agent.example/scan",
      "https://warden.gudman.xyz/apa/audit/0123456789abcdef",
      zeroHash,
    ];

    await assert.rejects(
      reviewerRegistry.write.giveFeedback([999n, ...args]),
      /InvalidAgent/,
    );
    await assert.rejects(
      registry.write.giveFeedback([agentId, ...args]),
      /SelfFeedback/,
    );
  });

  it("accepts typed boundaries and emits evidence that agrees with the audit", async function () {
    const registry = await deployHarness();
    const reviewerRegistry = await viem.getContractAt(
      "ReputationRegistryHarness",
      registry.address,
      { client: { wallet: reviewer } },
    );
    const endpoint = "https://agent.example/scan";
    const feedbackURI =
      "https://warden.gudman.xyz/apa/audit/0123456789abcdef";
    const tag2 = "sha256:" + "55".repeat(32);
    const transactionHash = await reviewerRegistry.write.giveFeedback([
      agentId,
      -(2n ** 127n),
      255,
      "security-audit",
      tag2,
      endpoint,
      feedbackURI,
      zeroHash,
    ]);
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: transactionHash,
    });
    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "NewFeedback",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
      strict: true,
    });

    assert.equal(await registry.read.feedbackCount([agentId]), 1n);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].args, {
      agentId,
      clientAddress: getAddress(reviewer.account.address),
      feedbackIndex: 0n,
      value: -(2n ** 127n),
      valueDecimals: 255,
      indexedTag1: keccak256(stringToHex("security-audit")),
      tag1: "security-audit",
      tag2,
      endpoint,
      feedbackURI,
      feedbackHash: zeroHash,
    });
  });

  it("executes Python-built ERC-8004 calldata against the local harness", async function () {
    const registry = await deployHarness();
    const vector = pythonVector("feedback", reviewer.account.address);
    const transactionHash = await reviewer.sendTransaction({
      to: registry.address,
      data: vector.data,
    });
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: transactionHash,
    });
    const events = await publicClient.getContractEvents({
      address: registry.address,
      abi: registry.abi,
      eventName: "NewFeedback",
      fromBlock: receipt.blockNumber,
      toBlock: receipt.blockNumber,
      strict: true,
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].args.agentId, agentId);
    assert.equal(events[0].args.value, 5n);
    assert.equal(events[0].args.valueDecimals, 0);
    assert.equal(events[0].args.tag1, "security-audit");
    assert.equal(
      events[0].args.tag2,
      `sha256:${vector.record_sha256}`,
    );
    assert.equal(events[0].args.feedbackHash, zeroHash);
  });
});
