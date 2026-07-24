import hardhatNodeTestRunner from "@nomicfoundation/hardhat-node-test-runner";
import hardhatViem from "@nomicfoundation/hardhat-viem";
import { defineConfig } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatNodeTestRunner, hardhatViem],
  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: {
          viaIR: true,
          optimizer: {
            enabled: true,
            runs: 200,
          },
          metadata: {
            bytecodeHash: "none",
          },
        },
      },
    ],
  },
  paths: {
    artifacts: "./artifacts",
    cache: "./cache",
    sources: "./src",
    tests: {
      nodejs: "./test-js",
    },
  },
});
