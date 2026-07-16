(function (root) {
  "use strict";

  const REFERENCE_MATERIAL = {
    issuerDocument: {
      issuer: "warden",
      keys: [
        {
          kid: "python-fixture-1",
          pub: "ed25519:WkgcE2NXdLijVH0vUuu0lWusnytkhpaM76frHY-qWrc",
          not_after: 9007199254740991,
        },
      ],
    },
    attestation: {
      spec_version: "apa/0.1",
      predicate_type: "https://warden.gudman.xyz/spec/protection/v1",
      attestation_id: "0123456789abcdef0123456789abcdef",
      issuer: "warden",
      protector: "warden",
      endpoint_host: "agent.example",
      pub: "ed25519:4-SkinOublbCA3LWjPcVWYNqx4y3A3wZK1gvOMP_rBg",
      tier: "guard-live",
      status: "active",
      scans_24h: 41207,
      verified_at: 1784000000,
      expires_at: 1784003600,
      evidence: {
        zeta: 7,
        alpha: {
          unicode: "\u03bb",
          labels: ["guard-live", "cross-language"],
        },
      },
      issuer_sig:
        "sig:A4LlXw9x0iNLTiWYVKgX66m5XfiJ9wvbsghwK-M0KwCFPYk4i1utTrX6CpwM0oTBofggA8fmEBIuNo3f5_UuAQ",
    },
    logEntries: [
      {
        seq: 1,
        ts: 1784000000,
        event: "issued",
        attestation_id: "0123456789abcdef0123456789abcdef",
        endpoint_host: "agent.example",
        status: "active",
        record_hash:
          "3aa2b0faf8b1a72acf6580e9f9d632d99c96e29657ff691a43e41e1bf86273ff",
        prev_hash:
          "0000000000000000000000000000000000000000000000000000000000000000",
      },
      {
        seq: 2,
        ts: 1784003600,
        event: "revoked",
        attestation_id: "22222222222222222222222222222222",
        endpoint_host: "agent.example",
        status: "revoked",
        record_hash:
          "2f68364d739206133ab2cbec4eb430ffdbca7551ce5204ad7cce712831c8aac0",
        prev_hash:
          "b3b7ae54059239f7e2ef85e5c6b5d98eff9f26b8382e91dbfcaed0b506b5d1ad",
      },
    ],
  };

  function referenceMaterial() {
    return JSON.parse(JSON.stringify(REFERENCE_MATERIAL));
  }

  function flipOneByte(value) {
    const bytes = new root.TextEncoder().encode(value);
    bytes[0] ^= 1;
    return new root.TextDecoder().decode(bytes);
  }

  async function runOfflineProof({
    cryptoImpl = root.crypto,
    nowSeconds = Math.floor(Date.now() / 1000),
  } = {}) {
    const material = referenceMaterial();
    const attestation = await root.WardenApaVerifier.verifyApaAttestation(
      material.attestation,
      material.issuerDocument,
      { cryptoImpl, nowSeconds },
    );
    const honestChain = await root.WardenTransparencyLog.verifyLogChain(
      material.logEntries,
      cryptoImpl,
    );
    const tamperedEntries = JSON.parse(JSON.stringify(material.logEntries));
    const before = tamperedEntries[0].endpoint_host;
    const after = flipOneByte(before);
    tamperedEntries[0].endpoint_host = after;
    const tamperedChain = await root.WardenTransparencyLog.verifyLogChain(
      tamperedEntries,
      cryptoImpl,
    );

    return {
      material,
      attestation: {
        ...attestation,
        freshness:
          attestation.code === "expired"
            ? "archival"
            : attestation.accepted
              ? "fresh"
              : attestation.effectiveStatus,
      },
      honestChain,
      tamperedChain,
      tamper: {
        entryIndex: 0,
        field: "endpoint_host",
        before,
        after,
      },
    };
  }

  function proofPresentation(result) {
    const signatureVerified = result.attestation.signatureValid === true;
    const honestChainVerified = result.honestChain.ok === true;
    const tamperRejected = result.tamperedChain.ok === false;
    const expiresAt = new Date(
      result.material.attestation.expires_at * 1000,
    ).toISOString();

    return {
      passed: signatureVerified && honestChainVerified && tamperRejected,
      summary:
        signatureVerified && honestChainVerified && tamperRejected
          ? "Offline browser proof complete: signature and chain verified; one-byte tampering rejected."
          : "Offline browser proof did not satisfy every verification check.",
      signature: {
        state: signatureVerified ? "verified" : "rejected",
        label: signatureVerified ? "Signature verified" : "Signature rejected",
        detail:
          signatureVerified && result.attestation.freshness === "archival"
            ? `The Ed25519 signature is valid. This embedded reference record expired at ${expiresAt}; it is archival evidence, not a current live-guard claim.`
            : signatureVerified
              ? "The embedded Warden reference record has a valid Ed25519 signature."
              : "The embedded reference record did not pass Ed25519 verification.",
      },
      honestChain: {
        state: honestChainVerified ? "verified" : "rejected",
        label: honestChainVerified
          ? "Log chain verified"
          : "Log chain rejected",
        detail: honestChainVerified
          ? `${result.honestChain.total} entries formed one continuous SHA-256 chain ending at ${result.honestChain.headHash}.`
          : result.honestChain.reason,
      },
      tamperedChain: {
        state: tamperRejected ? "rejected" : "failed",
        label: tamperRejected ? "Tamper caught" : "Tamper missed",
        detail: tamperRejected
          ? `One byte was flipped in entry ${result.tamper.entryIndex + 1}; verification rejected the chain at entry ${result.tamperedChain.index + 1}.`
          : "The modified chain was unexpectedly accepted.",
      },
    };
  }

  const api = {
    proofPresentation,
    referenceMaterial,
    runOfflineProof,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenHomeProof = api;
})(typeof globalThis === "undefined" ? this : globalThis);
