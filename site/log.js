(function (root) {
  "use strict";

  const GENESIS_PREV_HASH = "0".repeat(64);
  const HEX_HASH = /^[0-9a-f]{64}$/;
  const BREAKER_CERTIFICATE_ID = /^[0-9a-f]{32}$/;
  const BREAKER_BENCHMARK_CASE_ID = /^gauntlet-[0-9a-f]{16}$/;
  const AUDIT_ID = /^[0-9a-f]{16}$/;
  const MAX_LOG_ENTRIES = 10_000;
  const MAX_ANCHOR_HISTORY_ENTRIES = 10_000;
  const APA_LOG_ENTRY_FIELDS = new Set([
    "seq",
    "ts",
    "event",
    "attestation_id",
    "endpoint_host",
    "status",
    "record_hash",
    "prev_hash",
  ]);
  const BREAKER_LOG_ENTRY_FIELDS = new Set([
    "seq",
    "ts",
    "event",
    "record_type",
    "certificate_id",
    "benchmark_case_id",
    "record_hash",
    "prev_hash",
  ]);
  const AUDIT_LOG_ENTRY_FIELDS = new Set([
    "seq",
    "ts",
    "event",
    "record_type",
    "audit_id",
    "endpoint_host",
    "record_hash",
    "prev_hash",
  ]);
  const HARDENING_LOG_ENTRY_FIELDS = new Set([
    "seq",
    "ts",
    "event",
    "record_type",
    "pack_id",
    "audit_id",
    "record_hash",
    "prev_hash",
  ]);
  const LOG_CHECKPOINT_VERSION = "apa-log/0.1";

  function canonicalValue(value) {
    if (Array.isArray(value)) {
      return value.map(canonicalValue);
    }
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, canonicalValue(value[key])]),
      );
    }
    return value;
  }

  function canonicalJson(value) {
    return JSON.stringify(canonicalValue(value));
  }

  function rejectUnexpectedFields(entry, expectedFields, index, entryType) {
    for (const field of Object.keys(entry)) {
      if (!expectedFields.has(field)) {
        throw new Error(
          `Entry ${index + 1} ${field} is not valid for ${entryType} entries`,
        );
      }
    }
  }

  function normalizeLogEntry(entry, index) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`Entry ${index + 1} must be an object`);
    }
    if (!Number.isSafeInteger(entry.seq) || entry.seq < 1) {
      throw new Error(`Entry ${index + 1} seq must be a positive safe integer`);
    }
    if (!Number.isSafeInteger(entry.ts) || entry.ts < 0) {
      throw new Error(
        `Entry ${index + 1} ts must be a non-negative safe integer`,
      );
    }

    const recordType = entry.record_type;
    let expectedFields = APA_LOG_ENTRY_FIELDS;
    let entryType = "APA";
    if (recordType === "breaker-certificate") {
      expectedFields = BREAKER_LOG_ENTRY_FIELDS;
      entryType = "breaker-certificate";
      if (entry.event !== "breaker-confirmed") {
        throw new Error(
          `Entry ${index + 1} event must be breaker-confirmed for a BREAKER certificate`,
        );
      }
      if (
        typeof entry.certificate_id !== "string" ||
        !BREAKER_CERTIFICATE_ID.test(entry.certificate_id)
      ) {
        throw new Error(
          `Entry ${index + 1} certificate_id must be 32 lowercase hex characters`,
        );
      }
      if (
        typeof entry.benchmark_case_id !== "string" ||
        !BREAKER_BENCHMARK_CASE_ID.test(entry.benchmark_case_id)
      ) {
        throw new Error(
          `Entry ${index + 1} benchmark_case_id must be gauntlet- followed by 16 lowercase hex characters`,
        );
      }
    } else if (recordType === "endpoint-audit-attestation") {
      expectedFields = AUDIT_LOG_ENTRY_FIELDS;
      entryType = "endpoint-audit";
      if (!["audit-issued", "audit-revoked"].includes(entry.event)) {
        throw new Error(
          `Entry ${index + 1} event must be audit-issued or audit-revoked for endpoint-audit evidence`,
        );
      }
      if (
        typeof entry.audit_id !== "string" ||
        !AUDIT_ID.test(entry.audit_id)
      ) {
        throw new Error(
          `Entry ${index + 1} audit_id must be 16 lowercase hex characters`,
        );
      }
      if (typeof entry.endpoint_host !== "string" || !entry.endpoint_host) {
        throw new Error(
          `Entry ${index + 1} endpoint_host must be a non-empty string`,
        );
      }
    } else if (recordType === "hardening-pack") {
      expectedFields = HARDENING_LOG_ENTRY_FIELDS;
      entryType = "hardening-pack";
      if (entry.event !== "hardening-pack-issued") {
        throw new Error(
          `Entry ${index + 1} event must be hardening-pack-issued for hardening evidence`,
        );
      }
      if (typeof entry.pack_id !== "string" || !HEX_HASH.test(entry.pack_id)) {
        throw new Error(
          `Entry ${index + 1} pack_id must be 64 lowercase hex characters`,
        );
      }
      if (
        typeof entry.audit_id !== "string" ||
        !AUDIT_ID.test(entry.audit_id)
      ) {
        throw new Error(
          `Entry ${index + 1} audit_id must be 16 lowercase hex characters`,
        );
      }
    } else if (Object.prototype.hasOwnProperty.call(entry, "record_type")) {
      throw new Error(`Entry ${index + 1} record_type is unsupported`);
    } else {
      for (const field of [
        "event",
        "attestation_id",
        "endpoint_host",
        "status",
      ]) {
        if (typeof entry[field] !== "string" || !entry[field]) {
          throw new Error(
            `Entry ${index + 1} ${field} must be a non-empty string`,
          );
        }
      }
    }

    for (const field of ["record_hash", "prev_hash"]) {
      if (typeof entry[field] !== "string" || !HEX_HASH.test(entry[field])) {
        throw new Error(
          `Entry ${index + 1} ${field} must be lowercase SHA-256 hex`,
        );
      }
    }
    rejectUnexpectedFields(entry, expectedFields, index, entryType);
    return { ...entry };
  }

  function normalizeLogPayload(payload) {
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      throw new Error("Transparency log response must be an object");
    }
    if (!Array.isArray(payload.entries)) {
      throw new Error("Transparency log response omitted entries");
    }
    if (!Number.isInteger(payload.total) || payload.total < 0) {
      throw new Error("Transparency log total must be a non-negative integer");
    }
    if (payload.total !== payload.entries.length) {
      throw new Error("Transparency log total does not match entries length");
    }
    return payload.entries.map(normalizeLogEntry);
  }

  function normalizeLogPage(payload, cursor) {
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      !Array.isArray(payload.entries)
    ) {
      throw new Error("Transparency log page must be an object with entries");
    }
    if (!Number.isSafeInteger(payload.total) || payload.total < 0) {
      throw new Error(
        "Transparency log total must be a non-negative safe integer",
      );
    }
    if (
      payload.next_cursor !== null &&
      (!Number.isSafeInteger(payload.next_cursor) ||
        payload.next_cursor <= cursor)
    ) {
      throw new Error("Transparency log next_cursor must advance");
    }
    const entries = payload.entries.map((entry, index) =>
      normalizeLogEntry(entry, cursor + index),
    );
    for (const [index, entry] of entries.entries()) {
      if (entry.seq !== cursor + index + 1) {
        throw new Error("Transparency log page sequence is not contiguous");
      }
    }
    if (
      payload.next_cursor !== null &&
      (entries.length === 0 ||
        payload.next_cursor !== entries[entries.length - 1].seq)
    ) {
      throw new Error(
        "Transparency log next_cursor does not match the page tail",
      );
    }
    return {
      entries,
      total: payload.total,
      nextCursor: payload.next_cursor,
    };
  }

  async function fetchLogPages(fetchImpl, pageSize = 100) {
    if (typeof fetchImpl !== "function") {
      throw new Error("Transparency log fetch is unavailable");
    }
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 500) {
      throw new Error("Transparency log page size must be between 1 and 500");
    }
    const entries = [];
    let cursor = 0;
    let expectedTotal = null;
    while (true) {
      const response = await fetchImpl(
        `/apa/log?cursor=${cursor}&limit=${pageSize}`,
        {
          headers: { accept: "application/json" },
          cache: "no-store",
          signal: root.AbortSignal?.timeout?.(10_000),
        },
      );
      if (!response.ok) {
        throw new Error(`Log request failed with HTTP ${response.status}`);
      }
      const page = normalizeLogPage(await response.json(), cursor);
      if (page.total > MAX_LOG_ENTRIES) {
        throw new Error(
          `Transparency log exceeds the browser verification limit of ${MAX_LOG_ENTRIES.toLocaleString()} entries`,
        );
      }
      if (expectedTotal === null) {
        expectedTotal = page.total;
      } else if (page.total !== expectedTotal) {
        throw new Error("Transparency log changed while pages were being read");
      }
      entries.push(...page.entries);
      if (
        entries.length > expectedTotal ||
        (entries.length === expectedTotal && page.nextCursor !== null) ||
        (page.nextCursor !== null && page.nextCursor > expectedTotal)
      ) {
        throw new Error(
          "Transparency log pagination continues past the published total",
        );
      }
      if (page.nextCursor === null) {
        if (entries.length !== expectedTotal) {
          throw new Error(
            "Transparency log pages do not match the published total",
          );
        }
        return entries;
      }
      cursor = page.nextCursor;
    }
  }

  function decodeBase64Url(value, prefix, expectedLength) {
    const marker = `${prefix}:`;
    if (typeof value !== "string" || !value.startsWith(marker)) {
      throw new Error(`Expected a ${prefix}: base64url value`);
    }
    const encoded = value.slice(marker.length);
    if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
      throw new Error("Value is not unpadded base64url");
    }
    const padded =
      encoded.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (encoded.length % 4)) % 4);
    let binary;
    try {
      binary = root.atob(padded);
    } catch (error) {
      throw new Error("Value is not valid base64url", { cause: error });
    }
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    if (bytes.length !== expectedLength) {
      throw new Error(`${prefix} value must decode to ${expectedLength} bytes`);
    }
    const canonical = root
      .btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    if (canonical !== encoded) {
      throw new Error("Value is not canonical base64url");
    }
    return bytes;
  }

  function normalizeLogCheckpoint(checkpoint) {
    if (
      checkpoint === null ||
      typeof checkpoint !== "object" ||
      Array.isArray(checkpoint) ||
      Object.keys(checkpoint).length !== 6
    ) {
      throw new Error("Log checkpoint must be a six-field object");
    }
    if (checkpoint.spec_version !== LOG_CHECKPOINT_VERSION) {
      throw new Error("Log checkpoint spec_version is unsupported");
    }
    if (typeof checkpoint.issuer !== "string" || !checkpoint.issuer) {
      throw new Error("Log checkpoint issuer must be a non-empty string");
    }
    if (!Number.isSafeInteger(checkpoint.seq) || checkpoint.seq < 0) {
      throw new Error("Log checkpoint seq must be a non-negative safe integer");
    }
    if (!HEX_HASH.test(checkpoint.head_hash)) {
      throw new Error("Log checkpoint head_hash must be lowercase SHA-256 hex");
    }
    if (
      !Number.isSafeInteger(checkpoint.issued_at) ||
      checkpoint.issued_at < 0
    ) {
      throw new Error(
        "Log checkpoint issued_at must be non-negative safe Unix seconds",
      );
    }
    decodeBase64Url(checkpoint.issuer_sig, "sig", 64);
    return { ...checkpoint };
  }

  function issuerKeysForCheckpoint(checkpoint, issuerDocument) {
    if (
      issuerDocument === null ||
      typeof issuerDocument !== "object" ||
      Array.isArray(issuerDocument) ||
      Object.keys(issuerDocument).length !== 2 ||
      issuerDocument.issuer !== checkpoint.issuer ||
      !Array.isArray(issuerDocument.keys) ||
      issuerDocument.keys.length === 0
    ) {
      throw new Error("Issuer document does not match the log checkpoint");
    }
    const kids = new Set();
    const pubs = new Set();
    let previousNotAfter = Number.MAX_SAFE_INTEGER;
    const keys = issuerDocument.keys.map((key, index) => {
      if (
        key === null ||
        typeof key !== "object" ||
        Array.isArray(key) ||
        Object.keys(key).length !== 3 ||
        typeof key.kid !== "string" ||
        !key.kid ||
        key.kid.trim() !== key.kid ||
        !Number.isSafeInteger(key.not_after) ||
        key.not_after < 0 ||
        key.not_after > previousNotAfter
      ) {
        throw new Error("Issuer document contains a malformed key");
      }
      const pub = decodeBase64Url(key.pub, "ed25519", 32);
      if (index === 0 && key.not_after !== Number.MAX_SAFE_INTEGER) {
        throw new Error(
          "Current issuer key must use the safe-integer sentinel",
        );
      }
      if (index > 0 && key.not_after === Number.MAX_SAFE_INTEGER) {
        throw new Error("Retired issuer key must have a finite cutoff");
      }
      const pubIdentity = Array.from(pub).join(",");
      if (kids.has(key.kid) || pubs.has(pubIdentity)) {
        throw new Error("Issuer document contains a duplicate key");
      }
      kids.add(key.kid);
      pubs.add(pubIdentity);
      previousNotAfter = key.not_after;
      return key;
    });
    return keys.filter((key) => checkpoint.issued_at <= key.not_after);
  }

  async function sha256Hex(value, cryptoImpl = root.crypto) {
    if (!cryptoImpl?.subtle || typeof root.TextEncoder !== "function") {
      throw new Error("SHA-256 verification is unavailable in this browser");
    }
    const digest = await cryptoImpl.subtle.digest(
      "SHA-256",
      new root.TextEncoder().encode(value),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  }

  async function verifyLogChainWithPrefixes(entries, cryptoImpl = root.crypto) {
    const normalized = normalizeLogPayload({ entries, total: entries.length });
    let previousHash = GENESIS_PREV_HASH;
    const prefixHeads = [GENESIS_PREV_HASH];

    for (const [index, entry] of normalized.entries()) {
      if (entry.seq !== index + 1) {
        return {
          result: {
            ok: false,
            index,
            reason: `Entry ${index + 1} breaks the expected sequence.`,
          },
          prefixHeads,
        };
      }
      if (entry.prev_hash !== previousHash) {
        return {
          result: {
            ok: false,
            index,
            reason:
              index === 0
                ? "Entry 1 does not use the genesis previous hash."
                : `Entry ${index + 1} previous entry hash does not match.`,
          },
          prefixHeads,
        };
      }
      previousHash = await sha256Hex(canonicalJson(entry), cryptoImpl);
      prefixHeads.push(previousHash);
    }

    return {
      result: {
        ok: true,
        total: normalized.length,
        headHash: previousHash,
      },
      prefixHeads,
    };
  }

  async function verifyLogChain(entries, cryptoImpl = root.crypto) {
    const verified = await verifyLogChainWithPrefixes(entries, cryptoImpl);
    return verified.result;
  }

  async function verifyLogCheckpoint(
    checkpoint,
    issuerDocument,
    cryptoImpl = root.crypto,
  ) {
    const normalized = normalizeLogCheckpoint(checkpoint);
    const keys = issuerKeysForCheckpoint(normalized, issuerDocument);
    if (!cryptoImpl?.subtle) {
      throw new Error("Ed25519 verification is unavailable in this browser");
    }
    const signature = decodeBase64Url(normalized.issuer_sig, "sig", 64);
    const core = Object.fromEntries(
      Object.entries(normalized).filter(([key]) => key !== "issuer_sig"),
    );
    const signedBytes = new root.TextEncoder().encode(canonicalJson(core));
    for (const key of keys) {
      const publicKey = await cryptoImpl.subtle.importKey(
        "raw",
        decodeBase64Url(key.pub, "ed25519", 32),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      if (
        await cryptoImpl.subtle.verify(
          { name: "Ed25519" },
          publicKey,
          signature,
          signedBytes,
        )
      ) {
        return true;
      }
    }
    return false;
  }

  async function verifySignedLog(
    entries,
    checkpoint,
    issuerDocument,
    cryptoImpl = root.crypto,
  ) {
    const chain = await verifyLogChain(entries, cryptoImpl);
    if (!chain.ok) {
      return chain;
    }
    let normalized;
    let signatureValid;
    try {
      normalized = normalizeLogCheckpoint(checkpoint);
      signatureValid = await verifyLogCheckpoint(
        normalized,
        issuerDocument,
        cryptoImpl,
      );
    } catch (error) {
      return {
        ok: false,
        reason: `Signed checkpoint is invalid: ${error.message}`,
      };
    }
    if (!signatureValid) {
      return { ok: false, reason: "Signed checkpoint signature is invalid." };
    }
    if (
      normalized.seq !== chain.total ||
      normalized.head_hash !== chain.headHash
    ) {
      return {
        ok: false,
        reason: "Log entries do not match the issuer-signed checkpoint.",
      };
    }
    return { ...chain, checkpoint: normalized };
  }

  function normalizeAnchorPublication(publication) {
    if (
      publication === null ||
      typeof publication !== "object" ||
      Array.isArray(publication) ||
      Object.keys(publication).sort().join(",") !==
        "checkpoint,schema_version,status"
    ) {
      throw new Error(
        "External checkpoint publication must be a three-field object",
      );
    }
    if (publication.schema_version !== 1) {
      throw new Error("External checkpoint publication schema is unsupported");
    }
    if (publication.status === "unpublished") {
      if (publication.checkpoint !== null) {
        throw new Error(
          "Unpublished checkpoint publication must not contain a checkpoint",
        );
      }
      return { schema_version: 1, status: "unpublished", checkpoint: null };
    }
    if (publication.status !== "published") {
      throw new Error("External checkpoint publication status is invalid");
    }
    return {
      schema_version: 1,
      status: "published",
      checkpoint: normalizeLogCheckpoint(publication.checkpoint),
    };
  }

  async function verifyPublishedAnchor(
    entries,
    publication,
    issuerDocument,
    cryptoImpl = root.crypto,
  ) {
    if (publication === null || publication === undefined) {
      return {
        ok: false,
        status: "missing",
        reason: "An external checkpoint publication is not available.",
      };
    }

    let normalized;
    try {
      normalized = normalizeAnchorPublication(publication);
    } catch (error) {
      return {
        ok: false,
        status: "invalid",
        reason: `External checkpoint publication is invalid: ${error.message}`,
      };
    }
    if (normalized.status === "unpublished") {
      return {
        ok: false,
        status: "unpublished",
        reason: "An external checkpoint has not been published yet.",
      };
    }

    let signatureValid;
    try {
      signatureValid = await verifyLogCheckpoint(
        normalized.checkpoint,
        issuerDocument,
        cryptoImpl,
      );
    } catch (error) {
      return {
        ok: false,
        status: "invalid",
        reason: `Published checkpoint is invalid: ${error.message}`,
      };
    }
    if (!signatureValid) {
      return {
        ok: false,
        status: "invalid",
        reason: "Published checkpoint signature is invalid.",
      };
    }

    const pinnedSeq = normalized.checkpoint.seq;
    if (!Array.isArray(entries) || pinnedSeq > entries.length) {
      return {
        ok: false,
        status: "rejected",
        reason: "The current log is truncated before the published checkpoint.",
      };
    }
    let prefix;
    try {
      prefix = await verifyLogChain(entries.slice(0, pinnedSeq), cryptoImpl);
    } catch (error) {
      return {
        ok: false,
        status: "rejected",
        reason: `The published log prefix is invalid: ${error.message}`,
      };
    }
    if (
      !prefix.ok ||
      prefix.total !== pinnedSeq ||
      prefix.headHash !== normalized.checkpoint.head_hash
    ) {
      return {
        ok: false,
        status: "rejected",
        reason: "The log prefix does not match the published checkpoint.",
      };
    }
    return {
      ok: true,
      status: "verified",
      pinnedSeq,
      headHash: prefix.headHash,
      checkpoint: normalized.checkpoint,
    };
  }

  function normalizeAnchorHistory(document) {
    if (
      document === null ||
      typeof document !== "object" ||
      Array.isArray(document) ||
      Object.keys(document).sort().join(",") !==
        "anchors,history_head_hash,schema_version,status"
    ) {
      throw new Error("Anchor history must be an exact four-field object");
    }
    if (
      document.schema_version !== 1 ||
      !["unpublished", "published"].includes(document.status) ||
      !HEX_HASH.test(document.history_head_hash) ||
      !Array.isArray(document.anchors) ||
      document.anchors.length > MAX_ANCHOR_HISTORY_ENTRIES
    ) {
      throw new Error("Anchor history metadata is invalid");
    }
    const anchors = document.anchors.map((anchor, index) => {
      if (
        anchor === null ||
        typeof anchor !== "object" ||
        Array.isArray(anchor) ||
        Object.keys(anchor).sort().join(",") !==
          "anchor_seq,checkpoint,previous_anchor_hash" ||
        anchor.anchor_seq !== index + 1 ||
        !HEX_HASH.test(anchor.previous_anchor_hash)
      ) {
        throw new Error(`Anchor history entry ${index + 1} is malformed`);
      }
      return {
        anchor_seq: anchor.anchor_seq,
        previous_anchor_hash: anchor.previous_anchor_hash,
        checkpoint: normalizeLogCheckpoint(anchor.checkpoint),
      };
    });
    const expectedStatus = anchors.length ? "published" : "unpublished";
    if (document.status !== expectedStatus) {
      throw new Error("Anchor history status does not match its entries");
    }
    if (!anchors.length && document.history_head_hash !== GENESIS_PREV_HASH) {
      throw new Error("Empty anchor history must use the genesis head");
    }
    return {
      schema_version: 1,
      status: expectedStatus,
      history_head_hash: document.history_head_hash,
      anchors,
    };
  }

  async function verifyAnchorHistory(
    history,
    entries,
    issuerDocument,
    cryptoImpl = root.crypto,
    pinnedHead = null,
  ) {
    if (history === null || history === undefined) {
      return {
        ok: false,
        status: "missing",
        reason: "The public anchor history is not available.",
      };
    }
    let normalized;
    try {
      normalized = normalizeAnchorHistory(history);
    } catch (error) {
      return {
        ok: false,
        status: "invalid",
        reason: `Public anchor history is invalid: ${error.message}`,
      };
    }
    if (normalized.status === "unpublished") {
      return {
        ok: false,
        status: "unpublished",
        reason: "No public checkpoint history has been published yet.",
      };
    }
    if (pinnedHead !== null && !HEX_HASH.test(pinnedHead)) {
      return {
        ok: false,
        status: "invalid",
        reason: "The retained history head must be lowercase SHA-256 hex.",
      };
    }

    let previousAnchorHash = GENESIS_PREV_HASH;
    let previousCheckpointSeq = -1;
    let previousIssuedAt = -1;
    const observedHeads = [];
    let logVerification;
    try {
      logVerification = await verifyLogChainWithPrefixes(entries, cryptoImpl);
    } catch (error) {
      return {
        ok: false,
        status: "rejected",
        reason: `The current log is invalid: ${error.message}`,
      };
    }
    if (!logVerification.result.ok) {
      return {
        ok: false,
        status: "rejected",
        reason: `The current log is invalid: ${logVerification.result.reason}`,
      };
    }
    for (const anchor of normalized.anchors) {
      if (anchor.previous_anchor_hash !== previousAnchorHash) {
        return {
          ok: false,
          status: "rejected",
          reason: `Public anchor history chain breaks at entry ${anchor.anchor_seq}.`,
        };
      }
      if (
        anchor.checkpoint.seq <= previousCheckpointSeq ||
        anchor.checkpoint.issued_at < previousIssuedAt
      ) {
        return {
          ok: false,
          status: "rejected",
          reason: "Public anchor checkpoints are not strictly append-only.",
        };
      }
      let signatureValid;
      try {
        signatureValid = await verifyLogCheckpoint(
          anchor.checkpoint,
          issuerDocument,
          cryptoImpl,
        );
      } catch (error) {
        return {
          ok: false,
          status: "rejected",
          reason: `Public anchor checkpoint is invalid: ${error.message}`,
        };
      }
      if (!signatureValid) {
        return {
          ok: false,
          status: "rejected",
          reason: "Public anchor checkpoint signature is invalid.",
        };
      }
      if (anchor.checkpoint.seq > entries.length) {
        return {
          ok: false,
          status: "rejected",
          reason:
            "The current log is truncated before a public anchor checkpoint.",
        };
      }
      if (
        logVerification.prefixHeads[anchor.checkpoint.seq] !==
        anchor.checkpoint.head_hash
      ) {
        return {
          ok: false,
          status: "rejected",
          reason: "A public anchor checkpoint does not match its log prefix.",
        };
      }
      previousCheckpointSeq = anchor.checkpoint.seq;
      previousIssuedAt = anchor.checkpoint.issued_at;
      previousAnchorHash = await sha256Hex(canonicalJson(anchor), cryptoImpl);
      observedHeads.push(previousAnchorHash);
    }
    if (normalized.history_head_hash !== previousAnchorHash) {
      return {
        ok: false,
        status: "rejected",
        reason: "Public anchor history head does not match its entries.",
      };
    }
    if (pinnedHead !== null && !observedHeads.includes(pinnedHead)) {
      return {
        ok: false,
        status: "rejected",
        reason: "The retained history head is absent from the public chain.",
      };
    }
    return {
      ok: true,
      status: "verified",
      anchorCount: normalized.anchors.length,
      headHash: previousAnchorHash,
      pinned: pinnedHead !== null,
      latestCheckpoint:
        normalized.anchors[normalized.anchors.length - 1].checkpoint,
    };
  }

  async function fetchAnchorPublication(fetchImpl) {
    if (typeof fetchImpl !== "function") {
      throw new Error("External checkpoint fetch is unavailable");
    }
    const response = await fetchImpl("/data/apa-log-anchor.json", {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: root.AbortSignal?.timeout?.(10_000),
    });
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(
        `External checkpoint request failed with HTTP ${response.status}`,
      );
    }
    return response.json();
  }

  async function fetchAnchorHistory(fetchImpl) {
    if (typeof fetchImpl !== "function") {
      throw new Error("Public anchor history fetch is unavailable");
    }
    const response = await fetchImpl("/data/apa-log-anchor-history.json", {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: root.AbortSignal?.timeout?.(10_000),
    });
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(
        `Public anchor history request failed with HTTP ${response.status}`,
      );
    }
    return response.json();
  }

  function formatTimestamp(seconds) {
    const date = new Date(seconds * 1000);
    if (Number.isNaN(date.getTime())) {
      throw new Error("Log entry timestamp is invalid");
    }
    return date.toISOString();
  }

  const api = {
    GENESIS_PREV_HASH,
    MAX_LOG_ENTRIES,
    canonicalJson,
    fetchAnchorHistory,
    fetchAnchorPublication,
    fetchLogPages,
    normalizeAnchorPublication,
    normalizeAnchorHistory,
    normalizeLogCheckpoint,
    normalizeLogPage,
    normalizeLogPayload,
    sha256Hex,
    verifyLogChain,
    verifyLogCheckpoint,
    verifyAnchorHistory,
    verifyPublishedAnchor,
    verifySignedLog,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.WardenTransparencyLog = api;

  if (!root.document) {
    return;
  }

  const document = root.document;
  const container = document.querySelector("[data-apa-log]");
  if (!container) {
    return;
  }

  const entriesElement = document.querySelector("[data-apa-log-entries]");
  const retryButtons = document.querySelectorAll("[data-apa-log-retry]");
  const copyRawButton = document.querySelector("[data-apa-log-copy-raw]");
  const tamperButton = document.querySelector("[data-apa-log-tamper]");
  let verifiedMaterial = null;

  function text(selector, value) {
    const element = document.querySelector(selector);
    if (element) {
      element.textContent = value;
    }
  }

  function sourceStamp(state, message) {
    const element = document.querySelector("[data-apa-log-source]");
    if (!element) {
      return;
    }
    element.dataset.sourceStamp = state;
    element.className = `source-stamp source-stamp--${state}`;
    root.WardenUI?.applySourceStamp(element, state);
    element.textContent = `${state.toUpperCase()} · ${message}`;
    element.setAttribute(
      "aria-label",
      `Source state: ${state.toUpperCase()}. ${message}`,
    );
  }

  function setRetryDisabled(disabled) {
    for (const button of retryButtons) {
      button.disabled = disabled;
    }
  }

  function resetLocalTools() {
    verifiedMaterial = null;
    if (copyRawButton) {
      copyRawButton.disabled = true;
    }
    if (tamperButton) {
      tamperButton.disabled = true;
    }
    text(
      "[data-apa-log-raw]",
      "Normalized JSON is unavailable until the log is fetched.",
    );
    text(
      "[data-apa-log-tool-status]",
      "Fetch a valid non-empty log before running local tools.",
    );
  }

  function createFact(label, value, numeric = false) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    if (numeric) {
      description.className = "num";
    }
    wrapper.append(term, description);
    return wrapper;
  }

  function createEntry(entry) {
    const item = document.createElement("li");
    const heading = document.createElement("strong");
    const summary = document.createElement("p");
    const facts = document.createElement("dl");

    heading.textContent = `Entry ${entry.seq}: ${entry.event}`;
    facts.className = "data-list";
    if (entry.record_type === "breaker-certificate") {
      summary.textContent = `WARDEN BREAKER · ${entry.benchmark_case_id}`;
      facts.append(
        createFact("Observed", formatTimestamp(entry.ts), true),
        createFact("Certificate", entry.certificate_id, true),
        createFact("Benchmark case", entry.benchmark_case_id, true),
        createFact("Record hash", entry.record_hash, true),
        createFact("Previous hash", entry.prev_hash, true),
      );
    } else if (entry.record_type === "endpoint-audit-attestation") {
      summary.textContent = `Endpoint audit · ${entry.endpoint_host}`;
      facts.append(
        createFact("Observed", formatTimestamp(entry.ts), true),
        createFact("Audit ID", entry.audit_id, true),
        createFact("Lifecycle event", entry.event, false),
        createFact("Record hash", entry.record_hash, true),
        createFact("Previous hash", entry.prev_hash, true),
      );
    } else if (entry.record_type === "hardening-pack") {
      summary.textContent = `Hardening Pack · audit ${entry.audit_id}`;
      facts.append(
        createFact("Observed", formatTimestamp(entry.ts), true),
        createFact("Pack ID", entry.pack_id, true),
        createFact("Source audit", entry.audit_id, true),
        createFact("Record hash", entry.record_hash, true),
        createFact("Previous hash", entry.prev_hash, true),
      );
    } else {
      summary.textContent = `${entry.endpoint_host} · status ${entry.status}`;
      facts.append(
        createFact("Observed", formatTimestamp(entry.ts), true),
        createFact("Attestation", entry.attestation_id, true),
        createFact("Record hash", entry.record_hash, true),
        createFact("Previous hash", entry.prev_hash, true),
      );
    }
    item.append(heading, summary, facts);
    return item;
  }

  function renderEntries(entries) {
    if (entries.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty-state";
      empty.textContent = "The issuer has not published any log entries yet.";
      entriesElement.replaceChildren(empty);
      return;
    }
    entriesElement.replaceChildren(...entries.map(createEntry));
  }

  function retainedHistoryHead() {
    const parameters = new URLSearchParams(root.location?.search || "");
    const values = parameters.getAll("history_head");
    if (values.length > 1) {
      throw new Error("Provide at most one retained history_head value");
    }
    return values[0] || null;
  }

  async function loadLog() {
    container.dataset.state = "loading";
    setRetryDisabled(true);
    resetLocalTools();
    sourceStamp("unknown", "ledger verification in progress");
    text(
      "[data-apa-log-status]",
      "Fetching public log pages, issuer keys, and the signed checkpoint. No chain result is available yet.",
    );
    text("[data-apa-log-chain]", "Unknown while verification runs");
    try {
      const requestOptions = {
        headers: { accept: "application/json" },
        cache: "no-store",
        signal: root.AbortSignal?.timeout?.(10_000),
      };
      const [
        entries,
        checkpointResponse,
        issuerResponse,
        publication,
        history,
      ] = await Promise.all([
        fetchLogPages(root.fetch?.bind(root)),
        root.fetch("/apa/log/checkpoint", requestOptions),
        root.fetch("/.well-known/apa-issuer.json", requestOptions),
        fetchAnchorPublication(root.fetch?.bind(root)),
        fetchAnchorHistory(root.fetch?.bind(root)),
      ]);
      for (const [label, fetched] of [
        ["Checkpoint", checkpointResponse],
        ["Issuer document", issuerResponse],
      ]) {
        if (!fetched.ok) {
          throw new Error(
            `${label} request failed with HTTP ${fetched.status}`,
          );
        }
      }
      const checkpoint = await checkpointResponse.json();
      const issuerDocument = await issuerResponse.json();
      const result = await verifySignedLog(entries, checkpoint, issuerDocument);
      const observedAt = new Date().toISOString();

      renderEntries(entries);
      text(
        "[data-apa-log-raw]",
        JSON.stringify(
          { entries, total: entries.length, next_cursor: null },
          null,
          2,
        ),
      );
      text("[data-apa-log-total]", entries.length.toLocaleString());
      text("[data-apa-log-observed]", observedAt);
      if (!result.ok) {
        container.dataset.state = "tampered";
        sourceStamp("live", `ledger rejected ${observedAt}`);
        text("[data-apa-log-chain]", "Chain break detected");
        text("[data-apa-log-head]", "Not accepted");
        text("[data-apa-log-checkpoint]", "Not accepted");
        text("[data-apa-log-anchor]", "Not evaluated");
        text("[data-apa-log-history]", "Not evaluated");
        text("[data-apa-log-history-count]", "Not evaluated");
        text("[data-apa-log-history-head]", "Not evaluated");
        text("[data-apa-log-history-pin]", "Not evaluated");
        text(
          "[data-apa-log-status]",
          `${result.reason} No continuity result is accepted.`,
        );
        return;
      }

      const anchorResult = await verifyPublishedAnchor(
        entries,
        publication,
        issuerDocument,
      );
      const historyPin = retainedHistoryHead();
      const historyResult = await verifyAnchorHistory(
        history,
        entries,
        issuerDocument,
        root.crypto,
        historyPin,
      );
      const absentStatuses = ["missing", "unpublished"];
      let externalFailure = null;
      if (!anchorResult.ok && !absentStatuses.includes(anchorResult.status)) {
        externalFailure = anchorResult.reason;
      } else if (
        !historyResult.ok &&
        !absentStatuses.includes(historyResult.status)
      ) {
        externalFailure = historyResult.reason;
      } else if (historyPin && !historyResult.ok) {
        externalFailure =
          "A retained history head was supplied, but no verifiable public history is available.";
      } else if (anchorResult.ok !== historyResult.ok) {
        externalFailure =
          "The current public checkpoint and its history do not agree on publication state.";
      } else if (
        anchorResult.ok &&
        canonicalJson(anchorResult.checkpoint) !==
          canonicalJson(historyResult.latestCheckpoint)
      ) {
        externalFailure =
          "The current public checkpoint does not match the latest history entry.";
      }
      if (externalFailure) {
        container.dataset.state = "tampered";
        sourceStamp("live", `public checkpoint history rejected ${observedAt}`);
        text("[data-apa-log-chain]", "Public history rejected");
        text("[data-apa-log-head]", "Not accepted");
        text(
          "[data-apa-log-checkpoint]",
          `Signed ${formatTimestamp(result.checkpoint.issued_at)}`,
        );
        text("[data-apa-log-anchor]", "Rejected");
        text("[data-apa-log-history]", "Rejected");
        text("[data-apa-log-history-count]", "Not accepted");
        text("[data-apa-log-history-head]", "Not accepted");
        text("[data-apa-log-history-pin]", "Not accepted");
        text(
          "[data-apa-log-status]",
          `${externalFailure} No continuity result is accepted.`,
        );
        return;
      }

      const currentAnchorSummary = anchorResult.ok
        ? `Signed prefix through entry ${anchorResult.pinnedSeq.toLocaleString()} verified.`
        : anchorResult.reason;
      const historySummary = historyResult.ok
        ? `${historyResult.anchorCount.toLocaleString()} public history checkpoints verified${historyResult.pinned ? " against the retained head." : "; no independent head was supplied."}`
        : historyResult.reason;
      const anchorSummary = `${currentAnchorSummary} ${historySummary}`;
      text(
        "[data-apa-log-anchor]",
        anchorResult.ok
          ? `Verified through #${anchorResult.pinnedSeq.toLocaleString()}`
          : "No public checkpoint published",
      );
      text(
        "[data-apa-log-history]",
        historyResult.ok ? "History verified" : "No history published",
      );
      text(
        "[data-apa-log-history-count]",
        historyResult.ok
          ? historyResult.anchorCount.toLocaleString()
          : "No entries",
      );
      text(
        "[data-apa-log-history-head]",
        historyResult.ok ? historyResult.headHash : "Not published",
      );
      text(
        "[data-apa-log-history-pin]",
        historyResult.pinned
          ? "Retained head verified"
          : "No independent head supplied",
      );
      text(
        "[data-apa-log-checkpoint]",
        `Signed ${formatTimestamp(result.checkpoint.issued_at)}`,
      );
      sourceStamp("live", `ledger checked ${observedAt}`);

      if (entries.length === 0) {
        container.dataset.state = "empty";
        text("[data-apa-log-chain]", "No chain (empty log)");
        text("[data-apa-log-head]", "No entries");
        text(
          "[data-apa-log-status]",
          `The empty log was fetched at ${observedAt}. There is no entry chain to verify. ${anchorSummary}`,
        );
        return;
      }

      container.dataset.state = "verified";
      verifiedMaterial = { checkpoint, entries, issuerDocument };
      if (copyRawButton) {
        copyRawButton.disabled = false;
      }
      if (tamperButton) {
        tamperButton.disabled = false;
      }
      text(
        "[data-apa-log-tool-status]",
        "The verified normalized ledger is ready to copy or challenge locally.",
      );
      text("[data-apa-log-chain]", "Continuity verified");
      text("[data-apa-log-head]", result.headHash);
      text(
        "[data-apa-log-status]",
        `${entries.length.toLocaleString()} entries formed one continuous SHA-256 chain at ${observedAt}. ${anchorSummary}`,
      );
    } catch (error) {
      container.dataset.state = "error";
      sourceStamp("degraded", `ledger unavailable ${new Date().toISOString()}`);
      entriesElement.replaceChildren();
      text("[data-apa-log-total]", "Unavailable");
      text("[data-apa-log-chain]", "Not verified");
      text("[data-apa-log-head]", "Unavailable");
      text("[data-apa-log-checkpoint]", "Unavailable");
      text("[data-apa-log-anchor]", "Unavailable");
      text("[data-apa-log-history]", "Unavailable");
      text("[data-apa-log-history-count]", "Unavailable");
      text("[data-apa-log-history-head]", "Unavailable");
      text("[data-apa-log-history-pin]", "Unavailable");
      text("[data-apa-log-observed]", new Date().toISOString());
      text(
        "[data-apa-log-status]",
        `${error.message}. No continuity result is implied.`,
      );
    } finally {
      setRetryDisabled(false);
    }
  }

  for (const button of retryButtons) {
    button.addEventListener("click", loadLog);
  }
  copyRawButton?.addEventListener("click", async () => {
    if (!verifiedMaterial) {
      return;
    }
    try {
      await root.navigator.clipboard.writeText(
        JSON.stringify(
          {
            entries: verifiedMaterial.entries,
            total: verifiedMaterial.entries.length,
            next_cursor: null,
          },
          null,
          2,
        ),
      );
      text("[data-apa-log-tool-status]", "Normalized ledger JSON copied.");
    } catch (error) {
      text("[data-apa-log-tool-status]", `Copy failed: ${error.message}`);
    }
  });
  tamperButton?.addEventListener("click", async () => {
    if (!verifiedMaterial || verifiedMaterial.entries.length === 0) {
      return;
    }
    const changed = verifiedMaterial.entries.map((entry) => ({ ...entry }));
    changed[0].record_hash = `${changed[0].record_hash[0] === "0" ? "1" : "0"}${changed[0].record_hash.slice(1)}`;
    try {
      const result = await verifySignedLog(
        changed,
        verifiedMaterial.checkpoint,
        verifiedMaterial.issuerDocument,
      );
      text(
        "[data-apa-log-tool-status]",
        result.ok
          ? "Unexpected result: the changed local copy was accepted."
          : `Local tamper rejected: ${result.reason}`,
      );
    } catch (error) {
      text(
        "[data-apa-log-tool-status]",
        `Local tamper rejected: ${error.message}`,
      );
    }
  });
  loadLog();
})(typeof globalThis === "undefined" ? this : globalThis);
