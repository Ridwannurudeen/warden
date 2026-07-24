"""Targeted remediation packs built from retained per-class audit findings.

A pack is assembled from committed data only: the training corpus and the fixed
guidance table below. Nothing here calls a model or the network, so the same
audit always yields the same pack.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import date
from pathlib import Path
from typing import Mapping

from warden import protection, protection_store
from warden.badges import _canonical_json, ed25519_sign_record, ed25519_verify_record
from warden.taxonomy import mappings_for_reason_code

ROOT = Path(__file__).resolve().parents[1]
_TRAINING_ATTACKS_PATH = ROOT / "corpus" / "attacks.jsonl"
_CORPUS_FINGERPRINT_PATH = Path(__file__).with_name("corpus_fingerprint.txt")

SCHEMA_VERSION = 1
SPEC_VERSION = "warden-hardening-pack/0.1"
PREDICATE_TYPE = "https://warden.gudman.xyz/spec/hardening-pack/v1"
PACK_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_EXAMPLES_PER_CLASS = 5
NOTHING_TO_HARDEN = "Nothing to harden: this audit missed no threat classes."
PACK_CONTENT_FIELDS = {
    "schema_version",
    "audit_id",
    "target_host",
    "battery_id",
    "battery_version",
    "observed_on",
    "corpus_fingerprint",
    "addressed_classes",
    "remediation",
    "integration",
    "limitations",
    "message",
}
PACK_FIELDS = PACK_CONTENT_FIELDS | {
    "spec_version",
    "predicate_type",
    "pack_id",
    "issuer",
    "issued_at",
    "expires_at",
    "log_seq",
    "issuer_sig",
}
EXAMPLE_FIELDS = {
    "id",
    "payload",
    "expected_verdict",
    "expected_classes",
    "depth",
    "context",
    "source_id",
    "source_revision",
    "source_path",
    "source_record_id",
    "source_url",
    "source_file_sha256",
    "license_spdx",
    "license_url",
}
REMEDIATION_FIELDS = {
    "attack_class",
    "missed",
    "blocked",
    "total",
    "summary",
    "pattern_families",
    "analyzers",
    "example_attacks",
    "taxonomy_ids",
}

LIMITATIONS = (
    "This pack lists deterministic coverage that Warden already implements for the "
    "classes the audit observed as unblocked. Applying it does not prove the endpoint "
    "is safe, and a later audit is the only evidence that blocking actually improved."
)

INTEGRATION = {
    "in_process": (
        "WardenClient(local=True, fail_open=False).guard(untrusted_text) returns the "
        "original payload on ALLOW, the sanitized payload on SANITIZE, and raises "
        "WardenBlocked on BLOCK."
    ),
    "asgi_middleware": (
        "Mount the Python SDK's ASGI middleware so request bodies are screened before "
        "the handler runs."
    ),
    "reverse_proxy": (
        "Run warden-gateway in front of the endpoint when the application cannot be "
        "modified; a BLOCK, an invalid decision, or a scanner failure never reaches "
        "the upstream application."
    ),
    "caller_duty": (
        "Warden returns a decision; the caller enforces it. Execute the original only "
        "after ALLOW, the transformed payload only after SANITIZE, and no consequential "
        "action after BLOCK or an invalid result."
    ),
}

# Deterministic coverage Warden implements per threat class. Pattern families are
# keys of scanner.patterns.INJECTION_PATTERNS; analyzers are registry names.
CLASS_GUIDANCE: dict[str, dict[str, object]] = {
    "PROMPT_INJECTION": {
        "pattern_families": ["direct_instruction"],
        "analyzers": [],
        "summary": (
            "Instruction-override phrasing that tries to discard prior context or "
            "reveal a system prompt."
        ),
    },
    "ROLE_OVERRIDE": {
        "pattern_families": ["role_override"],
        "analyzers": [],
        "summary": (
            "Persona reassignment that tries to move the agent into an unrestricted "
            "or approving role."
        ),
    },
    "WEB3_INJECTION": {
        "pattern_families": ["web3_specific"],
        "analyzers": [],
        "summary": (
            "Payment- and transaction-shaped instructions that try to authorize or "
            "redirect on-chain actions."
        ),
    },
    "HIDDEN_UNICODE": {
        "pattern_families": ["control_characters"],
        "analyzers": [],
        "summary": (
            "Invisible or bidirectional control characters that hide instructions "
            "from human review."
        ),
    },
    "ENCODING_TRICK": {
        "pattern_families": ["encoding_tricks"],
        "analyzers": [],
        "summary": (
            "Encoded or nested payloads. Warden's normalization pre-pass decodes and "
            "folds candidates, then rescans them, so a threat that exists only inside "
            "an obfuscation layer is blocked outright."
        ),
    },
    "STATISTICAL_ANOMALY": {
        "pattern_families": [],
        "analyzers": [],
        "summary": (
            "Heuristic scoring over entropy, invisible-character ratio, instruction "
            "density, and context switching, for payloads no single pattern matches."
        ),
    },
    "CORPUS_MATCH": {
        "pattern_families": [],
        "analyzers": [],
        "summary": (
            "Similarity against the known-attack corpus. This layer runs at thorough "
            "depth; a fast-depth-only integration will not exercise it."
        ),
    },
    "DRAIN_ADDRESS": {
        "pattern_families": [],
        "analyzers": ["drain_address"],
        "summary": (
            "Recipient substitution. Detection depends on the caller supplying the "
            "intended recipients as context.expected_addresses; without them there is "
            "no baseline to compare a swapped address against."
        ),
    },
    "SECRET_EXFIL": {
        "pattern_families": [],
        "analyzers": ["exfiltration"],
        "summary": (
            "Attempts to read out seed phrases, private keys, API keys, or other "
            "credential material."
        ),
    },
    "TOOL_HIJACK": {
        "pattern_families": [],
        "analyzers": ["tool_hijack"],
        "summary": (
            "Tool-result and A2MCP content that tries to redirect which tool runs or "
            "with what arguments."
        ),
    },
    "MALICIOUS_LINK": {
        "pattern_families": [],
        "analyzers": ["malicious_link"],
        "summary": "Links that route the agent or its user to attacker-controlled destinations.",
    },
}


def _corpus_fingerprint() -> str:
    return f"sha256:{_CORPUS_FINGERPRINT_PATH.read_text(encoding='utf-8').strip()}"


def _built_in_attribution(
    case_id: str,
    source_file_sha256: str,
) -> dict[str, object]:
    return {
        "source_id": "warden-core",
        "source_revision": None,
        "source_path": "corpus/attacks.jsonl",
        "source_record_id": case_id,
        "source_url": (
            "https://github.com/Ridwannurudeen/warden/blob/main/corpus/attacks.jsonl"
        ),
        "source_file_sha256": source_file_sha256,
        "license_spdx": ["Apache-2.0"],
        "license_url": "https://github.com/Ridwannurudeen/warden/blob/main/LICENSE",
    }


def _training_examples() -> dict[str, list[dict[str, object]]]:
    """Group training-corpus cases by category.

    Only `corpus/attacks.jsonl` is read. The held-out benchmark sets are never a
    source for shipped packs, so published recall stays honest.
    """
    grouped: dict[str, list[dict[str, object]]] = {}
    source_file_sha256 = hashlib.sha256(
        _TRAINING_ATTACKS_PATH.read_bytes()
    ).hexdigest()
    with _TRAINING_ATTACKS_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            case = json.loads(line)
            category = str(case.get("category", ""))
            if not category:
                continue
            case_id = str(case.get("id", ""))
            attribution = (
                {
                    "source_id": case.get("source_id"),
                    "source_revision": case.get("source_revision"),
                    "source_path": case.get("source_path"),
                    "source_record_id": case.get("source_record_id"),
                    "source_url": case.get("source_url"),
                    "source_file_sha256": case.get("source_file_sha256"),
                    "license_spdx": case.get("license_spdx"),
                    "license_url": case.get("license_url"),
                }
                if "source_id" in case
                else _built_in_attribution(case_id, source_file_sha256)
            )
            grouped.setdefault(category, []).append(
                {
                    "id": case_id,
                    "payload": str(case.get("payload", "")),
                    "expected_verdict": str(case.get("expected_verdict", "")),
                    "expected_classes": list(case.get("expected_classes", [category])),
                    "depth": str(case.get("depth", "fast")),
                    "context": {
                        "expected_addresses": list(
                            (
                                case.get("context")
                                if isinstance(case.get("context"), dict)
                                else {}
                            ).get("expected_addresses", [])
                        )
                    },
                    **attribution,
                }
            )
    for cases in grouped.values():
        cases.sort(key=lambda case: str(case["id"]))
    return grouped


def build_pack(findings_record: Mapping[str, object]) -> dict[str, object]:
    """Assemble a remediation pack for the classes an audit observed as unblocked.

    A record whose classes were all blocked yields an empty remediation list; that
    is a valid pack meaning there is nothing to harden, not an error.
    """
    findings = findings_record.get("findings")
    if not isinstance(findings, list):
        raise ValueError("audit findings record is malformed")

    examples = _training_examples()
    remediation: list[dict[str, object]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("audit findings record is malformed")
        missed = finding.get("missed")
        if not isinstance(missed, int) or isinstance(missed, bool) or missed <= 0:
            continue
        attack_class = str(finding.get("attack_class", ""))
        guidance = CLASS_GUIDANCE.get(attack_class)
        if guidance is None:
            raise ValueError(f"no hardening guidance is defined for {attack_class}")
        remediation.append(
            {
                "attack_class": attack_class,
                "missed": missed,
                "blocked": finding.get("blocked"),
                "total": finding.get("total"),
                "summary": guidance["summary"],
                "pattern_families": list(guidance["pattern_families"]),
                "analyzers": list(guidance["analyzers"]),
                "example_attacks": examples.get(attack_class, [])[:MAX_EXAMPLES_PER_CLASS],
                "taxonomy_ids": mappings_for_reason_code(attack_class),
            }
        )
    remediation.sort(key=lambda entry: str(entry["attack_class"]))

    message = (
        NOTHING_TO_HARDEN
        if not remediation
        else f"Hardening guidance for {len(remediation)} missed threat "
        f"{'class' if len(remediation) == 1 else 'classes'}."
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "audit_id": findings_record.get("audit_id"),
        "target_host": findings_record.get("target_host"),
        "battery_id": findings_record.get("battery_id"),
        "battery_version": findings_record.get("battery_version"),
        "observed_on": findings_record.get("observed_on"),
        "corpus_fingerprint": _corpus_fingerprint(),
        "addressed_classes": [str(entry["attack_class"]) for entry in remediation],
        "remediation": remediation,
        "integration": dict(INTEGRATION),
        "limitations": LIMITATIONS,
        "message": message,
    }


def pack_id_for_content(content: Mapping[str, object]) -> str:
    if set(content) != PACK_CONTENT_FIELDS:
        raise ValueError("hardening pack content fields are invalid")
    return hashlib.sha256(_canonical_json(dict(content)).encode("utf-8")).hexdigest()


def _content_from_record(record: Mapping[str, object]) -> dict[str, object]:
    return {field: record.get(field) for field in PACK_CONTENT_FIELDS}


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_example(example: object) -> bool:
    if not isinstance(example, dict) or set(example) != EXAMPLE_FIELDS:
        return False
    if any(
        not isinstance(example.get(field), str) or not example[field]
        for field in ("id", "payload", "expected_verdict", "source_id")
    ):
        return False
    if not isinstance(example.get("license_spdx"), list) or not example["license_spdx"]:
        return False
    if (
        example.get("depth") not in {"fast", "thorough"}
        or not isinstance(example.get("expected_classes"), list)
        or not example["expected_classes"]
        or not all(
            isinstance(reason, str) and reason
            for reason in example["expected_classes"]
        )
    ):
        return False
    context = example.get("context")
    if (
        not isinstance(context, dict)
        or set(context) != {"expected_addresses"}
        or not isinstance(context["expected_addresses"], list)
        or len(context["expected_addresses"]) > 20
        or not all(
            isinstance(address, str) and address
            for address in context["expected_addresses"]
        )
    ):
        return False
    if any(
        not isinstance(license_id, str) or not license_id
        for license_id in example["license_spdx"]
    ):
        return False
    for field in (
        "source_revision",
        "source_path",
        "source_record_id",
        "source_url",
        "license_url",
    ):
        value = example.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            return False
    source_file_sha256 = example.get("source_file_sha256")
    return source_file_sha256 is None or _is_lower_hex(source_file_sha256, 64)


def _valid_content(content: object) -> bool:
    if (
        not isinstance(content, dict)
        or set(content) != PACK_CONTENT_FIELDS
        or content.get("schema_version") != SCHEMA_VERSION
        or content.get("integration") != INTEGRATION
        or content.get("limitations") != LIMITATIONS
        or not _is_lower_hex(content.get("audit_id"), 16)
        or not isinstance(content.get("target_host"), str)
        or not content["target_host"]
        or not isinstance(content.get("battery_id"), str)
        or not content["battery_id"]
        or not isinstance(content.get("battery_version"), str)
        or not content["battery_version"]
        or not isinstance(content.get("corpus_fingerprint"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", content["corpus_fingerprint"])
        or not isinstance(content.get("addressed_classes"), list)
        or not isinstance(content.get("remediation"), list)
    ):
        return False
    observed_on = content.get("observed_on")
    if not isinstance(observed_on, str):
        return False
    try:
        date.fromisoformat(observed_on)
    except ValueError:
        return False

    remediation = content["remediation"]
    classes: list[str] = []
    for entry in remediation:
        if not isinstance(entry, dict) or set(entry) != REMEDIATION_FIELDS:
            return False
        attack_class = entry.get("attack_class")
        missed = entry.get("missed")
        blocked = entry.get("blocked")
        total = entry.get("total")
        if (
            not isinstance(attack_class, str)
            or not attack_class
            or type(missed) is not int
            or type(blocked) is not int
            or type(total) is not int
            or missed < 1
            or blocked < 0
            or total < 1
            or missed != total - blocked
            or not isinstance(entry.get("summary"), str)
            or not entry["summary"]
            or not isinstance(entry.get("pattern_families"), list)
            or not all(isinstance(item, str) for item in entry["pattern_families"])
            or not isinstance(entry.get("analyzers"), list)
            or not all(isinstance(item, str) for item in entry["analyzers"])
            or not isinstance(entry.get("example_attacks"), list)
            or not all(_valid_example(example) for example in entry["example_attacks"])
            or not isinstance(entry.get("taxonomy_ids"), dict)
        ):
            return False
        classes.append(attack_class)
    expected_message = (
        NOTHING_TO_HARDEN
        if not classes
        else f"Hardening guidance for {len(classes)} missed threat "
        f"{'class' if len(classes) == 1 else 'classes'}."
    )
    return (
        classes == sorted(set(classes))
        and content["addressed_classes"] == classes
        and content.get("message") == expected_message
    )


def issue_pack(
    content: Mapping[str, object],
    *,
    log_seq: int,
    issued_at: int | None = None,
) -> dict[str, object]:
    material = dict(content)
    if not _valid_content(material):
        raise ValueError("hardening pack content is invalid")
    current = int(time.time()) if issued_at is None else issued_at
    if current > protection.MAX_SAFE_UNIX_SECONDS - PACK_TTL_SECONDS:
        raise ValueError("hardening pack issue time is invalid")
    record = {
        "spec_version": SPEC_VERSION,
        "predicate_type": PREDICATE_TYPE,
        "pack_id": pack_id_for_content(material),
        "issuer": protection.ISSUER_NAME,
        **material,
        "issued_at": current,
        "expires_at": current + PACK_TTL_SECONDS,
        "log_seq": log_seq,
    }
    signed = ed25519_sign_record(
        record,
        protection.issuer_private_key(),
        "issuer_sig",
    )
    if not verify_pack(signed):
        raise ValueError("hardening pack fields are invalid")
    return json.loads(_canonical_json(signed))


def verify_pack(record: dict[str, object]) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != PACK_FIELDS
        or not protection._signed_json_values_are_safe(record)
        or record.get("spec_version") != SPEC_VERSION
        or record.get("predicate_type") != PREDICATE_TYPE
        or record.get("issuer") != protection.ISSUER_NAME
    ):
        return False
    content = _content_from_record(record)
    issued_at = record.get("issued_at")
    expires_at = record.get("expires_at")
    log_seq = record.get("log_seq")
    if (
        not _valid_content(content)
        or record.get("pack_id") != pack_id_for_content(content)
        or type(issued_at) is not int
        or not 0 <= issued_at <= protection.MAX_SAFE_UNIX_SECONDS
        or type(expires_at) is not int
        or expires_at != issued_at + PACK_TTL_SECONDS
        or type(log_seq) is not int
        or not 1 <= log_seq <= protection.MAX_SAFE_UNIX_SECONDS
    ):
        return False
    try:
        keys = protection.issuer_keys()
    except ValueError:
        return False
    return any(
        issued_at <= int(key["not_after"])
        and ed25519_verify_record(record, str(key["pub"]), "issuer_sig")
        for key in keys
    )


def effective_status(
    record: Mapping[str, object],
    *,
    revoked: bool,
    now: int | None = None,
) -> str:
    if not verify_pack(dict(record)):
        return "invalid"
    if revoked:
        return "revoked"
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        return "invalid"
    return "active" if current <= int(record["expires_at"]) else "stale"


def record_sha256(record: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()


def publish_pack(
    findings_record: Mapping[str, object],
    *,
    issued_at: int | None = None,
) -> dict[str, object]:
    content = build_pack(findings_record)
    pack_id = pack_id_for_content(content)
    return protection_store.commit_hardening_pack(
        pack_id=pack_id,
        audit_id=str(content["audit_id"]),
        record_factory=lambda log_seq: issue_pack(
            content,
            log_seq=log_seq,
            issued_at=issued_at,
        ),
        record_validator=verify_pack,
    )
