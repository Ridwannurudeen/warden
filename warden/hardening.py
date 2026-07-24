"""Targeted remediation packs built from retained per-class audit findings.

A pack is assembled from committed data only: the training corpus and the fixed
guidance table below. Nothing here calls a model or the network, so the same
audit always yields the same pack.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from warden.taxonomy import mappings_for_reason_code

ROOT = Path(__file__).resolve().parents[1]
_TRAINING_ATTACKS_PATH = ROOT / "corpus" / "attacks.jsonl"
_CORPUS_FINGERPRINT_PATH = Path(__file__).with_name("corpus_fingerprint.txt")

SCHEMA_VERSION = 1
MAX_EXAMPLES_PER_CLASS = 5

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


def _training_examples() -> dict[str, list[dict[str, object]]]:
    """Group training-corpus cases by category.

    Only `corpus/attacks.jsonl` is read. The held-out benchmark sets are never a
    source for shipped packs, so published recall stays honest.
    """
    grouped: dict[str, list[dict[str, object]]] = {}
    with _TRAINING_ATTACKS_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            case = json.loads(line)
            category = str(case.get("category", ""))
            if not category:
                continue
            grouped.setdefault(category, []).append(
                {
                    "id": str(case.get("id", "")),
                    "payload": str(case.get("payload", "")),
                    "expected_verdict": str(case.get("expected_verdict", "")),
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
    }
