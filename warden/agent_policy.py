"""Turn a scan verdict into the guardrails OKX already tells builders to set.

OKX.AI gives builders two native controls — spending limits and allowlists — and
leaves choosing them entirely manual. A scan already knows which of those controls
would have mattered, because it knows which threat classes actually fired.

This module maps observed threat classes onto those controls. It is deliberately
**advisory and unsigned**: the signed Hardening Pack pins both its field set and
its `integration` dict to module constants (`hardening.PACK_CONTENT_FIELDS`,
`hardening.INTEGRATION`), so adding policy there would invalidate every pack
already issued.

It does not invent numbers. A single payload is no basis for choosing a daily
transfer cap, so the advice names the control to set and the evidence for setting
it, and leaves the value to the builder.
"""

from __future__ import annotations

from warden.core.verdict import ReasonCode

# Which native OKX control each threat class argues for, and why. Only classes
# that map to a real control appear — a class with no control implication is
# better left out than padded with filler advice.
_CONTROL_FOR_CLASS: dict[ReasonCode, tuple[str, str]] = {
    ReasonCode.DRAIN_ADDRESS: (
        "payee_allowlist",
        "A payout address was substituted in this payload. An allowlist is the only "
        "control that stops a redirect the agent believes is legitimate.",
    ),
    ReasonCode.WEB3_INJECTION: (
        "payee_allowlist",
        "The payload tried to steer an on-chain action, so the set of addresses the "
        "agent may pay should be fixed ahead of time rather than read from input.",
    ),
    ReasonCode.TOOL_HIJACK: (
        "spend_limit",
        "The payload attempted to drive a tool call. A per-transaction cap bounds "
        "what a hijacked call can move before a human sees it.",
    ),
    ReasonCode.SECRET_EXFIL: (
        "credential_isolation",
        "The payload attempted to read credentials. Keys reachable from tool output "
        "are reachable by the attacker who controls that output.",
    ),
    ReasonCode.PROMPT_INJECTION: (
        "input_screening",
        "Instructions were embedded in content the agent treats as data. Screen "
        "untrusted text before it reaches the model, not after.",
    ),
    ReasonCode.ROLE_OVERRIDE: (
        "input_screening",
        "The payload tried to replace the agent's operating instructions.",
    ),
    ReasonCode.MALICIOUS_LINK: (
        "input_screening",
        "The payload carried a link the agent might fetch or surface to a user.",
    ),
}

_CONTROL_TITLES: dict[str, str] = {
    "payee_allowlist": "Set a payee allowlist",
    "spend_limit": "Set a per-transaction and daily spend limit",
    "credential_isolation": "Keep credentials out of tool-output context",
    "input_screening": "Screen untrusted input before the model acts on it",
}

# Order controls by how directly they stop loss of funds, so the most consequential
# recommendation is first rather than whichever class happened to fire first.
_CONTROL_PRIORITY: list[str] = [
    "payee_allowlist",
    "spend_limit",
    "credential_isolation",
    "input_screening",
]


def build_policy(
    threat_classes: list[str],
    detections: list[dict[str, object]],
    expected_addresses: list[str],
) -> dict[str, object]:
    """Recommend OKX-native guardrails for the threats this scan actually observed."""
    observed: list[ReasonCode] = []
    for name in threat_classes:
        try:
            code = ReasonCode(name)
        except ValueError:
            continue
        if code not in observed:
            observed.append(code)

    controls: dict[str, list[str]] = {}
    for code in observed:
        mapped = _CONTROL_FOR_CLASS.get(code)
        if mapped is None:
            continue
        control, reason = mapped
        controls.setdefault(control, [])
        if reason not in controls[control]:
            controls[control].append(reason)

    recommendations = [
        {
            "control": control,
            "title": _CONTROL_TITLES[control],
            "because": controls[control],
        }
        for control in _CONTROL_PRIORITY
        if control in controls
    ]

    return {
        "recommendations": recommendations,
        "deny_addresses": _attacker_addresses(detections),
        "allow_addresses": list(dict.fromkeys(expected_addresses)),
        "limitations": (
            "Advisory, unsigned, and derived from a single payload. It names the control "
            "to set and the evidence for setting it; it does not choose limit values, "
            "because one payload is no basis for a spending cap. Not a signed Hardening "
            "Pack and not a certification."
        ),
    }


def _attacker_addresses(detections: list[dict[str, object]]) -> list[str]:
    """Addresses a drain detection surfaced.

    No allowlist filtering happens here: the scanner does not raise DRAIN_ADDRESS
    for an address the caller passed in `expected_addresses`, so a vouched-for
    address never reaches this function. Re-filtering would duplicate a guarantee
    that is already made upstream.
    """
    found: list[str] = []
    for detection in detections:
        raw_class = detection.get("class") or detection.get("class_")
        value = raw_class.value if isinstance(raw_class, ReasonCode) else raw_class
        if value != ReasonCode.DRAIN_ADDRESS.value:
            continue
        match = detection.get("match")
        # A detection match is only an address when it looks like one; drain findings
        # can also carry a malformed-token match, which must not become a deny rule.
        if not isinstance(match, str) or not _is_evm_address(match):
            continue
        if match in found:
            continue
        found.append(match)
    return found


def _is_evm_address(value: str) -> bool:
    return (
        len(value) == 42
        and value.startswith("0x")
        and all(character in "0123456789abcdefABCDEF" for character in value[2:])
    )
