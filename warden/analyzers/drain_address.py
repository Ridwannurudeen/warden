"""Detect payment redirection addresses inside agent payloads."""

import re

from warden.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from warden.core.verdict import ReasonCode

# `0X` is an accepted address prefix, so the prefix is matched case-insensitively:
# upper-casing only the `x` must not hide a recipient from the drain gate.
EVM_ADDRESS_RE = re.compile(r"0[xX][a-fA-F0-9]{40}(?![a-fA-F0-9])")
SOLANA_ADDRESS_RE = re.compile(r"(?<![A-Za-z0-9])([1-9A-HJ-NP-Za-km-z]{32,44})(?![A-Za-z0-9])")
# `remit` and `disburse` are the remaining members of the standard payment verb
# family already represented here by send/transfer/pay/wire/payout: verbs whose only
# ordinary sense is causing value to reach a named party. Unlike the polysemous
# members of that family (settle, release, sweep, credit) they carry no non-financial
# reading, so they are safe as bare verbs; the polysemous ones are handled by
# FORWARD_TRANSFER_INTENT_RE, which also requires an object and a destination.
TRANSFER_INTENT_RE = re.compile(
    r"(?i)\b(send|transfer|pay|deposit|withdraw|wire|to address"
    r"|move|redirect|payout|route|wallet\s+is|receiving address"
    r"|remit(?:s|ted|ting|tance)?|disburse(?:s|d|ment)?)\b"
)
CONTEXTUAL_RECIPIENT_RE = re.compile(r"(?i)\b(?:recipients?|payments?)\b")
STRUCTURED_DESTINATION_RE = re.compile(
    r"""(?ix)
    (?:^|[.\s{,\[])
    ["']?
    (?:
        destination
        | beneficiary
        | payee
        | recipients?
        | payout[_-]?recipients?
        | receiving[_-]?(?:address|wallet)
        | to
    )
    ["']?
    \s*[:=]\s*["']?
    """
)
STRUCTURED_PAYMENT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:payment|settlement|payout|transfer|transaction|amount|"
    r"eth|btc|bnb|sol|usdt|usdc|dai|tokens?|funds?|balance|assets?)\b"
)
# `forward` generalised to the conveyance half of the payment verb family — the verbs
# that also have an everyday non-financial reading (settle a dispute, release a build,
# sweep a directory). Requiring a value object and an explicit `to` destination is what
# makes them safe to include: "settle the payout to <address>" is a payment
# instruction, "settle the review comments" is not.
FORWARD_TRANSFER_INTENT_RE = re.compile(
    r"(?i)\b(?:forward|settle|release|sweep|remit|disburse|dispatch|push|credit)\s+"
    r"(?:(?:the|all|remaining|entire|outstanding|residual)\s+){0,2}"
    r"(?:\d+(?:\.\d+)?\s+)?"
    r"(?:eth|btc|bnb|sol|usdt|usdc|dai|tokens?|funds?|payments?|balance|assets?|holdings"
    # Treasury nouns for money still owed or left over — the objects these verbs take.
    r"|proceeds|remainder|residual|earnings|payouts?|remittance|disbursement|settlement)"
    r"\s+to\b"
)
HIGH_RISK_DRAIN_INTENT_RE = re.compile(
    r"(?i)\b(?:send|transfer|wire|route|forward|move|remit|disburse|sweep)\s+(?:the\s+)?"
    r"(?:remaining|entire|all)\s+"
    r"(?:funds|balance|holdings|assets|tokens?|proceeds|earnings|payouts?)\b"
)
# A payment instruction paired with a malformed (non-40-char) 0x token.
# The strict EVM path cannot see a truncated or overlong recipient, so inspect
# it separately. Exactly 40 hex is a valid EVM address (EVM_ADDRESS_RE) and
# exactly 64 hex is a tx hash / private key (exfiltration analyzer), so both
# lengths are excluded here.
MALFORMED_ADDR_RE = re.compile(
    r"0[xX][a-fA-F0-9]{20,39}(?![a-fA-F0-9])|0[xX][a-fA-F0-9]{41,63}(?![a-fA-F0-9])"
)
# A report of a transfer that already happened states where it came from and how it
# ended: explorer detail panels lead with `From:` / `Status: Success` / `Block:`, and
# decoded calldata is labelled as decoded. An instruction to make a transfer names
# only a destination. A structured `to:` inside one of these framings is therefore a
# record, not a redirection. Only used when the caller supplied no expected
# addresses — with an expectation to compare against, an unexpected recipient in a
# receipt is still worth flagging.
# A money-movement verb used as a prose imperative, which is what overrides a
# receipt framing. It deliberately excludes ABI/function-call syntax like
# `transfer(address to, uint256 amount)` — there the verb is a decoded-calldata
# signature (`transfer` immediately followed by `(`), not an instruction, so a
# legitimate calldata dump keeps its receipt treatment.
PROSE_TRANSFER_IMPERATIVE_RE = re.compile(
    r"(?i)\b(?:send|transfer|wire|route|move|remit|disburse|forward|redirect"
    r"|pay|payout|withdraw|sweep|release)\b(?!\s*\()"
)
TRANSFER_REPORT_CONTEXT_RE = re.compile(
    r"""(?ix)
    (?:^|[\s|,;(\[])
    (?:
        from \s* [:=]
      | sender \s* [:=]
      | status \s* [:=] \s* (?:success|failed|reverted|confirmed|pending)
      | block (?: \s* (?:number|hash) )? \s* [:=]
      | (?:tx|transaction) \s* (?:hash|id) \s* [:=]
      | timestamp \s* [:=]
      | decoded \s+ (?:calldata|input|data|function|params?|event|log)
      | (?:calldata|input \s+ data) \s* [:=]
    )
    """
)


class DrainAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "drain_address"

    @property
    def weight(self) -> float:
        return 0.30

    async def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        payload = str(ctx.extra.get("payload") or "")
        if not payload.strip():
            return AnalyzerResult(
                name=self.name, weight=self.weight, score=0, data={"detections": []}
            )

        expected_addresses = ctx.extra.get("expected_addresses", [])
        has_expected = bool(expected_addresses)
        expected_evm = {
            str(address).lower()
            for address in expected_addresses
            if isinstance(address, str) and address.lower().startswith("0x")
        }
        expected_other = {
            str(address)
            for address in expected_addresses
            if isinstance(address, str) and not address.lower().startswith("0x")
        }

        detections = []
        for match in EVM_ADDRESS_RE.finditer(payload):
            address = match.group()
            confidence = self._confidence(
                payload,
                match.start(),
                match.end(),
                address.lower() in expected_evm,
                has_expected,
            )
            if confidence:
                detections.append(self._detection(address, confidence))

        for match in SOLANA_ADDRESS_RE.finditer(payload):
            address = match.group(1)
            if address in expected_other:
                continue
            confidence = self._confidence(
                payload, match.start(1), match.end(1), False, has_expected
            )
            if confidence:
                detections.append(self._detection(address, confidence))

        if (
            TRANSFER_INTENT_RE.search(payload)
            or FORWARD_TRANSFER_INTENT_RE.search(payload)
            or HIGH_RISK_DRAIN_INTENT_RE.search(payload)
            or (has_expected and CONTEXTUAL_RECIPIENT_RE.search(payload))
            or (
                STRUCTURED_DESTINATION_RE.search(payload)
                and (has_expected or STRUCTURED_PAYMENT_CONTEXT_RE.search(payload))
            )
        ):
            for match in MALFORMED_ADDR_RE.finditer(payload):
                token = match.group()
                if token.lower() in expected_evm:
                    continue
                detections.append(self._detection(token, 0.60))

        score = max((detection["confidence"] for detection in detections), default=0.0) * 100
        flags = [f"Payment redirection candidate: {detection['match']}" for detection in detections]
        return AnalyzerResult(
            name=self.name,
            weight=self.weight,
            score=score,
            flags=flags,
            data={"detections": detections},
        )

    @staticmethod
    def _confidence(
        payload: str,
        start: int,
        end: int,
        is_expected: bool,
        has_expected: bool,
    ) -> float:
        if is_expected:
            return 0.0
        window = payload[max(0, start - 80) : min(len(payload), end + 80)]
        if HIGH_RISK_DRAIN_INTENT_RE.search(window):
            return 0.95
        if STRUCTURED_DESTINATION_RE.search(window) and (
            has_expected or STRUCTURED_PAYMENT_CONTEXT_RE.search(window)
        ):
            # A genuine explorer receipt frames the address as a record (From:/
            # Status:/Block:/decoded calldata) AND carries no transfer imperative —
            # it describes a transfer that already happened. An imperative in the
            # same window ("send 5 ETH to <addr>") is an instruction no matter what
            # receipt-looking prefix an attacker prepends, so the report framing only
            # demotes when the window has no active transfer intent. The framing is
            # scoped to the window, not the whole payload: otherwise a single
            # "Status: success" anywhere disables the gate for every address.
            if (
                not has_expected
                and TRANSFER_REPORT_CONTEXT_RE.search(window)
                and not PROSE_TRANSFER_IMPERATIVE_RE.search(window)
            ):
                return 0.0
            return 0.95 if has_expected else 0.80
        if (
            not TRANSFER_INTENT_RE.search(window)
            and not FORWARD_TRANSFER_INTENT_RE.search(window)
            and not (has_expected and CONTEXTUAL_RECIPIENT_RE.search(window))
        ):
            return 0.60 if has_expected else 0.0
        return 0.95 if has_expected else 0.80

    @staticmethod
    def _detection(address: str, confidence: float) -> dict[str, object]:
        return {
            "class": ReasonCode.DRAIN_ADDRESS.value,
            "match": address,
            "confidence": confidence,
        }
