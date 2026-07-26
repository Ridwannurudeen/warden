"""Async Warden client — the same surface as WardenClient, with `await`."""

from __future__ import annotations

import json
from inspect import isawaitable
from typing import Literal

import httpx

from warden_guard.client import (
    DEFAULT_BASE_URL,
    AsyncX402PaymentHandler,
    Depth,
    FEEDBACK_PATH,
    FREE_PATH,
    PAID_PATH,
    VARIANT_AUDIT_PATH,
    FeedbackOutcome,
    FeedbackResult,
    FeedbackThreatClass,
    FeedbackVerdict,
    LocalEngine,
    ScanResult,
    WardenBlocked,
    WardenError,
    _canonical_paid_url,
    _validate_variant_audit_report,
    build_variant_audit_body,
    build_feedback_body,
    build_scan_body,
    parse_x402_challenge,
    validate_x402_payment_header,
    validate_x402_settlement_header,
    validate_scan_depth,
)
from warden_guard.state import increment_scan_count


class AsyncWardenClient:
    """Async client for the Warden payload firewall.

    Same tiers and defaults as :class:`warden_guard.WardenClient`: the free
    hosted tier is best-effort telemetry (`fail_open=True`); use `local=True`
    for in-process enforcement-grade verdicts. `paid=True` selects the protected
    route but never creates or holds a payment signature. A caller-owned
    `payment_handler` may authorize one replay after canonical validation.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        paid: bool = False,
        local: bool = False,
        timeout: float = 8.0,
        fail_open: bool = True,
        payment_handler: AsyncX402PaymentHandler | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.path = PAID_PATH if paid else FREE_PATH
        self.local = local
        self.timeout = timeout
        self.fail_open = fail_open
        if payment_handler is not None and not paid:
            raise WardenError("x402 payment_handler requires paid=True")
        if payment_handler is not None and local:
            raise WardenError("x402 payment_handler requires local=False")
        if payment_handler is not None and not callable(payment_handler):
            raise WardenError("x402 payment_handler must be callable")
        self.payment_handler = payment_handler
        self._paid_url = _canonical_paid_url(self.base_url) if payment_handler is not None else None
        self._variant_audit_url = (
            _canonical_paid_url(self.base_url, VARIANT_AUDIT_PATH)
            if payment_handler is not None
            else None
        )
        self._engine = LocalEngine() if local else None

    async def scan(
        self,
        payload: str,
        *,
        expected_addresses: list[str] | None = None,
        depth: Depth = "fast",
    ) -> ScanResult:
        """Scan one untrusted payload and return a Warden verdict."""
        depth = validate_scan_depth(depth, local=self.local, path=self.path)
        if self._engine is not None:
            data = await self._engine.scan(
                payload, depth=depth, expected_addresses=expected_addresses
            )
            result = ScanResult.from_response(data)
            increment_scan_count()
            return result
        body = build_scan_body(payload, depth=depth, expected_addresses=expected_addresses)
        request_url = self._paid_url or self.base_url + self.path
        payment_enabled = self.payment_handler is not None
        try:
            client_options: dict[str, object] = {"timeout": self.timeout}
            if payment_enabled:
                client_options.update(follow_redirects=False, trust_env=False)
            async with httpx.AsyncClient(**client_options) as client:
                if payment_enabled:
                    request_body = json.dumps(
                        body,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                    response = await client.post(
                        request_url,
                        content=request_body,
                        headers={"content-type": "application/json"},
                    )
                else:
                    request_body = None
                    response = await client.post(request_url, json=body)
                if payment_enabled and response.is_redirect:
                    raise WardenError("Warden x402 challenge returned a redirect")
                if payment_enabled and response.status_code == 402:
                    challenge = parse_x402_challenge(
                        response.headers,
                        expected_resource_url=request_url,
                    )
                    try:
                        payment_value = self.payment_handler(challenge)
                        if isawaitable(payment_value):
                            payment_value = await payment_value
                    except Exception as exc:
                        raise WardenError("Warden x402 payment handler failed") from exc
                    payment_header = validate_x402_payment_header(
                        payment_value,
                        challenge=challenge,
                    )
                    replay = await client.post(
                        request_url,
                        content=request_body,
                        headers={
                            "content-type": "application/json",
                            "PAYMENT-SIGNATURE": payment_header,
                        },
                    )
                    if replay.status_code == 402:
                        try:
                            replay_challenge = parse_x402_challenge(
                                replay.headers,
                                expected_resource_url=request_url,
                            )
                        except WardenError as exc:
                            raise WardenError(
                                "Warden x402 challenge changed or became malformed on replay"
                            ) from exc
                        if replay_challenge != challenge:
                            raise WardenError("Warden x402 challenge changed on replay")
                        raise WardenError(
                            "Warden permits only one paid replay; payment was not accepted"
                        )
                    if replay.is_redirect:
                        raise WardenError("Warden x402 replay returned a redirect")
                    if replay.status_code != 200:
                        raise WardenError(
                            f"Warden x402 replay failed with HTTP {replay.status_code}"
                        )
                    validate_x402_settlement_header(replay.headers)
                    response = replay
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError as exc:
                    raise WardenError("Invalid Warden response: expected JSON") from exc
                result = ScanResult.from_response(data)
                increment_scan_count()
                return result
        except httpx.HTTPError as exc:
            if payment_enabled:
                raise WardenError(f"Warden x402 request failed: {exc}") from exc
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 402:
                raise WardenError(
                    "Warden scan requires x402 payment; paid=True selects the protected "
                    "endpoint but does not create or settle a payment signature"
                ) from exc
            if self.fail_open:
                return ScanResult(verdict="ALLOW", risk_level="NONE", raw={"error": str(exc)})
            raise WardenError(f"Warden scan failed: {exc}") from exc

    async def variant_audit(
        self,
        target_url: str,
        *,
        threat_classes: list[str] | None = None,
        max_variants_per_class: int | None = None,
        since: str | None = None,
        depth: str = "standard",
    ) -> dict[str, object]:
        """Run a paid adversarial variant audit against a consenting endpoint.

        The async twin of :meth:`warden_guard.WardenClient.variant_audit`, with
        the same options, the same request marshalling and the same response
        validation. As there, no free tier and no fail-open: a failed audit
        raises rather than reading as a clean bill of health.
        """
        if self.payment_handler is None or self._variant_audit_url is None:
            raise WardenError(
                "variant_audit requires an x402 payment_handler; it is a paid route "
                "with no free tier"
            )
        body = build_variant_audit_body(
            target_url,
            threat_classes=threat_classes,
            max_variants_per_class=max_variants_per_class,
            since=since,
            depth=depth,
        )
        request_url = self._variant_audit_url
        request_body = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    request_url,
                    content=request_body,
                    headers={"content-type": "application/json"},
                )
                if response.is_redirect:
                    raise WardenError("Warden x402 challenge returned a redirect")
                if response.status_code == 402:
                    challenge = parse_x402_challenge(
                        response.headers,
                        expected_resource_url=request_url,
                    )
                    supplied = self.payment_handler(challenge)
                    try:
                        if isawaitable(supplied):
                            supplied = await supplied
                    except Exception as exc:
                        raise WardenError("Warden x402 payment handler failed") from exc
                    payment_header = validate_x402_payment_header(supplied, challenge)
                    replay = await client.post(
                        request_url,
                        content=request_body,
                        headers={
                            "content-type": "application/json",
                            "PAYMENT-SIGNATURE": payment_header,
                        },
                    )
                    if replay.status_code == 402:
                        try:
                            replay_challenge = parse_x402_challenge(
                                replay.headers,
                                expected_resource_url=request_url,
                            )
                        except WardenError as exc:
                            raise WardenError(
                                "Warden x402 challenge changed or became malformed on replay"
                            ) from exc
                        if replay_challenge != challenge:
                            raise WardenError("Warden x402 challenge changed on replay")
                        raise WardenError(
                            "Warden permits only one paid replay; payment was not accepted"
                        )
                    if replay.is_redirect:
                        raise WardenError("Warden x402 replay returned a redirect")
                    if replay.status_code != 200:
                        raise WardenError(
                            f"Warden x402 replay failed with HTTP {replay.status_code}"
                        )
                    validate_x402_settlement_header(replay.headers)
                    response = replay
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError as exc:
                    raise WardenError("Invalid Warden response: expected JSON") from exc
        except httpx.HTTPError as exc:
            raise WardenError(f"Warden variant audit failed: {exc}") from exc
        _validate_variant_audit_report(data)
        return data

    async def submit_feedback(
        self,
        *,
        outcome: FeedbackOutcome,
        observed_verdict: FeedbackVerdict,
        threat_class: FeedbackThreatClass,
        redacted_reproducer: str,
        consent_to_retain: Literal[True],
        redaction_confirmed: Literal[True],
    ) -> FeedbackResult:
        """Submit one redacted reproducer after explicit user consent."""
        body = build_feedback_body(
            outcome=outcome,
            observed_verdict=observed_verdict,
            threat_class=threat_class,
            redacted_reproducer=redacted_reproducer,
            consent_to_retain=consent_to_retain,
            redaction_confirmed=redaction_confirmed,
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.base_url + FEEDBACK_PATH, json=body)
                response.raise_for_status()
                try:
                    data = response.json()
                except ValueError as exc:
                    raise WardenError("Invalid Warden feedback response: expected JSON") from exc
        except httpx.HTTPError as exc:
            raise WardenError(f"Warden feedback submission failed: {exc}") from exc
        return FeedbackResult.from_response(data)

    async def guard(self, payload: str, **kwargs: object) -> str:
        """Scan and enforce: return the safe payload to act on, or raise on BLOCK."""
        result = await self.scan(payload, **kwargs)  # type: ignore[arg-type]
        if result.blocked:
            raise WardenBlocked(result)
        if result.sanitized and result.sanitized_payload is not None:
            return result.sanitized_payload
        return payload
