"""Pydantic boundary models for Warden HTTP and MCP surfaces."""

import re
import unicodedata
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from warden.core.verdict import ReasonCode, Verdict

MAX_PAYLOAD_LENGTH = 100_000
MAX_DEMO_PAYLOAD_LENGTH = 4_000
MAX_DEMO_EXPECTED_ADDRESSES = 20
MAX_TARGET_URL_LENGTH = 2_048
MAX_SAMPLE_PROMPTS = 20

Depth = Literal["fast", "thorough"]
VerdictLabel = Literal["ALLOW", "SANITIZE", "BLOCK"]
RiskLabel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Grade = Literal["A", "B", "C", "D", "F", "INCONCLUSIVE"]
ClaimStatus = Literal["not_candidate", "pending", "duplicate"]
FeedbackOutcome = Literal["missed_attack", "false_positive", "correct_detection"]
FeedbackStatus = Literal["pending", "duplicate"]

_FINDER_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def normalize_finder_handle(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(
        character for character in normalized if unicodedata.category(character) != "Cf"
    ).strip(" \t\r\n")
    return normalized or None


def finder_handle_is_visible(value: str) -> bool:
    return all(
        character == " "
        or (
            character.isprintable()
            and not any(
                start <= ord(character) <= end for start, end in _FINDER_DEFAULT_IGNORABLE_RANGES
            )
        )
        for character in value
    )


class ScanContext(BaseModel):
    expected_addresses: list[str] = Field(default_factory=list)
    source: str | None = Field(default=None, max_length=256)


class ScanRequest(BaseModel):
    payload: str
    depth: Depth = "fast"
    context: ScanContext = Field(default_factory=ScanContext)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("payload must not be blank")
        if len(value) > MAX_PAYLOAD_LENGTH:
            raise ValueError(f"payload must not exceed {MAX_PAYLOAD_LENGTH} characters")
        return value


class DemoScanContext(ScanContext):
    expected_addresses: list[str] = Field(
        default_factory=list,
        max_length=MAX_DEMO_EXPECTED_ADDRESSES,
    )


class DemoScanRequest(BaseModel):
    payload: str
    context: DemoScanContext = Field(default_factory=DemoScanContext)

    @field_validator("payload")
    @classmethod
    def truncate_payload(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("payload must not be blank")
        return value[:MAX_DEMO_PAYLOAD_LENGTH]


class DemoExample(BaseModel):
    id: str
    label: str
    reason_code: ReasonCode | None
    payload: str


class DemoAspReceipt(BaseModel):
    handler: Literal["warden-demo-asp"] = "warden-demo-asp"
    invoked: bool
    received_payload: str | None


class GauntletRequest(BaseModel):
    intent: str = Field(max_length=500)
    payload: str
    context: DemoScanContext = Field(default_factory=DemoScanContext)
    finder: str | None = Field(default=None, max_length=128)
    public_credit_consent: bool = Field(default=False, strict=True)
    training_use_consent: bool = Field(default=False, strict=True)

    @field_validator("intent")
    @classmethod
    def normalize_intent(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("intent must not be blank")
        return normalized

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("payload must not be blank")
        return value[:MAX_DEMO_PAYLOAD_LENGTH]

    @field_validator("finder", mode="before")
    @classmethod
    def normalize_finder(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = normalize_finder_handle(value)
        if normalized is None and value.strip(" \t\r\n"):
            raise ValueError("finder must contain only visible characters")
        if normalized is not None and not finder_handle_is_visible(normalized):
            raise ValueError("finder must contain only visible characters")
        return normalized


class Detection(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    class_: ReasonCode = Field(alias="class")
    match: str
    confidence: float = Field(ge=0, le=1)
    source: str


class ScanResponse(BaseModel):
    verdict: VerdictLabel
    risk_level: RiskLabel
    threat_classes: list[str]
    detections: list[Detection]
    sanitized_payload: str
    recommendation: str
    checks: dict[str, str]
    latency_ms: float
    # Additive evidence field from the offline learned advisory scorer. null when
    # no weights artifact is loaded. Advisory only — it does not set the verdict.
    attack_probability: float | None = Field(default=None, ge=0, le=1)

    @classmethod
    def from_verdict(cls, verdict: Verdict) -> "ScanResponse":
        return cls(
            verdict=verdict.verdict,
            risk_level=verdict.risk_level,
            threat_classes=[reason.value for reason in verdict.threat_classes],
            detections=[Detection.model_validate(detection) for detection in verdict.detections],
            sanitized_payload=verdict.sanitized_payload,
            recommendation=verdict.recommendation,
            checks=verdict.checks,
            latency_ms=verdict.latency_ms,
            attack_probability=verdict.attack_probability,
        )


class AgentPolicyRecommendation(BaseModel):
    control: str
    title: str
    because: list[str]


class AgentPolicyRequest(BaseModel):
    payload: str
    context: DemoScanContext = Field(default_factory=DemoScanContext)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("payload must not be blank")
        return value[:MAX_DEMO_PAYLOAD_LENGTH]


class AgentPolicyResponse(BaseModel):
    scan: ScanResponse
    recommendations: list[AgentPolicyRecommendation]
    deny_addresses: list[str]
    allow_addresses: list[str]
    limitations: str


class DemoTheaterResponse(ScanResponse):
    asp_receipt: DemoAspReceipt


class GauntletResponse(ScanResponse):
    claim_status: ClaimStatus
    claim_id: str | None = None


class GauntletStats(BaseModel):
    attempts: int
    pending_claims: int
    confirmed_bypasses: int
    corpus_size: int


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: FeedbackOutcome
    observed_verdict: VerdictLabel
    threat_class: ReasonCode
    redacted_reproducer: str = Field(max_length=MAX_DEMO_PAYLOAD_LENGTH)
    consent_to_retain: Literal[True]
    redaction_confirmed: Literal[True]

    @field_validator("consent_to_retain", "redaction_confirmed", mode="before")
    @classmethod
    def require_explicit_true(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("explicit boolean true is required")
        return True

    @field_validator("redacted_reproducer")
    @classmethod
    def validate_redacted_reproducer(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("redacted_reproducer must not be blank")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("redacted_reproducer must contain valid unicode scalar text") from exc
        return value

    @model_validator(mode="after")
    def validate_outcome_verdict(self) -> "FeedbackRequest":
        if self.outcome == "missed_attack" and self.observed_verdict != "ALLOW":
            raise ValueError("missed_attack requires an observed ALLOW verdict")
        if self.outcome != "missed_attack" and self.observed_verdict == "ALLOW":
            raise ValueError(f"{self.outcome} requires a non-ALLOW observed verdict")
        return self


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feedback_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    status: FeedbackStatus
    retained_until: str


class ThreatIntelCell(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: FeedbackOutcome
    threat_class: ReasonCode
    count: int = Field(ge=5)


class ThreatIntelSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    generated_at: str
    window_start: str | None
    window_end: str
    k_anonymity: Literal[5]
    included_records: int = Field(ge=0)
    cells: list[ThreatIntelCell]
    source: str
    limitations: str


class BreakerCertificate(BaseModel):
    spec_version: Literal["warden-breaker/1"]
    predicate_type: Literal["https://warden.gudman.xyz/spec/gauntlet-breaker/v1"]
    certificate_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    issuer: Literal["warden"]
    award: Literal["WARDEN BREAKER"]
    benchmark_case_id: str = Field(pattern=r"^gauntlet-[0-9a-f]{16}$")
    threat_class: ReasonCode
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_scope: Literal["human-reviewed-redacted-reproducer"]
    finder: str | None
    confirmed_at: int = Field(ge=0)
    log_seq: int = Field(ge=1)
    issuer_sig: str


class BreakerLeaderboardResponse(BaseModel):
    breakers: list[BreakerCertificate]
    total: int


class BreakerDetailResponse(BaseModel):
    certificate: BreakerCertificate


class AuditRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=MAX_TARGET_URL_LENGTH)
    sample_prompts: list[str] = Field(default_factory=list, max_length=MAX_SAMPLE_PROMPTS)
    input_field: str = Field(default="payload", min_length=1, max_length=64)

    @field_validator("sample_prompts")
    @classmethod
    def truncate_sample_prompts(cls, value: list[str]) -> list[str]:
        return [prompt[:MAX_PAYLOAD_LENGTH] for prompt in value]

    @field_validator("input_field")
    @classmethod
    def validate_input_field(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("input_field must be a valid JSON object key")
        return value


class AuditResult(BaseModel):
    probe_id: str | None = None
    attack_class: str
    sent: str
    blocked: bool
    taxonomy_ids: dict[str, list[str]] = Field(default_factory=dict)


class BadgeRecord(BaseModel):
    audit_id: str
    target_host: str
    grade: str
    score: float
    blocked: int
    total: int
    issued_at: str
    # None = legacy record issued before consent entered the signed payload.
    consent_verified: bool | None = None
    signature: str


class BadgeRegistryEntry(BaseModel):
    badge: BadgeRecord
    verified: bool


class BadgeRegistryResponse(BaseModel):
    badges: list[BadgeRegistryEntry]
    total: int


class AuditAttestationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_version: Literal["apa-audit/0.1"]
    predicate_type: Literal["https://warden.gudman.xyz/spec/endpoint-audit/v1"]
    audit_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    issuer: Literal["warden"]
    subject: str
    endpoint_host: str
    battery_id: str
    battery_version: str
    battery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    blocked: int = Field(ge=0)
    total: int = Field(ge=1)
    conclusive: int = Field(ge=1)
    inconclusive: Literal[0]
    benign_total: int = Field(ge=1)
    benign_passed: int = Field(ge=1)
    grade: Literal["A", "B", "C", "D", "F"]
    consent_verified: Literal[True]
    liveness_passed: Literal[True]
    observed_on: str
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    limitations: str
    log_seq: int = Field(ge=1)
    issuer_sig: str


class AuditEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attestation: AuditAttestationRecord | None
    status: Literal["active", "stale", "revoked", "invalid"]
    verified: bool
    revoked_at: int | None
    limitations: str


class ShieldLineageEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollment_revision: int | None = Field(default=None, ge=1)
    comparison: Literal["initial", "unchanged", "improved", "regressed", "inconclusive"]
    reason: str
    occurred_at: int = Field(ge=0)
    accepted_as_baseline: bool
    attestation: AuditAttestationRecord
    status: Literal["active", "stale", "revoked"]
    verified: Literal[True]
    revoked_at: int | None = Field(default=None, ge=0)


class ShieldLineageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    target_id: str = Field(min_length=1, max_length=64)
    entries: list[ShieldLineageEntry]
    total: int = Field(ge=0)
    limitations: str


class AuditResponse(BaseModel):
    score: float = Field(ge=0, le=100)
    grade: Grade
    results: list[AuditResult]
    badge: str
    recommendations: list[str]
    badge_record: BadgeRecord | None = None
    consent_verified: bool = True


class HardenRequest(BaseModel):
    audit_id: str = Field(pattern=r"^[0-9a-f]{16}$")


class HardenContext(BaseModel):
    expected_addresses: list[str] = Field(default_factory=list, max_length=20)


class HardenExample(BaseModel):
    id: str
    payload: str
    expected_verdict: str
    expected_classes: list[str]
    depth: Depth
    context: HardenContext
    source_id: str
    source_revision: str | None
    source_path: str | None
    source_record_id: str | None
    source_url: str | None
    source_file_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    license_spdx: list[str]
    license_url: str | None


class HardenRemediation(BaseModel):
    attack_class: str
    missed: int = Field(ge=1)
    blocked: int = Field(ge=0)
    total: int = Field(ge=1)
    summary: str
    pattern_families: list[str]
    analyzers: list[str]
    example_attacks: list[HardenExample]
    taxonomy_ids: dict[str, list[str]] = Field(default_factory=dict)


class HardenResponse(BaseModel):
    spec_version: Literal["warden-hardening-pack/0.1"]
    predicate_type: Literal["https://warden.gudman.xyz/spec/hardening-pack/v1"]
    pack_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    issuer: Literal["warden"]
    schema_version: Literal[1]
    audit_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    target_host: str
    battery_id: str
    battery_version: str
    observed_on: str
    corpus_fingerprint: str
    addressed_classes: list[str]
    remediation: list[HardenRemediation]
    integration: dict[str, str]
    limitations: str
    message: str
    issued_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    log_seq: int = Field(ge=1)
    issuer_sig: str = Field(pattern=r"^sig:")


class HardenEvidenceResponse(BaseModel):
    pack: HardenResponse | None
    status: Literal["active", "stale", "revoked", "invalid"]
    verified: bool
    revoked_at: int | None = Field(default=None, ge=0)
    issuer_document: dict[str, object] | None
    log_suffix: list[dict[str, object]]
    checkpoint: dict[str, object] | None
    limitations: str


ResistanceGrade = Literal["A", "B", "C", "D", "F", "INCONCLUSIVE"]


class VariantAuditRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=MAX_TARGET_URL_LENGTH)
    # None means every class that has variants. An explicit empty list is rejected by
    # the engine rather than silently treated as "all".
    threat_classes: list[str] | None = Field(default=None, max_length=len(ReasonCode))
    # None means the depth tier's own ceiling. The engine enforces the per-tier
    # limit, so 50 is only reachable at depth "deep".
    max_variants_per_class: int | None = Field(default=None, ge=1, le=50)
    # An earlier retained report for the same host, to be compared against.
    since: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    # "deep" probes more variants over a longer whole-run budget. The listed fee
    # is unchanged; depth is bounded work, not a different product.
    depth: Literal["standard", "deep"] = "standard"


class VariantAuditCaps(BaseModel):
    depth: Literal["standard", "deep"]
    max_variants_per_class: int = Field(ge=1)
    max_total_variants: int = Field(ge=1)
    probe_timeout_seconds: float = Field(gt=0)
    total_timeout_seconds: float = Field(gt=0)
    max_response_bytes: int = Field(ge=1)


class VariantAuditClassResult(BaseModel):
    threat_class: str
    total: int = Field(ge=0)
    detected: int = Field(ge=0)
    missed: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    conclusive: int = Field(ge=0)
    # None when no probe in the class was conclusive, so a rate would be meaningless.
    detection_rate: float | None = Field(default=None, ge=0, le=100)
    # INCONCLUSIVE is the absence of a grade, never a pass.
    grade: ResistanceGrade


class VariantAuditTotals(BaseModel):
    threat_classes: int = Field(ge=0)
    variants_sent: int = Field(ge=0)
    detected: int = Field(ge=0)
    missed: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    conclusive: int = Field(ge=0)
    detection_rate: float | None = Field(default=None, ge=0, le=100)
    grade: ResistanceGrade


class VariantAuditClassDelta(BaseModel):
    threat_class: str
    # None when either run had no conclusive probe in the class.
    detection_rate_change: float | None = Field(default=None, ge=-100, le=100)
    grade_from: ResistanceGrade
    grade_to: ResistanceGrade


class VariantAuditDelta(BaseModel):
    since_report_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    since_issued_at: int = Field(ge=0)
    # False when Warden's corpus or generator moved between the two runs, which
    # makes them different tests rather than a before and after.
    same_corpus: bool
    detection_rate_change: float | None = Field(default=None, ge=-100, le=100)
    grade_from: ResistanceGrade
    grade_to: ResistanceGrade
    per_class: list[VariantAuditClassDelta]


class VariantAuditResponse(BaseModel):
    # Deliberately not pinned to one version: retained reports outlive a schema
    # bump, and a Literal here would turn every stored report into a 500 on the
    # retrieval route the moment SCHEMA_VERSION moves.
    schema_version: int = Field(ge=1)
    target_host: str
    corpus_fingerprint: str
    generator: str
    caps: VariantAuditCaps
    per_class: list[VariantAuditClassResult]
    totals: VariantAuditTotals
    consent_verified: Literal[True]
    limitations: list[str]
    # Server entropy that makes report_id unguessable; see variant_audit.
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    # None unless the request named an earlier report for the same host.
    delta: VariantAuditDelta | None = None
    report_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    issuer: Literal["warden"]
    issued_at: int = Field(ge=0)
    issuer_sig: str


class VariantAuditReportResponse(BaseModel):
    report: VariantAuditResponse
    verified: bool


class ResistanceBadge(BaseModel):
    spec_version: Literal["warden-resistance-badge/1"]
    report_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_host: str
    # INCONCLUSIVE is absent by construction: an ungraded run earns no badge.
    grade: Literal["A", "B", "C", "D", "F"]
    detection_rate: float = Field(ge=0, le=100)
    detected: int = Field(ge=0)
    conclusive: int = Field(ge=1)
    variants_sent: int = Field(ge=1)
    threat_classes: int = Field(ge=1)
    corpus_fingerprint: str
    generator: str
    observed_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)
    issuer: Literal["warden"]
    limitations: str
    issuer_sig: str = Field(pattern=r"^sig:")


class ResistanceBadgeResponse(BaseModel):
    badge: ResistanceBadge
    verified: bool
    status: Literal["active", "stale", "invalid"]


class ApaRegisterRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=MAX_TARGET_URL_LENGTH)


class ApaRevokeRequest(BaseModel):
    attestation_id: str = Field(min_length=1, max_length=64)
    ts: int
    nonce: str = Field(min_length=1, max_length=256)
    replacement_pub: str | None = Field(default=None, min_length=1, max_length=128)
    sig: str = Field(min_length=1, max_length=256)


class HealthResponse(BaseModel):
    status: str
    version: str
    corpus_size: int
    analyzers: list[str]
    uptime_seconds: float = Field(ge=0)


class RuntimeStatsResponse(BaseModel):
    uptime_seconds: float = Field(ge=0)
    scans: int = Field(ge=0)
    blocks_by_class: dict[str, int]
    p50_latency_ms: float | None = Field(default=None, ge=0)


class ReadinessCheck(BaseModel):
    status: Literal["ready", "disabled", "not_ready"]
    detail: str


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    version: str
    checks: dict[str, ReadinessCheck]
