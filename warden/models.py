"""Pydantic boundary models for Warden HTTP and MCP surfaces."""

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
        )


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

    @field_validator("sample_prompts")
    @classmethod
    def truncate_sample_prompts(cls, value: list[str]) -> list[str]:
        return [prompt[:MAX_PAYLOAD_LENGTH] for prompt in value]


class AuditResult(BaseModel):
    attack_class: str
    sent: str
    blocked: bool


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


class AuditResponse(BaseModel):
    score: float = Field(ge=0, le=100)
    grade: Grade
    results: list[AuditResult]
    badge: str
    recommendations: list[str]
    badge_record: BadgeRecord | None = None
    consent_verified: bool = True


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
