"""Pydantic boundary models for Warden HTTP and MCP surfaces."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from warden.core.verdict import ReasonCode, Verdict

MAX_PAYLOAD_LENGTH = 100_000
MAX_DEMO_PAYLOAD_LENGTH = 4_000
MAX_DEMO_EXPECTED_ADDRESSES = 20
MAX_TARGET_URL_LENGTH = 2_048
MAX_SAMPLE_PROMPTS = 20

Depth = Literal["fast", "thorough"]
VerdictLabel = Literal["ALLOW", "SANITIZE", "BLOCK"]
RiskLabel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Grade = Literal["A", "B", "C", "D", "F"]
ClaimStatus = Literal["not_candidate", "pending", "duplicate"]


class ScanContext(BaseModel):
    expected_addresses: list[str] = Field(default_factory=list)
    source: str | None = Field(default=None, max_length=256)


class ScanRequest(BaseModel):
    payload: str
    depth: Depth = "fast"
    context: ScanContext = Field(default_factory=ScanContext)

    @field_validator("payload")
    @classmethod
    def truncate_payload(cls, value: str) -> str:
        return value[:MAX_PAYLOAD_LENGTH]


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
        return value[:MAX_DEMO_PAYLOAD_LENGTH]


class DemoExample(BaseModel):
    id: str
    label: str
    reason_code: ReasonCode | None
    payload: str


class GauntletRequest(BaseModel):
    intent: str = Field(max_length=500)
    payload: str
    context: DemoScanContext = Field(default_factory=DemoScanContext)
    finder: str | None = Field(default=None, max_length=128)

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

    @field_validator("finder")
    @classmethod
    def normalize_finder(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


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


class GauntletResponse(ScanResponse):
    claim_status: ClaimStatus
    claim_id: str | None = None


class GauntletStats(BaseModel):
    attempts: int
    pending_claims: int
    confirmed_bypasses: int
    corpus_size: int


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
    signature: str


class AuditResponse(BaseModel):
    score: float = Field(ge=0, le=100)
    grade: Grade
    results: list[AuditResult]
    badge: str
    recommendations: list[str]
    badge_record: BadgeRecord | None = None
    consent_verified: bool = True


class HealthResponse(BaseModel):
    status: str
    version: str
    corpus_size: int
    analyzers: list[str]
