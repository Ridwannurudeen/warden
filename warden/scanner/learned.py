"""Offline learned advisory scorer: pure-numpy inference over signed weights.

The scorer is one L2-regularised logistic regression fitted offline by
``scripts/train_learned_scorer.py``. Only the weights ship; inference here is a
dot product and a logistic, so it is fully deterministic, needs no provider, and
makes no network call.

Loading fails closed at every step. A missing switch, a missing or unreadable
artifact, hostile JSON, a dimension or configuration mismatch, a broken
``model_sha256`` binding, a pinned signature that does not verify, or an absent
``numpy`` all return ``None`` from :func:`build_learned_scorer_from_env`, and a
``None`` scorer leaves the pipeline bit-identical to a build without this module.

The score is reported alongside the scanner result rather than appended to
``detections``. A detection would feed `InjectionScanner._compute_risk_level`
and `_sanitize_content` and so could move a verdict on its own; the block below
reaches `VerdictEngine.decide` only as one more `PolicyRule` folded into the
existing monotone `max`, which is what makes evidence-only provably inert.

Environment:

``WARDEN_LEARNED_SCORER_ENABLED``
    Required. Unset (or not one of ``1/true/yes/on``) is the kill switch.
``WARDEN_LEARNED_SCORER_PATH``
    Optional override for the artifact location.
``WARDEN_LEARNED_SCORER_PUB``
    Optional ``ed25519:`` public key. When set, the artifact's ``issuer_sig``
    must verify against it or the scorer refuses to load.
``WARDEN_LEARNED_EVIDENCE_THRESHOLD``
    Advisory reporting threshold (default 0.5). Never changes a verdict.
``WARDEN_LEARNED_ENFORCE_THRESHOLD``
    Unset means enforcement is off, which is the shipped default. When set, a
    probability at or above it asks the verdict engine for
    ``WARDEN_LEARNED_ENFORCE_VERDICT`` (default ``SANITIZE``), which can only
    ever escalate because verdicts are combined with a monotone ``max``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
from typing import Mapping, Sequence

from warden.badges import ed25519_verify_record
from warden.scanner import features
from warden.scanner.provider_json import load_provider_json

try:  # numpy reaches the locked runtime through an optional extra, so guard it.
    import numpy
except ImportError:  # pragma: no cover - exercised by monkeypatching `numpy`
    numpy = None

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACT_PATH = Path(__file__).with_name("learned_scorer.json")
LEARNED_SCHEMA_VERSION = 1
# Measured over every corpus and held-out row this repo ships (188 attacks, 453
# benign): AUC 0.8105, attack median 0.870, benign median 0.363. At the old 0.5
# default, 135 of 453 benign rows (29.8%) scored high enough to publish a
# probability, so a third of ordinary business text carried a number a reader
# could mistake for a finding. At 0.90 that falls to 6 rows (1.3%) while 47.3%
# of attacks still report. This threshold governs REPORTING only; it does not
# change the model, which stays modest at AUC 0.81 — the lever for that is
# retraining, not this constant.
DEFAULT_EVIDENCE_THRESHOLD = 0.9
DEFAULT_ENFORCE_VERDICT = "SANITIZE"
ENABLED_VALUES = frozenset({"1", "true", "yes", "on"})
ENFORCEABLE_VERDICTS = frozenset({"SANITIZE", "BLOCK"})
MAX_ARTIFACT_BYTES = 4_000_000
SIGNATURE_FIELD = "issuer_sig"
_HASHED_FIELDS = frozenset({"model_sha256", SIGNATURE_FIELD})


def canonical_core(record: Mapping[str, object]) -> str:
    """Canonical JSON of the artifact without its own hash and signature."""
    core = {key: value for key, value in record.items() if key not in _HASHED_FIELDS}
    return json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def model_sha256(record: Mapping[str, object]) -> str:
    """Digest that binds every weight and every declared parameter."""
    return hashlib.sha256(canonical_core(record).encode("utf-8")).hexdigest()


class LearnedScorer:
    """Pure-numpy logistic inference over a validated weights artifact."""

    def __init__(
        self,
        weights: Sequence[float],
        bias: float,
        model_digest: str,
        *,
        evidence_threshold: float = DEFAULT_EVIDENCE_THRESHOLD,
        enforce_threshold: float | None = None,
        enforce_verdict: str = DEFAULT_ENFORCE_VERDICT,
    ) -> None:
        if len(weights) != features.FEATURE_DIMENSION:
            raise ValueError("learned scorer weights must match the feature dimension")
        self._weights = numpy.asarray(weights, dtype=numpy.float64)
        self._bias = float(bias)
        self._model_digest = model_digest
        self._evidence_threshold = evidence_threshold
        self._enforce_threshold = enforce_threshold
        self._enforce_verdict = enforce_verdict

    @property
    def model_sha256(self) -> str:
        return self._model_digest

    @property
    def evidence_threshold(self) -> float:
        return self._evidence_threshold

    def probability(
        self,
        content: str,
        *,
        regex_hits: Sequence[Mapping[str, object]],
        heuristic: Mapping[str, object],
        similarity: Mapping[str, object],
    ) -> float:
        vector = numpy.asarray(
            features.extract_features(
                content,
                regex_hits=regex_hits,
                heuristic=heuristic,
                similarity=similarity,
            ),
            dtype=numpy.float64,
        )
        logit = float(numpy.dot(self._weights, vector)) + self._bias
        return _logistic(logit)

    def evaluate(
        self,
        content: str,
        *,
        regex_hits: Sequence[Mapping[str, object]],
        heuristic: Mapping[str, object],
        similarity: Mapping[str, object],
    ) -> dict[str, object]:
        """Return the advisory evidence block the scanner attaches to its result."""
        score = self.probability(
            content,
            regex_hits=regex_hits,
            heuristic=heuristic,
            similarity=similarity,
        )
        # Enforcement reads the raw score. It must not depend on the reporting
        # threshold, or raising the latter would silently weaken the former.
        enforced = (
            self._enforce_verdict
            if self._enforce_threshold is not None and score >= self._enforce_threshold
            else None
        )
        return {
            # Reported only when it clears the threshold. Below it the model is
            # not separating anything a reader could act on, and publishing the
            # number anyway invites it to be read as a finding.
            "attack_probability": score if score >= self._evidence_threshold else None,
            "scored": True,
            "evidence_threshold": self._evidence_threshold,
            "feature_vector_version": features.FEATURE_VECTOR_VERSION,
            "model_sha256": self._model_digest,
            "enforced_verdict": enforced,
        }


def _logistic(logit: float) -> float:
    if logit >= 0:
        return 1.0 / (1.0 + math.exp(-logit))
    exponential = math.exp(logit)
    return exponential / (1.0 + exponential)


def _finite_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _threshold(values: Mapping[str, str], name: str) -> float | None:
    raw = values.get(name, "").strip()
    if not raw:
        return None
    try:
        parsed = float(raw)
    except ValueError:
        return None
    if not math.isfinite(parsed) or not 0.0 <= parsed <= 1.0:
        return None
    return parsed


def _load_artifact(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            return None
        document = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        record = load_provider_json(document)
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def _validated_weights(record: Mapping[str, object]) -> tuple[list[float], float] | None:
    if record.get("schema_version") != LEARNED_SCHEMA_VERSION:
        return None
    if record.get("feature_vector_version") != features.FEATURE_VECTOR_VERSION:
        return None
    if record.get("feature_dimension") != features.FEATURE_DIMENSION:
        return None
    if record.get("hash_seed") != features.HASH_SEED:
        return None
    if record.get("bucket_count") != features.HASH_BUCKETS:
        return None
    if model_sha256(record) != record.get("model_sha256"):
        return None
    raw_weights = record.get("weights")
    if not isinstance(raw_weights, list) or len(raw_weights) != features.FEATURE_DIMENSION:
        return None
    weights: list[float] = []
    for value in raw_weights:
        number = _finite_float(value)
        if number is None:
            return None
        weights.append(number)
    bias = _finite_float(record.get("bias"))
    if bias is None:
        return None
    return weights, bias


def build_learned_scorer_from_env(
    environ: Mapping[str, str] | None = None,
) -> LearnedScorer | None:
    """Build the advisory scorer, or return ``None`` and leave the pipeline untouched."""
    values = os.environ if environ is None else environ
    if values.get("WARDEN_LEARNED_SCORER_ENABLED", "").strip().lower() not in ENABLED_VALUES:
        return None
    if numpy is None:
        logger.warning("Learned advisory scorer disabled: numpy is unavailable")
        return None

    configured_path = values.get("WARDEN_LEARNED_SCORER_PATH", "").strip()
    path = Path(configured_path) if configured_path else DEFAULT_ARTIFACT_PATH
    record = _load_artifact(path)
    if record is None:
        logger.warning("Learned advisory scorer disabled: artifact is missing or unreadable")
        return None

    public_key = values.get("WARDEN_LEARNED_SCORER_PUB", "").strip()
    if public_key and not ed25519_verify_record(dict(record), public_key, SIGNATURE_FIELD):
        logger.warning("Learned advisory scorer disabled: artifact signature did not verify")
        return None

    validated = _validated_weights(record)
    if validated is None:
        logger.warning("Learned advisory scorer disabled: artifact failed validation")
        return None
    weights, bias = validated

    enforce_verdict = values.get("WARDEN_LEARNED_ENFORCE_VERDICT", "").strip().upper()
    if enforce_verdict not in ENFORCEABLE_VERDICTS:
        enforce_verdict = DEFAULT_ENFORCE_VERDICT
    try:
        return LearnedScorer(
            weights,
            bias,
            str(record["model_sha256"]),
            # `or` would fold a deliberate 0.0 into the default, because zero is
            # falsy — and 0.0 is the one setting that means "publish everything",
            # which an operator debugging the scorer is most likely to reach for.
            evidence_threshold=(
                configured_evidence
                if (configured_evidence := _threshold(values, "WARDEN_LEARNED_EVIDENCE_THRESHOLD"))
                is not None
                else DEFAULT_EVIDENCE_THRESHOLD
            ),
            enforce_threshold=_threshold(values, "WARDEN_LEARNED_ENFORCE_THRESHOLD"),
            enforce_verdict=enforce_verdict,
        )
    except ValueError:
        return None
