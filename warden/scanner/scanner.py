"""Deterministic prompt-injection detection for Warden's production engine.

Protects AI agents from malicious content embedded in token metadata,
contract descriptions, and data feeds.

The default layers are regex matching, statistical heuristics, and thorough-mode
TF-IDF similarity against the versioned attack corpus. Provider-neutral embedding
similarity and semantic classification are available only when explicitly configured
in a paid runtime; they run after the deterministic thorough layers and failures
preserve their result.
"""

import logging
import math
import re
import unicodedata
from collections import Counter
from typing import Dict, List, Optional, Tuple

from warden.scanner.embedding import EmbeddingAnalyzer
from warden.scanner.learned import LearnedScorer
from warden.scanner.patterns import (
    INJECTION_PATTERNS,
    CATEGORY_CONFIDENCE,
    ENTROPY_THRESHOLD,
    INVISIBLE_RATIO_THRESHOLD,
    INSTRUCTION_DENSITY_THRESHOLD,
    CONTEXT_SWITCH_OVERLAP_THRESHOLD,
    HEURISTIC_SCORE_THRESHOLD,
    HEURISTIC_WEIGHTS,
    IMPERATIVE_VERBS,
    INSTRUCTION_KEYWORDS,
    KNOWN_INJECTIONS,
    SIMILARITY_THRESHOLD,
    AMBIGUOUS_RANGE,
)
from warden.scanner.semantic import SemanticAnalyzer, SemanticThreatCategory

logger = logging.getLogger(__name__)

SEMANTIC_CONFIDENCE_THRESHOLD = 0.8
EMBEDDING_SIMILARITY_THRESHOLD = 0.82
MAX_REGEX_MATCHES_PER_CATEGORY = 100
SEMANTIC_PATTERN_CATEGORIES = {
    SemanticThreatCategory.PROMPT_INJECTION: "ai_prompt_injection",
    SemanticThreatCategory.DRAIN_ADDRESS: "ai_drain_address",
    SemanticThreatCategory.SECRET_EXFIL: "ai_secret_exfil",
    SemanticThreatCategory.TOOL_HIJACK: "ai_tool_hijack",
}
WHOLE_PAYLOAD_REDACTION_CATEGORIES = frozenset(
    {
        "direct_instruction",
        "role_override",
        "web3_specific",
        "encoding_tricks",
        "corpus_match",
    }
)


class InjectionScanner:
    """Deterministic prompt-injection detection with optional paid model tiers."""

    def __init__(
        self,
        ai_analyzer: SemanticAnalyzer | None = None,
        embedding_analyzer: EmbeddingAnalyzer | None = None,
        learned_scorer: LearnedScorer | None = None,
    ):
        self._ai = ai_analyzer
        self._embedding = embedding_analyzer
        self._learned = learned_scorer
        # Pre-compile regex patterns for performance
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        for category, patterns in INJECTION_PATTERNS.items():
            self._compiled_patterns[category] = [(re.compile(p), p) for p in patterns]
        # Pre-compute TF-IDF vectors for known injections (Layer 3)
        self._idf: Dict[str, float] = {}
        self._corpus_vectors: List[Dict[str, float]] = []
        self._build_tfidf_corpus()

    def _build_tfidf_corpus(self) -> None:
        """Build TF-IDF vectors for the known injection corpus."""
        # Tokenize all documents
        tokenized = [self._tokenize(doc) for doc in KNOWN_INJECTIONS]
        n_docs = len(tokenized)

        # Compute document frequency
        df: Counter = Counter()
        for tokens in tokenized:
            unique_tokens = set(tokens)
            for token in unique_tokens:
                df[token] += 1

        # Compute IDF: log(N / df) with smoothing
        self._idf = {token: math.log((n_docs + 1) / (count + 1)) + 1 for token, count in df.items()}

        # Compute TF-IDF vector per document
        self._corpus_vectors = []
        for tokens in tokenized:
            tf = Counter(tokens)
            total = len(tokens) if tokens else 1
            vec = {
                token: (count / total) * self._idf.get(token, 1.0) for token, count in tf.items()
            }
            self._corpus_vectors.append(vec)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Lowercase word tokenization for TF-IDF."""
        return re.findall(r"[a-z0-9]+", text.lower())

    async def scan(
        self,
        content: str,
        depth: str = "fast",
        allow_semantic: bool = True,
    ) -> Dict:
        """Scan content for prompt injection.

        Args:
            content: Text to scan (token metadata, contract description, etc.)
            depth: "fast" for regex and heuristics, "thorough" to add TF-IDF and
                the optional configured embedding and semantic classifiers.
            allow_semantic: Whether the caller's deterministic gates permit the
                optional paid model tiers.

        Returns:
            dict with keys:
                clean (bool): True if no injection detected
                risk_level (str): NONE / LOW / MEDIUM / HIGH / CRITICAL
                layers_triggered (list[int]): Which layers flagged the content
                detections (list[dict]): Individual detection results
                sanitized_content (str): Content with injections removed
                recommendation (str): Human-readable guidance
                learned (dict | None): Offline learned-scorer evidence, or None
                    when no weights artifact is loaded. Never affects the keys
                    above.
        """
        if not content or not content.strip():
            return self._build_result(
                clean=True,
                risk_level="NONE",
                layers_triggered=[],
                detections=[],
                sanitized_content=content or "",
                recommendation="Empty content — no injection risk.",
                learned=None,
                semantic_consulted=False,
            )

        detections: List[Dict] = []
        layers_triggered: List[int] = []
        semantic_consulted = False

        # ── Layer 1: Regex fast-path ───────────────────────────────
        layer1_hits = self._run_regex_layer(content)
        if layer1_hits:
            detections.extend(layer1_hits)
            layers_triggered.append(1)

        # ── Layer 2: Statistical heuristics ────────────────────────
        layer2_result = self._run_heuristic_layer(content)
        if layer2_result["flagged"]:
            detections.append(
                {
                    "type": "heuristic",
                    "pattern_category": "statistical_analysis",
                    "match_text": None,
                    "confidence": layer2_result["score"],
                    "layer": 2,
                    "detail": layer2_result["detail"],
                }
            )
            layers_triggered.append(2)

        layer3_result: Optional[Dict] = None

        if depth == "thorough":
            heuristic_score = layer2_result["score"]

            # ── Layer 3: TF-IDF similarity ─────────────────────────
            # Trigger when Layer 2 score is ambiguous OR Layer 1 found nothing
            if (AMBIGUOUS_RANGE[0] <= heuristic_score <= AMBIGUOUS_RANGE[1]) or not layer1_hits:
                layer3_result = self._run_similarity_layer(content)
                if layer3_result["flagged"]:
                    detections.append(
                        {
                            "type": "similarity",
                            "pattern_category": "corpus_match",
                            "match_text": layer3_result["closest_match"],
                            "confidence": layer3_result["similarity"],
                            "layer": 3,
                            "detail": f"Cosine similarity {layer3_result['similarity']:.2f} with known injection",
                        }
                    )
                    layers_triggered.append(3)

            # ── Layer 4: embedding similarity ──────────────────────
            # Deterministic detections are authoritative and avoid the paid calls.
            if allow_semantic and self._embedding and not detections:
                layer4_result = await self._run_embedding_layer(content)
                if layer4_result["flagged"]:
                    detections.append(
                        {
                            "type": "embedding_similarity",
                            "pattern_category": "embedding_match",
                            "match_text": None,
                            "confidence": layer4_result["confidence"],
                            "layer": 4,
                            "detail": layer4_result["detail"],
                        }
                    )
                    layers_triggered.append(4)

            if allow_semantic and self._ai and not detections:
                # Recorded whether or not it flags: a receipt that only shows the
                # layer when it fires cannot distinguish "the model judged this
                # clean" from "the model was never asked".
                semantic_consulted = True
                layer5_result = await self._run_semantic_layer(content)
                if layer5_result["flagged"]:
                    detections.append(
                        {
                            "type": "semantic_classification",
                            "pattern_category": layer5_result["pattern_category"],
                            "match_text": None,
                            "confidence": layer5_result["confidence"],
                            "layer": 5,
                            "detail": layer5_result["reason"],
                        }
                    )
                    layers_triggered.append(5)

        # ── Learned advisory layer ─────────────────────────────────
        # Offline weights, pure numpy, evidence only: the block below is
        # attached alongside the deterministic result and never enters
        # `detections`, so `clean`, `risk_level`, `layers_triggered` and
        # `sanitized_content` are byte-identical to a run without a model.
        learned: Optional[Dict] = None
        if self._learned is not None:
            if layer3_result is None:
                layer3_result = self._run_similarity_layer(content)
            learned = self._learned.evaluate(
                content,
                regex_hits=layer1_hits,
                heuristic=layer2_result,
                similarity=layer3_result,
            )

        # ── Aggregate results ──────────────────────────────────────
        clean = len(detections) == 0
        risk_level = self._compute_risk_level(detections, layers_triggered)
        sanitized = self._sanitize_content(content, detections)
        recommendation = self._build_recommendation(clean, risk_level, detections)

        return self._build_result(
            clean=clean,
            risk_level=risk_level,
            layers_triggered=sorted(set(layers_triggered)),
            detections=detections,
            sanitized_content=sanitized,
            recommendation=recommendation,
            learned=learned,
            semantic_consulted=semantic_consulted,
        )

    # ── Layer 1: Regex ─────────────────────────────────────────────────

    def _run_regex_layer(self, content: str) -> List[Dict]:
        """Run compiled regex patterns against content."""
        hits = []
        for category, compiled_list in self._compiled_patterns.items():
            confidence = CATEGORY_CONFIDENCE.get(category, 0.85)
            seen_matches = set()
            for pattern, raw_pattern in compiled_list:
                for match in pattern.finditer(content):
                    match_text = match.group()
                    if match_text in seen_matches:
                        continue
                    seen_matches.add(match_text)
                    hits.append(
                        {
                            "type": "regex",
                            "pattern_category": category,
                            "match_text": match_text,
                            "confidence": confidence,
                            "layer": 1,
                        }
                    )
                    if len(seen_matches) >= MAX_REGEX_MATCHES_PER_CATEGORY:
                        break
                if len(seen_matches) >= MAX_REGEX_MATCHES_PER_CATEGORY:
                    break
        return hits

    # ── Layer 2: Heuristics ────────────────────────────────────────────

    def _run_heuristic_layer(self, content: str) -> Dict:
        """Run statistical heuristic analyzers on content."""
        scores = {}
        details = []

        # 2a. Unicode entropy analysis
        entropy = self._unicode_entropy(content)
        entropy_score = (
            min(1.0, max(0.0, (entropy - 2.0) / (ENTROPY_THRESHOLD - 2.0)))
            if ENTROPY_THRESHOLD > 2.0
            else 0.0
        )
        scores["entropy"] = entropy_score
        if entropy > ENTROPY_THRESHOLD:
            details.append(f"High Unicode entropy: {entropy:.2f}")

        # 2b. Invisible character ratio
        invisible_ratio = self._invisible_char_ratio(content)
        invisible_score = (
            min(1.0, invisible_ratio / INVISIBLE_RATIO_THRESHOLD)
            if INVISIBLE_RATIO_THRESHOLD > 0
            else 0.0
        )
        scores["invisible_ratio"] = invisible_score
        if invisible_ratio > INVISIBLE_RATIO_THRESHOLD:
            details.append(f"Invisible char ratio: {invisible_ratio:.4f}")

        # 2c. Instruction density
        density = self._instruction_density(content)
        density_score = (
            min(1.0, density / INSTRUCTION_DENSITY_THRESHOLD)
            if INSTRUCTION_DENSITY_THRESHOLD > 0
            else 0.0
        )
        scores["instruction_density"] = density_score
        if density > INSTRUCTION_DENSITY_THRESHOLD:
            details.append(f"High instruction density: {density:.2f}")

        # 2d. Context switch detection
        switch_score = self._context_switch_score(content)
        scores["context_switch"] = switch_score
        if switch_score > 0.6:
            details.append(f"Context switch detected: score={switch_score:.2f}")

        # Weighted average
        combined = sum(scores[k] * HEURISTIC_WEIGHTS[k] for k in HEURISTIC_WEIGHTS)

        return {
            "score": round(combined, 4),
            "flagged": combined > HEURISTIC_SCORE_THRESHOLD,
            "detail": "; ".join(details) if details else "No heuristic anomalies",
            "subscores": scores,
        }

    @staticmethod
    def _unicode_entropy(text: str) -> float:
        """Shannon entropy over Unicode general categories."""
        if not text:
            return 0.0
        categories = [unicodedata.category(ch) for ch in text]
        counts = Counter(categories)
        total = len(categories)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _invisible_char_ratio(text: str) -> float:
        """Ratio of zero-width / control characters to total length."""
        if not text:
            return 0.0
        invisible = set(
            "\u200b\u200c\u200d\u200e\u200f"
            "\u2060\u2061\u2062\u2063\ufeff"
            "\u202a\u202b\u202c\u202d\u202e"
        )
        count = sum(1 for ch in text if ch in invisible)
        return count / len(text)

    @staticmethod
    def _instruction_density(text: str) -> float:
        """Ratio of imperative verbs to total words."""
        words = re.findall(r"[a-zA-Z]+", text.lower())
        if not words:
            return 0.0
        verb_count = sum(1 for w in words if w in IMPERATIVE_VERBS)
        return verb_count / len(words)

    @staticmethod
    def _context_switch_score(text: str) -> float:
        """Detect topic switches between first and second halves of text."""
        words = re.findall(r"[a-zA-Z]+", text.lower())
        if len(words) < 6:
            return 0.0

        mid = len(words) // 2
        first_half = set(words[:mid])
        second_half = set(words[mid:])

        # Word overlap (Jaccard-like)
        if not first_half or not second_half:
            return 0.0
        overlap = len(first_half & second_half) / len(first_half | second_half)

        # Instruction keyword presence in second half
        instruction_count = len(second_half & INSTRUCTION_KEYWORDS)
        keyword_ratio = instruction_count / len(second_half) if second_half else 0

        # Low overlap + high instruction keywords = suspicious
        if overlap < CONTEXT_SWITCH_OVERLAP_THRESHOLD and keyword_ratio > 0.1:
            return min(1.0, (1 - overlap) * 0.6 + keyword_ratio * 0.4)

        return max(0.0, (1 - overlap) * 0.3)

    # ── Layer 3: TF-IDF similarity ─────────────────────────────────────

    def _run_similarity_layer(self, content: str) -> Dict:
        """Compute TF-IDF cosine similarity against known injection corpus."""
        tokens = self._tokenize(content)
        if not tokens:
            return {"flagged": False, "similarity": 0.0, "closest_match": ""}

        # Build query TF-IDF vector
        tf = Counter(tokens)
        total = len(tokens)
        query_vec = {
            token: (count / total) * self._idf.get(token, 1.0) for token, count in tf.items()
        }

        # Find maximum cosine similarity
        best_sim = 0.0
        best_idx = 0
        for i, doc_vec in enumerate(self._corpus_vectors):
            sim = self._cosine_similarity(query_vec, doc_vec)
            if sim > best_sim:
                best_sim = sim
                best_idx = i

        return {
            "flagged": best_sim >= SIMILARITY_THRESHOLD,
            "similarity": round(best_sim, 4),
            "closest_match": KNOWN_INJECTIONS[best_idx] if best_sim >= SIMILARITY_THRESHOLD else "",
        }

    @staticmethod
    def _cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Cosine similarity between two sparse vectors (dicts)."""
        common_keys = set(vec_a) & set(vec_b)
        if not common_keys:
            return 0.0

        dot = sum(vec_a[k] * vec_b[k] for k in common_keys)
        mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
        mag_b = math.sqrt(sum(v * v for v in vec_b.values()))

        if mag_a == 0 or mag_b == 0:
            return 0.0

        return dot / (mag_a * mag_b)

    # ── Layer 4: embedding similarity ──────────────────────────────────

    async def _run_embedding_layer(self, content: str) -> Dict:
        """Compare content with cached embeddings for the versioned corpus."""
        try:
            match = await self._embedding.match(content, tuple(KNOWN_INJECTIONS))
            similarity = match.similarity
            if (
                isinstance(similarity, bool)
                or not isinstance(similarity, (int, float))
                or not math.isfinite(similarity)
                or not -1 <= similarity <= 1
            ):
                raise ValueError("embedding similarity must be finite and between -1 and 1")
            similarity = float(similarity)
            return {
                "flagged": similarity >= EMBEDDING_SIMILARITY_THRESHOLD,
                "confidence": max(0.0, similarity),
                "detail": (
                    f"Embedding similarity {similarity:.2f} with the versioned injection corpus"
                ),
            }
        except Exception as exc:
            logger.warning(
                "Optional embedding similarity unavailable: %s",
                type(exc).__name__,
            )
            return {
                "flagged": False,
                "confidence": 0.0,
                "detail": "Embedding layer unavailable",
            }

    # ── Layer 5: semantic classification ───────────────────────────────

    async def _run_semantic_layer(self, content: str) -> Dict:
        """Ask the configured optional analyzer for semantic classification."""
        try:
            classification = await self._ai.classify(content)
            if not isinstance(classification.flagged, bool):
                raise ValueError("semantic flagged value must be a boolean")
            if (
                isinstance(classification.confidence, bool)
                or not isinstance(classification.confidence, (int, float))
                or not math.isfinite(classification.confidence)
                or not 0 <= classification.confidence <= 1
            ):
                raise ValueError("semantic confidence must be finite and between 0 and 1")
            if not isinstance(classification.reason, str):
                raise ValueError("semantic reason must be a string")
            pattern_category = (
                SEMANTIC_PATTERN_CATEGORIES.get(classification.category)
                if classification.flagged
                else None
            )
            if classification.flagged and pattern_category is None:
                raise ValueError("flagged semantic classification requires a supported category")
            return {
                "flagged": (
                    classification.flagged
                    and classification.confidence >= SEMANTIC_CONFIDENCE_THRESHOLD
                ),
                "confidence": classification.confidence,
                "reason": classification.reason,
                "pattern_category": pattern_category,
            }
        except Exception as exc:
            logger.warning(
                "Optional semantic classification unavailable: %s",
                type(exc).__name__,
            )
            return {
                "flagged": False,
                "confidence": 0.0,
                "reason": "Semantic layer unavailable",
                "pattern_category": None,
            }

    # ── Result building ────────────────────────────────────────────────

    @staticmethod
    def _compute_risk_level(detections: List[Dict], layers_triggered: List[int]) -> str:
        """Compute overall risk level from detections."""
        if not detections:
            return "NONE"

        max_confidence = max(d["confidence"] for d in detections)
        n_layers = len(set(layers_triggered))

        # Multiple layers agreeing = higher risk
        if max_confidence >= 0.90 and n_layers >= 2:
            return "CRITICAL"
        if max_confidence >= 0.90 or n_layers >= 3:
            return "HIGH"
        if max_confidence >= 0.70 or n_layers >= 2:
            return "MEDIUM"
        return "LOW"

    def _sanitize_content(self, content: str, detections: List[Dict]) -> str:
        """Remove detected injection payloads from content."""
        categories = {det.get("pattern_category") for det in detections}
        if categories & WHOLE_PAYLOAD_REDACTION_CATEGORIES:
            return "[REDACTED]"

        # Remove invisible/control characters
        invisible = set(
            "\u200b\u200c\u200d\u200e\u200f"
            "\u2060\u2061\u2062\u2063\ufeff"
            "\u202a\u202b\u202c\u202d\u202e"
        )
        return "".join(ch for ch in content if ch not in invisible)

    @staticmethod
    def _build_recommendation(clean: bool, risk_level: str, detections: List[Dict]) -> str:
        """Generate human-readable recommendation."""
        if clean:
            return "Content appears clean. No prompt injection indicators detected."

        categories = set()
        for d in detections:
            categories.add(d.get("pattern_category", "unknown"))

        parts = []
        if "direct_instruction" in categories:
            parts.append("Direct instruction override attempt detected.")
        if "role_override" in categories:
            parts.append("Role/identity manipulation attempt detected.")
        if "web3_specific" in categories:
            parts.append("Web3-targeted injection (fund transfer/approval) detected.")
        if "control_characters" in categories:
            parts.append("Hidden control characters found — possible obfuscation.")
        if "encoding_tricks" in categories:
            parts.append("Encoded payload detected.")
        if "statistical_analysis" in categories:
            parts.append("Statistical anomalies suggest injection content.")
        if "corpus_match" in categories:
            parts.append("Content matches known injection payloads.")
        if "embedding_match" in categories:
            parts.append("Embedding similarity matched the injection corpus.")
        if "ai_prompt_injection" in categories:
            parts.append("Semantic classifier flagged prompt-injection intent.")
        if "ai_drain_address" in categories:
            parts.append("Semantic classifier flagged payment-redirection intent.")
        if "ai_secret_exfil" in categories:
            parts.append("Semantic classifier flagged secret-exfiltration intent.")
        if "ai_tool_hijack" in categories:
            parts.append("Semantic classifier flagged tool-hijack intent.")

        advice = {
            "LOW": "Monitor but likely benign.",
            "MEDIUM": "Exercise caution — inspect content before processing.",
            "HIGH": "Block this content from AI agent processing.",
            "CRITICAL": "Block immediately — high-confidence injection attempt.",
        }

        parts.append(advice.get(risk_level, "Review manually."))
        return " ".join(parts)

    @staticmethod
    def _build_result(**kwargs) -> Dict:
        """Construct the standardized result dict."""
        return {
            "clean": kwargs["clean"],
            "risk_level": kwargs["risk_level"],
            "layers_triggered": kwargs["layers_triggered"],
            "detections": kwargs["detections"],
            "sanitized_content": kwargs["sanitized_content"],
            "recommendation": kwargs["recommendation"],
            "learned": kwargs["learned"],
            "semantic_consulted": kwargs["semantic_consulted"],
        }
