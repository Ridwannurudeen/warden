"""Near-duplicate leakage, clustering, and split-integrity gates for dataset promotion.

Exact-match dedupe (``canonical_dataset_payload``) cannot see a paraphrase, a respaced
payload, or a base64 blob with one character changed. Three gates close that gap:

Gate A (leakage, hard fail)
    Every candidate row is compared against every held-out row. A row is rejected when
    its MinHash-estimated Jaccard over shingles reaches ``LEAKAGE_JACCARD_THRESHOLD``,
    when the exact Jaccard over the same shingles reaches it, or when 13-gram
    containment against a held-out row exceeds ``LEAKAGE_CONTAINMENT_THRESHOLD``.
    Containment is the gate that catches a short held-out payload sitting verbatim
    inside a long ingested one, which Jaccard dilutes to nothing.

Gate B (intra-corpus, report only)
    Candidates plus existing training rows are clustered at ``CLUSTER_JACCARD_THRESHOLD``
    so training can weight by cluster representative instead of memorising one phrase a
    thousand times. Clustering never fails a promotion.

Gate C (split integrity)
    The cluster assignment from Gate B is published per row so whole clusters can be
    kept on one side of any later train/eval split.

Everything here is pure Python plus NumPy. The MinHash permutation parameters are
derived from keyed BLAKE2b digests rather than a seeded RNG so signatures are identical
across processes, machines, and NumPy releases.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import NamedTuple

import numpy as np

from warden.scanner.normalize import fold_unicode

MINHASH_PERMUTATIONS = 128
MINHASH_SEED = "warden-near-duplicates-v1"
WORD_SHINGLE_SIZE = 5
CHARACTER_SHINGLE_SIZE = 5
CONTAINMENT_GRAM_SIZE = 13
CONTAINMENT_MIN_TOKENS = 5
LEAKAGE_JACCARD_THRESHOLD = 0.8
LEAKAGE_CONTAINMENT_THRESHOLD = 0.5
CLUSTER_JACCARD_THRESHOLD = 0.8
SEGMENTATION_RUN_LENGTH = 3
LSH_BANDS = 16
LSH_ROWS = 8
DECONTAMINATION_REPORT_NAME = "decontamination-report.json"
REPORT_SCHEMA_VERSION = 1

_MERSENNE_PRIME = (1 << 31) - 1
_WORD_PREFIX = "w:"
_CHARACTER_PREFIX = "c:"

assert LSH_BANDS * LSH_ROWS == MINHASH_PERMUTATIONS


def _permutation_parameters() -> tuple[np.ndarray, np.ndarray]:
    multipliers: list[int] = []
    offsets: list[int] = []
    for index in range(MINHASH_PERMUTATIONS):
        digest = hashlib.blake2b(
            f"{MINHASH_SEED}/{index}".encode(),
            digest_size=16,
            person=b"warden-minhash",
        ).digest()
        multipliers.append(int.from_bytes(digest[:8], "big") % (_MERSENNE_PRIME - 1) + 1)
        offsets.append(int.from_bytes(digest[8:], "big") % _MERSENNE_PRIME)
    return (
        np.array(multipliers, dtype=np.uint64),
        np.array(offsets, dtype=np.uint64),
    )


_MULTIPLIERS, _OFFSETS = _permutation_parameters()
_EMPTY_SIGNATURE = np.full(MINHASH_PERMUTATIONS, _MERSENNE_PRIME, dtype=np.uint64)


def _collapse_spaced_letters(tokens: list[str]) -> list[str]:
    """Join ``i g n o r e`` back into ``ignore`` so respacing is not a novel row."""
    collapsed: list[str] = []
    run: list[str] = []
    for token in tokens:
        if len(token) == 1:
            run.append(token)
            continue
        if len(run) >= SEGMENTATION_RUN_LENGTH:
            collapsed.append("".join(run))
        else:
            collapsed.extend(run)
        run = []
        collapsed.append(token)
    if len(run) >= SEGMENTATION_RUN_LENGTH:
        collapsed.append("".join(run))
    else:
        collapsed.extend(run)
    return collapsed


def shingle_fold(text: str) -> str:
    """Fold text to the space-delimited alphanumeric form used for every shingle.

    Unicode is folded with the scanner's own ``fold_unicode`` (NFKC, invisible and bidi
    control removal, homoglyph mapping), then case is folded, then every non-alphanumeric
    character becomes a space. Collapsing punctuation is load-bearing rather than
    cosmetic: 35 of the 94 held-out attack payloads are JSON objects or base64 blobs that
    contain no ASCII space at all, so whitespace-only tokenisation makes word shingles
    degenerate for them. Runs of single-character tokens are rejoined last.
    """
    folded = fold_unicode(text).casefold()
    spaced = "".join(character if character.isalnum() else " " for character in folded)
    return " ".join(_collapse_spaced_letters(spaced.split()))


def shingles(text: str) -> frozenset[str]:
    """Return the shingle set of ``text``: word 5-grams plus space-free character 5-grams.

    Word shingles carry phrase-level similarity. Character shingles are always emitted
    over the space-stripped fold so a one-token base64 payload, a respaced payload, and a
    JSON blob all still have a non-degenerate representation. The two families are
    prefixed so they occupy disjoint parts of the shingle universe.
    """
    return _shingles(shingle_fold(text).split())


def _shingles(tokens: list[str]) -> frozenset[str]:
    grams: set[str] = set()
    if len(tokens) >= WORD_SHINGLE_SIZE:
        grams.update(
            _WORD_PREFIX + " ".join(tokens[index : index + WORD_SHINGLE_SIZE])
            for index in range(len(tokens) - WORD_SHINGLE_SIZE + 1)
        )
    elif tokens:
        grams.add(_WORD_PREFIX + " ".join(tokens))
    compact = "".join(tokens)
    if len(compact) >= CHARACTER_SHINGLE_SIZE:
        grams.update(
            _CHARACTER_PREFIX + compact[index : index + CHARACTER_SHINGLE_SIZE]
            for index in range(len(compact) - CHARACTER_SHINGLE_SIZE + 1)
        )
    elif compact:
        grams.add(_CHARACTER_PREFIX + compact)
    return frozenset(grams)


def containment_grams(text: str, size: int) -> frozenset[str]:
    """Return word ``size``-grams, or the whole token sequence when the row is shorter."""
    return _containment_grams(shingle_fold(text).split(), size)


def _containment_grams(tokens: list[str], size: int) -> frozenset[str]:
    if not tokens:
        return frozenset()
    if len(tokens) < size:
        return frozenset({" ".join(tokens)})
    return frozenset(
        " ".join(tokens[index : index + size]) for index in range(len(tokens) - size + 1)
    )


def _gram_hash(gram: str) -> int:
    return (
        int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=4).digest(), "big")
        % _MERSENNE_PRIME
    )


def minhash_signature(grams: Iterable[str]) -> np.ndarray:
    """Return the ``MINHASH_PERMUTATIONS``-wide MinHash signature of a shingle set."""
    hashed = np.array(sorted({_gram_hash(gram) for gram in grams}), dtype=np.uint64)
    if hashed.size == 0:
        return _EMPTY_SIGNATURE.copy()
    permuted = (np.multiply.outer(hashed, _MULTIPLIERS) + _OFFSETS) % _MERSENNE_PRIME
    return permuted.min(axis=0).astype(np.uint64)


def estimate_jaccard(left: np.ndarray, right: np.ndarray) -> float:
    """Return the MinHash-estimated Jaccard similarity of two signatures."""
    return float(np.count_nonzero(left == right)) / MINHASH_PERMUTATIONS


def exact_jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    return intersection / (len(left) + len(right) - intersection)


class _Row(NamedTuple):
    row_id: str
    shingles: frozenset[str]
    signature: np.ndarray
    containment_grams: frozenset[str]
    token_count: int


def _prepare(row_id: str, payload: str) -> _Row:
    tokens = shingle_fold(payload).split()
    grams = _shingles(tokens)
    return _Row(
        row_id=row_id,
        shingles=grams,
        signature=minhash_signature(grams),
        containment_grams=_containment_grams(tokens, CONTAINMENT_GRAM_SIZE),
        token_count=len(tokens),
    )


def _prepare_all(rows: Sequence[tuple[str, str]]) -> list[_Row]:
    return [_prepare(row_id, payload) for row_id, payload in rows]


class LeakageFinding(NamedTuple):
    """The strongest held-out overlap measured for one candidate row."""

    row_id: str
    estimated_jaccard: float
    estimated_dataset: str | None
    estimated_row_id: str | None
    exact_jaccard: float
    exact_dataset: str | None
    exact_row_id: str | None
    max_containment: float
    containment_dataset: str | None
    containment_row_id: str | None
    reasons: tuple[str, ...]

    @property
    def rejected(self) -> bool:
        return bool(self.reasons)


def _name_pair(pair: tuple[str, str] | None) -> str:
    return f"{pair[0]} row {pair[1]}" if pair else "no held-out row"


def _held_out_matrix(rows: Sequence[_Row]) -> np.ndarray:
    if not rows:
        return np.empty((0, MINHASH_PERMUTATIONS), dtype=np.uint64)
    return np.vstack([row.signature for row in rows])


def measure_leakage(
    candidates: Sequence[tuple[str, str]],
    held_out: Mapping[str, Sequence[tuple[str, str]]],
) -> list[LeakageFinding]:
    """Gate A. Measure every candidate against every held-out row and flag leakage.

    The held-out side is small and fixed, so this is an exhaustive comparison rather than
    an LSH prefilter: a hard-fail gate must not be able to miss a pair because a banding
    draw went the wrong way. Both the MinHash estimate and the exact Jaccard over the same
    shingle sets are computed, and either one reaching the threshold rejects the row, so
    MinHash estimator variance can only ever reject a borderline row, never admit one.
    """
    prepared_held_out = {name: _prepare_all(rows) for name, rows in held_out.items()}
    signature_matrices = {name: _held_out_matrix(rows) for name, rows in prepared_held_out.items()}
    gram_index: dict[str, list[tuple[str, int]]] = {}
    containment_index: dict[str, list[tuple[str, int]]] = {}
    for name, rows in prepared_held_out.items():
        for position, row in enumerate(rows):
            for gram in row.shingles:
                gram_index.setdefault(gram, []).append((name, position))
            for gram in row.containment_grams:
                containment_index.setdefault(gram, []).append((name, position))

    findings: list[LeakageFinding] = []
    for row_id, payload in candidates:
        candidate = _prepare(row_id, payload)
        best_estimate = 0.0
        estimated_pair: tuple[str, str] | None = None
        for name, matrix in signature_matrices.items():
            if matrix.shape[0] == 0:
                continue
            estimates = (
                np.count_nonzero(matrix == candidate.signature, axis=1) / MINHASH_PERMUTATIONS
            )
            position = int(np.argmax(estimates))
            estimate = float(estimates[position])
            if estimate > best_estimate:
                best_estimate = estimate
                estimated_pair = (name, prepared_held_out[name][position].row_id)

        best_exact = 0.0
        exact_pair: tuple[str, str] | None = None
        overlaps: Counter[tuple[str, int]] = Counter()
        for gram in candidate.shingles:
            overlaps.update(gram_index.get(gram, ()))
        for (name, position), intersection in overlaps.items():
            other = prepared_held_out[name][position]
            union = len(candidate.shingles) + len(other.shingles) - intersection
            exact = intersection / union if union else 0.0
            if exact > best_exact:
                best_exact = exact
                exact_pair = (name, other.row_id)

        best_containment = 0.0
        containment_pair: tuple[str, str] | None = None
        if candidate.token_count >= CONTAINMENT_MIN_TOKENS:
            candidate_overlaps: Counter[tuple[str, int]] = Counter()
            for gram in candidate.containment_grams:
                candidate_overlaps.update(containment_index.get(gram, ()))
            for (name, position), intersection in candidate_overlaps.items():
                other = prepared_held_out[name][position]
                if other.token_count < CONTAINMENT_MIN_TOKENS:
                    continue
                smaller = min(len(candidate.containment_grams), len(other.containment_grams))
                score = intersection / smaller if smaller else 0.0
                if score > best_containment:
                    best_containment = score
                    containment_pair = (name, other.row_id)

        reasons: list[str] = []
        if best_estimate >= LEAKAGE_JACCARD_THRESHOLD:
            reasons.append(
                f"minhash-estimated Jaccard {best_estimate:.4f} against "
                f"{_name_pair(estimated_pair)} reaches {LEAKAGE_JACCARD_THRESHOLD}"
            )
        if best_exact >= LEAKAGE_JACCARD_THRESHOLD:
            reasons.append(
                f"exact Jaccard {best_exact:.4f} against "
                f"{_name_pair(exact_pair)} reaches {LEAKAGE_JACCARD_THRESHOLD}"
            )
        if best_containment > LEAKAGE_CONTAINMENT_THRESHOLD:
            reasons.append(
                f"{CONTAINMENT_GRAM_SIZE}-gram containment {best_containment:.4f} against "
                f"{_name_pair(containment_pair)} exceeds {LEAKAGE_CONTAINMENT_THRESHOLD}"
            )
        findings.append(
            LeakageFinding(
                row_id=row_id,
                estimated_jaccard=best_estimate,
                estimated_dataset=estimated_pair[0] if estimated_pair else None,
                estimated_row_id=estimated_pair[1] if estimated_pair else None,
                exact_jaccard=best_exact,
                exact_dataset=exact_pair[0] if exact_pair else None,
                exact_row_id=exact_pair[1] if exact_pair else None,
                max_containment=best_containment,
                containment_dataset=containment_pair[0] if containment_pair else None,
                containment_row_id=containment_pair[1] if containment_pair else None,
                reasons=tuple(reasons),
            )
        )
    return findings


class Cluster(NamedTuple):
    cluster_id: int
    representative: str
    members: tuple[str, ...]


def _is_near_duplicate(left: _Row, right: _Row) -> bool:
    return (
        estimate_jaccard(left.signature, right.signature) >= CLUSTER_JACCARD_THRESHOLD
        or exact_jaccard(left.shingles, right.shingles) >= CLUSTER_JACCARD_THRESHOLD
    )


def _band_keys(signature: np.ndarray) -> list[bytes]:
    return [
        signature[band * LSH_ROWS : (band + 1) * LSH_ROWS].tobytes() + band.to_bytes(2, "big")
        for band in range(LSH_BANDS)
    ]


def assign_clusters(rows: Sequence[tuple[str, str]]) -> list[Cluster]:
    """Gates B and C. Cluster rows at ``CLUSTER_JACCARD_THRESHOLD`` and name each cluster.

    Candidate generation uses ``LSH_BANDS`` bands of ``LSH_ROWS`` rows, whose S-curve
    inflection sits near 0.71, below the 0.8 decision threshold; every generated pair is
    then verified against the full signature and the exact shingle sets, so banding only
    ever bounds the work, never the decision. Clustering is report-only, which is why an
    LSH prefilter is acceptable here and not in Gate A.

    Inside a bucket, rows are matched against cluster leaders rather than against every
    other member. All-pairs matching is quadratic in the size of a *true* cluster, and the
    corpora this gate exists for are exactly the ones with huge true clusters -- a bucket
    of 50k copies of one phrase would be 1.25 billion comparisons. Leader matching makes
    that bucket linear. The cost is that it is single-linkage only through the leader a
    row first matches, so two leaders that are each near a third row are not merged.
    """
    prepared = _prepare_all(rows)
    parent = list(range(len(prepared)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    buckets: dict[bytes, list[int]] = {}
    for index, row in enumerate(prepared):
        for key in _band_keys(row.signature):
            buckets.setdefault(key, []).append(index)

    for members in buckets.values():
        if len(members) < 2:
            continue
        leaders: list[int] = []
        for index in members:
            for leader in leaders:
                if find(index) == find(leader) or _is_near_duplicate(
                    prepared[index], prepared[leader]
                ):
                    union(index, leader)
                    break
            else:
                leaders.append(index)

    grouped: dict[int, list[int]] = {}
    for index in range(len(prepared)):
        grouped.setdefault(find(index), []).append(index)
    clusters: list[Cluster] = []
    for cluster_id, root in enumerate(sorted(grouped)):
        members = tuple(prepared[index].row_id for index in sorted(grouped[root]))
        clusters.append(Cluster(cluster_id=cluster_id, representative=members[0], members=members))
    return clusters


def build_decontamination_report(
    *,
    dataset: str,
    candidates: Sequence[tuple[str, str]],
    held_out: Mapping[str, Sequence[tuple[str, str]]],
    corpus: Sequence[tuple[str, str]],
) -> dict[str, object]:
    """Run all three gates and return the publishable decontamination artifact."""
    findings = measure_leakage(candidates, held_out)
    clusters = assign_clusters(corpus)
    cluster_of: dict[str, int] = {}
    for cluster in clusters:
        for member in cluster.members:
            cluster_of[member] = cluster.cluster_id
    histogram = Counter(len(cluster.members) for cluster in clusters)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "dataset": dataset,
        "parameters": {
            "character_shingle_size": CHARACTER_SHINGLE_SIZE,
            "cluster_jaccard_threshold": CLUSTER_JACCARD_THRESHOLD,
            "containment_gram_size": CONTAINMENT_GRAM_SIZE,
            "containment_min_tokens": CONTAINMENT_MIN_TOKENS,
            "leakage_containment_threshold": LEAKAGE_CONTAINMENT_THRESHOLD,
            "leakage_jaccard_threshold": LEAKAGE_JACCARD_THRESHOLD,
            "lsh_bands": LSH_BANDS,
            "lsh_rows": LSH_ROWS,
            "minhash_permutations": MINHASH_PERMUTATIONS,
            "minhash_seed": MINHASH_SEED,
            "segmentation_run_length": SEGMENTATION_RUN_LENGTH,
            "word_shingle_size": WORD_SHINGLE_SIZE,
        },
        "held_out_rows": {name: len(rows) for name, rows in sorted(held_out.items())},
        "corpus_rows": len(corpus),
        "candidate_rows": len(candidates),
        "rows": [
            {
                "cluster_id": cluster_of.get(finding.row_id),
                "containment_dataset": finding.containment_dataset,
                "containment_row_id": finding.containment_row_id,
                "id": finding.row_id,
                "max_containment": round(finding.max_containment, 6),
                "max_estimated_jaccard": round(finding.estimated_jaccard, 6),
                "max_exact_jaccard": round(finding.exact_jaccard, 6),
                "nearest_estimated_dataset": finding.estimated_dataset,
                "nearest_estimated_id": finding.estimated_row_id,
                "nearest_exact_dataset": finding.exact_dataset,
                "nearest_exact_id": finding.exact_row_id,
                "reasons": list(finding.reasons),
                "rejected": finding.rejected,
            }
            for finding in findings
        ],
        "rejected": [finding.row_id for finding in findings if finding.rejected],
        "clusters": [
            {
                "cluster_id": cluster.cluster_id,
                "members": list(cluster.members),
                "representative": cluster.representative,
                "size": len(cluster.members),
            }
            for cluster in clusters
            if len(cluster.members) > 1
        ],
        "cluster_size_histogram": {str(size): count for size, count in sorted(histogram.items())},
    }
