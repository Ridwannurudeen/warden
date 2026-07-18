"""Decoder Wall — bounded normalization pre-pass for the Warden engine.

Derives candidate texts from a payload by reversing common obfuscation
layers (base64/base64url, hex, percent-encoding, HTML entities, ``\\xNN``
escapes) and by folding Unicode disguises (NFKC, confusable homoglyphs,
zero-width/bidi controls). The engine scans the ORIGINAL payload and every
derived candidate and unions the findings, so normalization can only ADD
detections — it can never suppress a verdict that fires on the raw text.

Everything here is pure Python, offline, and strictly bounded: a hard
recursion depth cap, a per-text size cap, and a total candidate cap keep a
crafted input from turning the pre-pass into a decompression bomb.
"""

import base64
import binascii
import html
import json
import re
import unicodedata
from urllib.parse import unquote

MAX_DECODE_DEPTH = 3
MAX_CANDIDATES = 12
MAX_CONTAINER_INPUT_SIZE = 100_000
MAX_TEXT_SIZE = MAX_CONTAINER_INPUT_SIZE
MAX_DECODED_SEGMENTS_PER_TEXT = 12
MAX_CONTAINER_DEPTH = 64
MAX_CONTAINER_NODES = 4096
MIN_DECODED_LENGTH = 8
MIN_PRINTABLE_RATIO = 0.9
PLAUSIBLE_TEXT_WINDOW = 64

# Provenance labels for derived candidates.
TRANSFORM_DECODED = "decoded"
TRANSFORM_UNICODE = "unicode"
TRANSFORM_AMBIGUOUS_CONTAINER = "ambiguous_container"
TRANSFORM_UNSAFE_CONTAINER = "unsafe_container"
TRANSFORM_DECODER_LIMIT = "decoder_limit"

ZERO_WIDTH_BIDI = frozenset("​‌‍‎‏⁠⁡⁢⁣﻿‪‫‬‭‮")

# Focused confusables fold: Cyrillic/Greek look-alikes mapped to the Latin
# letters they imitate (TR39-style skeleton, offline subset). Only characters
# that are visually near-identical to ASCII are folded, so ordinary Cyrillic
# or Greek prose is left alone unless it is masquerading as Latin keywords.
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "г": "r",
    # Cyrillic uppercase
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "І": "I",
    "Ј": "J",
    "Ѕ": "S",
    "Ү": "Y",
    # Greek lowercase
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ω": "w",
    "σ": "s",
    "η": "n",
    "μ": "u",
    # Greek uppercase
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}

_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}){8,})")
_X_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_ENTITY = re.compile(r"&(?:#\d{2,6};|#x[0-9a-fA-F]{2,6};|[a-zA-Z]{2,10};)")
_CONTAINER_ENCODING_KEYS = frozenset({"encoding", "codec"})
_CONTAINER_VALUE_KEYS = frozenset({"blob", "chunks", "content", "data", "payload", "value"})
_CONTAINER_SEMANTIC_KEYS = _CONTAINER_ENCODING_KEYS | _CONTAINER_VALUE_KEYS


class _AmbiguousContainerError(ValueError):
    pass


def _reject_ambiguous_container_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    parsed: dict[str, object] = {}
    semantic_keys: set[str] = set()
    encoding_key: str | None = None
    for key, value in pairs:
        normalized_key = key.casefold()
        if normalized_key in _CONTAINER_SEMANTIC_KEYS:
            if normalized_key in semantic_keys:
                raise _AmbiguousContainerError
            if normalized_key in _CONTAINER_ENCODING_KEYS:
                if encoding_key is not None:
                    raise _AmbiguousContainerError
                encoding_key = normalized_key
            semantic_keys.add(normalized_key)
        parsed[key] = value
    return parsed


def _has_duplicate_semantic_keys(text: str) -> bool:
    try:
        json.loads(text, object_pairs_hook=_reject_ambiguous_container_keys)
    except _AmbiguousContainerError:
        return True
    except (json.JSONDecodeError, RecursionError):
        return False
    return False


def _is_printable_text(decoded: str) -> bool:
    if len(decoded) < MIN_DECODED_LENGTH:
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    return printable / len(decoded) >= MIN_PRINTABLE_RATIO


def _is_plausible_text(decoded: str) -> bool:
    """Accept printable output with at least one bounded text-like window."""
    if not _is_printable_text(decoded):
        return False
    step = PLAUSIBLE_TEXT_WINDOW // 2
    for start in range(0, len(decoded), step):
        window = decoded[start : start + PLAUSIBLE_TEXT_WINDOW]
        letters = sum(1 for ch in window if ch.isalpha())
        if letters / len(window) >= 0.4:
            return True
    return False


def _decode_bytes(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) > MAX_TEXT_SIZE:
        return None
    return decoded if _is_plausible_text(decoded) else None


def _decode_explicit_bytes(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if _is_explicit_text(decoded) else None


def _is_explicit_text(decoded: str) -> bool:
    if not decoded or len(decoded) > MAX_TEXT_SIZE:
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    return printable / len(decoded) >= MIN_PRINTABLE_RATIO


def _base64_decodings(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    for variant in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(variant, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _decode_bytes(raw)
        if decoded is not None:
            return decoded
    return None


def _explicit_base64_decoding(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    for variant in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(variant, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _decode_explicit_bytes(raw)
        if decoded is not None:
            return decoded
    return None


def _decode_container_value(encoding: str, value: object) -> tuple[str | None, bool]:
    normalized_encoding = encoding.casefold().replace("_", "").replace("-", "")
    if normalized_encoding not in {
        "b64",
        "base64",
        "base64url",
        "hex",
        "hexadecimal",
        "percent",
        "url",
        "urlencoded",
        "percentencoded",
        "html",
        "htmlentities",
        "xescape",
        "hexescape",
    }:
        return None, True

    if isinstance(value, str):
        encoded = value
    elif isinstance(value, list) and all(isinstance(chunk, str) for chunk in value):
        if sum(len(chunk) for chunk in value) > MAX_TEXT_SIZE:
            return None, True
        encoded = "".join(value)
    else:
        return None, True

    if not encoded or len(encoded) > MAX_TEXT_SIZE:
        return None, True

    if normalized_encoding in {"b64", "base64", "base64url"}:
        decoded = _explicit_base64_decoding(encoded)
        return decoded, decoded is None
    if normalized_encoding in {"hex", "hexadecimal"}:
        normalized_hex = encoded.removeprefix("0x")
        if len(normalized_hex) % 2:
            return None, True
        try:
            decoded = _decode_explicit_bytes(bytes.fromhex(normalized_hex))
            return decoded, decoded is None
        except ValueError:
            return None, True
    if normalized_encoding in {"percent", "url", "urlencoded", "percentencoded"}:
        if not _PERCENT_ESCAPE.search(encoded) or not re.fullmatch(
            r"(?:[^%]|%[0-9a-fA-F]{2})+", encoded
        ):
            return None, True
        decoded = unquote(encoded, errors="replace")
        candidate = decoded if decoded != encoded and _is_explicit_text(decoded) else None
        return candidate, candidate is None
    if normalized_encoding in {"html", "htmlentities"}:
        decoded = html.unescape(encoded)
        candidate = decoded if decoded != encoded and _is_explicit_text(decoded) else None
        return candidate, candidate is None
    if normalized_encoding in {"xescape", "hexescape"} and _X_ESCAPES.fullmatch(encoded):
        raw = bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9a-fA-F]{2})", encoded))
        decoded = _decode_explicit_bytes(raw)
        return decoded, decoded is None
    return None, True


def _has_explicit_encoded_container(node: object) -> bool:
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            keys = {str(key).casefold() for key in current}
            if keys & _CONTAINER_ENCODING_KEYS and keys & _CONTAINER_VALUE_KEYS:
                return True
            pending.extend(value for value in current.values() if isinstance(value, (dict, list)))
        elif isinstance(current, list):
            pending.extend(value for value in current if isinstance(value, (dict, list)))
    return False


def _container_decodings(text: str) -> tuple[list[str], bool]:
    try:
        document = json.loads(text, object_pairs_hook=_reject_ambiguous_container_keys)
    except _AmbiguousContainerError:
        return [], True
    except RecursionError:
        return [], True
    except json.JSONDecodeError:
        return [], False

    decoded_values: list[str] = []
    pending: list[tuple[object, int]] = [(document, 0)]
    visited = 0
    while pending:
        if visited >= MAX_CONTAINER_NODES:
            return decoded_values, any(
                _has_explicit_encoded_container(node) for node, _depth in pending
            )
        node, depth = pending.pop()
        visited += 1
        if depth > MAX_CONTAINER_DEPTH:
            uninspected = [node, *(item for item, _item_depth in pending)]
            return decoded_values, any(
                _has_explicit_encoded_container(item) for item in uninspected
            )
        if isinstance(node, dict):
            normalized_items = {str(key).casefold(): value for key, value in node.items()}
            encoding_values = [
                value for key, value in normalized_items.items() if key in _CONTAINER_ENCODING_KEYS
            ]
            opaque_entries = [
                (key, value)
                for key, value in normalized_items.items()
                if key in _CONTAINER_VALUE_KEYS
            ]
            opaque_values: set[str] = set()
            if encoding_values and opaque_entries:
                encoding = encoding_values[0]
                if not isinstance(encoding, str):
                    return decoded_values, True
                for key, value in opaque_entries:
                    if isinstance(value, str) or (
                        isinstance(value, list) and all(isinstance(chunk, str) for chunk in value)
                    ):
                        opaque_values.add(key)
                    decoded, invalid_structure = _decode_container_value(encoding, value)
                    if invalid_structure:
                        return decoded_values, True
                    if decoded is not None and decoded not in decoded_values:
                        if len(decoded_values) >= MAX_DECODED_SEGMENTS_PER_TEXT:
                            return decoded_values, True
                        decoded_values.append(decoded)
            children = [
                value
                for key, value in normalized_items.items()
                if key not in opaque_values and isinstance(value, (dict, list))
            ]
            if visited + len(pending) + len(children) > MAX_CONTAINER_NODES:
                uninspected = [*children, *(item for item, _item_depth in pending)]
                return decoded_values, any(
                    _has_explicit_encoded_container(item) for item in uninspected
                )
            pending.extend((value, depth + 1) for value in children)
        elif isinstance(node, list):
            children = [value for value in node if isinstance(value, (dict, list))]
            if visited + len(pending) + len(children) > MAX_CONTAINER_NODES:
                uninspected = [*children, *(item for item, _item_depth in pending)]
                return decoded_values, any(
                    _has_explicit_encoded_container(item) for item in uninspected
                )
            pending.extend((value, depth + 1) for value in children)
    return decoded_values, False


def _decoded_segments(text: str) -> tuple[list[str], bool]:
    """Decode every plausible encoded segment embedded in ``text``."""
    segments: list[str] = []

    def _add(candidate: str | None) -> bool:
        if candidate and candidate not in segments and candidate != text:
            segments.append(candidate)
        return len(segments) >= MAX_DECODED_SEGMENTS_PER_TEXT

    container_decodings, ambiguous_container = _container_decodings(text)
    for decoded in container_decodings:
        if _add(decoded):
            return segments, ambiguous_container

    for match in _BASE64_TOKEN.finditer(text):
        if _add(_base64_decodings(match.group())):
            return segments, ambiguous_container

    for match in _HEX_RUN.finditer(text):
        run = match.group(1)
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        if _add(_decode_bytes(raw)):
            return segments, ambiguous_container

    for match in _X_ESCAPES.finditer(text):
        raw = bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9a-fA-F]{2})", match.group()))
        if _add(_decode_bytes(raw)):
            return segments, ambiguous_container

    if len(_PERCENT_ESCAPE.findall(text)) >= 3:
        unquoted = unquote(text, errors="replace")
        if unquoted != text and len(unquoted) <= MAX_TEXT_SIZE and _is_plausible_text(unquoted):
            if _add(unquoted):
                return segments, ambiguous_container

    if _HTML_ENTITY.search(text):
        unescaped = html.unescape(text)
        if unescaped != text and len(unescaped) <= MAX_TEXT_SIZE and _is_plausible_text(unescaped):
            if _add(unescaped):
                return segments, ambiguous_container

    return segments, ambiguous_container


def strip_invisibles(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_BIDI)


def fold_unicode(text: str) -> str:
    """NFKC-normalize, drop zero-width/bidi controls, fold homoglyphs."""
    folded = unicodedata.normalize("NFKC", strip_invisibles(text))
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in folded)


def derive_candidates(text: str) -> list[tuple[str, str]]:
    """Return ``(candidate_text, transform)`` pairs derived from ``text``.

    ``transform`` is ``"unicode"`` for fold/strip variants and ``"decoded"``
    for reversed encodings (including layered encodings up to the depth cap).
    The original text is included only as a fail-closed marker when semantic
    JSON keys collide or a declared encoding cannot be inspected safely.
    """
    if not text:
        return []
    text = text[:MAX_CONTAINER_INPUT_SIZE]

    candidates: list[tuple[str, str]] = []
    seen: set[str] = {text}

    def _add(candidate: str, transform: str) -> bool:
        if candidate not in seen and len(candidates) < MAX_CANDIDATES - 1:
            seen.add(candidate)
            candidates.append((candidate, transform))
            return True
        return candidate in seen

    def _limit_marker(source: str) -> list[tuple[str, str]]:
        candidates.append((source[:MAX_TEXT_SIZE], TRANSFORM_DECODER_LIMIT))
        return candidates

    folded = fold_unicode(text)
    if folded != text:
        if not _add(folded, TRANSFORM_UNICODE):
            return _limit_marker(text)

    # Breadth-first layered decoding with a strict depth cap.
    frontier = [text] + ([folded] if folded != text else [])
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for current in frontier:
            decoded_segments, ambiguous_container = _decoded_segments(current)
            if ambiguous_container:
                transform = (
                    TRANSFORM_AMBIGUOUS_CONTAINER
                    if _has_duplicate_semantic_keys(current)
                    else TRANSFORM_UNSAFE_CONTAINER
                )
                candidates.append((current[:MAX_TEXT_SIZE], transform))
                return candidates
            for decoded in decoded_segments:
                if not _add(decoded, TRANSFORM_DECODED):
                    return _limit_marker(current)
                decoded_folded = fold_unicode(decoded)
                if decoded_folded != decoded:
                    if not _add(decoded_folded, TRANSFORM_DECODED):
                        return _limit_marker(current)
                next_frontier.append(decoded)
        if not next_frontier:
            break
        frontier = next_frontier

    for current in frontier:
        decoded_segments, unsafe_container = _decoded_segments(current)
        if decoded_segments or unsafe_container:
            return _limit_marker(current)

    return candidates
