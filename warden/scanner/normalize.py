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
import re
import unicodedata
from urllib.parse import unquote

MAX_DECODE_DEPTH = 3
MAX_CANDIDATES = 12
MAX_TEXT_SIZE = 65536
MAX_DECODED_SEGMENTS_PER_TEXT = 8
MIN_DECODED_LENGTH = 8
MIN_PRINTABLE_RATIO = 0.9

# Provenance labels for derived candidates.
TRANSFORM_DECODED = "decoded"
TRANSFORM_UNICODE = "unicode"

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


def _is_plausible_text(decoded: str) -> bool:
    """Accept decoded bytes only when they read as real text, not noise."""
    if len(decoded) < MIN_DECODED_LENGTH:
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    if printable / len(decoded) < MIN_PRINTABLE_RATIO:
        return False
    letters = sum(1 for ch in decoded if ch.isalpha())
    return letters / len(decoded) >= 0.4


def _decode_bytes(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if _is_plausible_text(decoded) else None


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


def _decoded_segments(text: str) -> list[str]:
    """Decode every plausible encoded segment embedded in ``text``."""
    segments: list[str] = []

    def _add(candidate: str | None) -> bool:
        if candidate and candidate not in segments and candidate != text:
            segments.append(candidate)
        return len(segments) >= MAX_DECODED_SEGMENTS_PER_TEXT

    for match in _BASE64_TOKEN.finditer(text):
        if _add(_base64_decodings(match.group())):
            return segments

    for match in _HEX_RUN.finditer(text):
        run = match.group(1)
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        if _add(_decode_bytes(raw)):
            return segments

    for match in _X_ESCAPES.finditer(text):
        raw = bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9a-fA-F]{2})", match.group()))
        if _add(_decode_bytes(raw)):
            return segments

    if len(_PERCENT_ESCAPE.findall(text)) >= 3:
        unquoted = unquote(text, errors="replace")
        if unquoted != text and _is_plausible_text(unquoted):
            if _add(unquoted):
                return segments

    if _HTML_ENTITY.search(text):
        unescaped = html.unescape(text)
        if unescaped != text and _is_plausible_text(unescaped):
            if _add(unescaped):
                return segments

    return segments


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
    The original text is NOT included — callers always scan it separately.
    """
    if not text:
        return []
    text = text[:MAX_TEXT_SIZE]

    candidates: list[tuple[str, str]] = []
    seen: set[str] = {text}

    def _add(candidate: str, transform: str) -> None:
        candidate = candidate[:MAX_TEXT_SIZE]
        if candidate not in seen and len(candidates) < MAX_CANDIDATES:
            seen.add(candidate)
            candidates.append((candidate, transform))

    folded = fold_unicode(text)
    if folded != text:
        _add(folded, TRANSFORM_UNICODE)

    # Breadth-first layered decoding with a strict depth cap.
    frontier = [text] + ([folded] if folded != text else [])
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for current in frontier:
            if len(candidates) >= MAX_CANDIDATES:
                return candidates
            for decoded in _decoded_segments(current):
                _add(decoded, TRANSFORM_DECODED)
                decoded_folded = fold_unicode(decoded)
                if decoded_folded != decoded:
                    _add(decoded_folded, TRANSFORM_DECODED)
                next_frontier.append(decoded)
        if not next_frontier:
            break
        frontier = next_frontier

    return candidates
