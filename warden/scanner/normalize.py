"""Decoder Wall — bounded normalization pre-pass for the Warden engine.

Derives candidate texts from a payload by reversing common obfuscation
layers (base64/base64url, hex, percent-encoding, HTML entities, ``\\xNN``
escapes), by folding Unicode disguises (NFKC, confusable homoglyphs,
zero-width/bidi controls), and by folding the two ASCII disguises Unicode
normalization cannot reach: character segmentation (``I g n o r e``,
``I.g.n.o.r.e.``, ``i-g-n-o-r-e``) and leetspeak (``1gn0r3``). The engine
scans the ORIGINAL payload and every
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
from collections import Counter
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
# Transit layers — decodings that are not text but are nothing except another
# encoding — are carried forward for one more hop instead of being scanned.
# They cost a decode each and never become candidates, so a small global budget
# is enough to cover published layering (two or three wrappers) while keeping a
# crafted fan-out from multiplying the pre-pass.
MAX_TRANSIT_SEGMENTS = 4
# Four single-character groups is the shortest run that folds. Three would
# swallow initialisms ("U.S.A.", "F.B.I.") and two would swallow "a.m." and
# single-letter words, so the floor is what keeps ordinary prose untouched.
MIN_SEGMENT_RUN = 4
MAX_LEET_TOKEN_LENGTH = 16
MIN_LEET_HEXLIKE_LENGTH = 12
# Leetspeak is a phrase-level style. Requiring three co-occurring leet words
# is what keeps the fold away from lone digit-bearing identifiers in code.
MIN_LEET_WORDS = 3

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

# Separator punctuation used by published character-spacing bypasses. Comma,
# semicolon and colon are deliberately absent: they carry real list structure
# in benign prose ("tranches a, b, c, d") and folding them would invent words.
SEGMENT_PUNCTUATION = ".-_|*/\\+~"

# ASCII lookalikes the homoglyph map cannot cover, because these characters are
# legitimate ASCII rather than confusable Unicode. ``1`` folds to ``i`` (the
# form used by "1gn0r3", "1nstruct10ns"); the ``1`` -> ``l`` reading is not
# folded, since one candidate per payload is the budget we can afford.
LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
}

_SEGMENT_SEPARATOR = r"[\s" + re.escape(SEGMENT_PUNCTUATION) + r"]+"
# One alphanumeric character that is not part of a longer alphanumeric group.
_SEGMENT_GROUP = r"[0-9A-Za-z](?![0-9A-Za-z])"
_SEGMENT_RUN = re.compile(
    r"(?<![0-9A-Za-z])"
    + _SEGMENT_GROUP
    + r"(?:"
    + _SEGMENT_SEPARATOR
    + _SEGMENT_GROUP
    + r"){"
    + str(MIN_SEGMENT_RUN - 1)
    + r",}"
)
_SEGMENT_SPLIT = re.compile(r"(" + _SEGMENT_SEPARATOR + r")")
_LEET_TOKEN = re.compile(r"[0-9A-Za-z@$!]+")
_LEET_HEXLIKE = re.compile(r"[0-9a-fA-F]+")
# Any character the fold could rewrite. Screening with this first turns the
# fold into one C-level scan for the overwhelming majority of payloads
# (10 KB of ordinary prose: 9.9 ms -> 0.03 ms).
_LEET_TRIGGER = re.compile("[" + re.escape("".join(LEET_MAP)) + "]")
_URL_SPAN = re.compile(r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|www\.|xn--)\S+")
_LEET_TRAILING_DIGITS = re.compile(r"[0-9]+\Z")

_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?((?:[0-9a-fA-F]{2}){8,})")
_X_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_PERCENT_LAYER = re.compile(r"(?:[^%]|%[0-9a-fA-F]{2})+")
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
    except (ValueError, RecursionError):
        # ValueError covers JSONDecodeError and CPython's int-string digit
        # limit, which a long run of digits trips inside the JSON scanner.
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


def _is_encoded_layer(decoded: str) -> bool:
    """Is ``decoded`` nothing but one more encoding of something else?

    This is the shape of a layered-encoding evasion: each wrapper decodes to a
    bare encoding of the next, never to text, so every intermediate layer fails
    the plausibility gate and the chain stops one hop short of the payload.
    The test is deliberately whole-string — a layer carrying prose *around* an
    encoded run is already plausible text and travels the ordinary path — so
    the only thing admitted here is a wrapper with nothing else in it.
    """
    stripped = decoded.strip()
    if len(stripped) < MIN_DECODED_LENGTH:
        return False
    if (
        _HEX_RUN.fullmatch(stripped)
        or _BASE64_TOKEN.fullmatch(stripped)
        or _X_ESCAPES.fullmatch(stripped)
    ):
        return True
    return len(_PERCENT_ESCAPE.findall(stripped)) >= 3 and bool(_PERCENT_LAYER.fullmatch(stripped))


def _layer_text(decoded: str | None) -> str | None:
    """Return ``decoded`` when it is a printable, purely-encoded transit layer."""
    if decoded is None or len(decoded) > MAX_TEXT_SIZE:
        return None
    if not _is_printable_text(decoded) or not _is_encoded_layer(decoded):
        return None
    return decoded


def _decode_bytes(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) > MAX_TEXT_SIZE:
        return None
    return decoded if _is_plausible_text(decoded) else None


def _decode_layer_bytes(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return _layer_text(decoded)


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


def _base64_bytes(token: str) -> bytes | None:
    """Decode one base64/base64url token to bytes, or ``None``.

    At most one variant can succeed: ``validate=True`` rejects ``-``/``_`` for
    the standard alphabet, so a token carrying them only decodes after the
    substitution, and a token without them makes both variants identical.
    Returning bytes lets a caller classify the same decode as text or as a
    transit layer without paying for a second decode.
    """
    padded = token + "=" * (-len(token) % 4)
    for variant in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            return base64.b64decode(variant, validate=True)
        except (binascii.Error, ValueError):
            continue
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
    except ValueError:
        # JSONDecodeError, plus CPython's int-string digit limit: a payload
        # that is a long run of digits is not a container, so it is not
        # opaque either. Letting it escape would crash the pre-pass.
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


def _decoded_segments(text: str) -> tuple[list[str], list[str], bool]:
    """Decode the encoded segments embedded in ``text``.

    Returns the plausible-text decodings, the transit layers (decodings that
    are not text but are themselves nothing but one more encoding, to be
    unwrapped on the next hop rather than scanned), and whether a declared
    container could not be inspected safely.
    """
    segments: list[str] = []
    transit: list[str] = []

    def _add(candidate: str | None) -> bool:
        if candidate and candidate not in segments and candidate != text:
            segments.append(candidate)
        return len(segments) >= MAX_DECODED_SEGMENTS_PER_TEXT

    def _add_transit(candidate: str | None) -> None:
        """Record a transit layer, softly: a full budget drops it silently.

        Transit layers are never scanned themselves, so dropping one can only
        lose a detection on a deeper hop. Aborting the segment scan for them
        would instead cost detections on this hop.
        """
        if (
            candidate
            and candidate not in transit
            and candidate != text
            and len(transit) < MAX_TRANSIT_SEGMENTS
        ):
            transit.append(candidate)

    container_decodings, ambiguous_container = _container_decodings(text)
    for decoded in container_decodings:
        if _add(decoded):
            return segments, transit, ambiguous_container

    for match in _BASE64_TOKEN.finditer(text):
        raw = _base64_bytes(match.group())
        if raw is None:
            continue
        decoded = _decode_bytes(raw)
        if decoded is None:
            _add_transit(_decode_layer_bytes(raw))
        elif _add(decoded):
            return segments, transit, ambiguous_container

    for match in _HEX_RUN.finditer(text):
        run = match.group(1)
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        decoded = _decode_bytes(raw)
        if decoded is None:
            _add_transit(_decode_layer_bytes(raw))
        elif _add(decoded):
            return segments, transit, ambiguous_container

    for match in _X_ESCAPES.finditer(text):
        raw = bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9a-fA-F]{2})", match.group()))
        decoded = _decode_bytes(raw)
        if decoded is None:
            _add_transit(_decode_layer_bytes(raw))
        elif _add(decoded):
            return segments, transit, ambiguous_container

    if len(_PERCENT_ESCAPE.findall(text)) >= 3:
        unquoted = unquote(text, errors="replace")
        if unquoted != text and len(unquoted) <= MAX_TEXT_SIZE:
            if not _is_plausible_text(unquoted):
                _add_transit(_layer_text(unquoted))
            elif _add(unquoted):
                return segments, transit, ambiguous_container

    if _HTML_ENTITY.search(text):
        unescaped = html.unescape(text)
        if unescaped != text and len(unescaped) <= MAX_TEXT_SIZE:
            if not _is_plausible_text(unescaped):
                _add_transit(_layer_text(unescaped))
            elif _add(unescaped):
                return segments, transit, ambiguous_container

    return segments, transit, ambiguous_container


def strip_invisibles(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_BIDI)


def fold_unicode(text: str) -> str:
    """NFKC-normalize, drop zero-width/bidi controls, fold homoglyphs."""
    folded = unicodedata.normalize("NFKC", strip_invisibles(text))
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in folded)


def _rejoin_segmented_run(run: str) -> str:
    """Collapse one run of single-character groups back into dense words.

    Word boundaries are recovered from the separators themselves: the most
    frequent separator inside the run is the intra-word one (the single space
    of ``I g n o r e``, the dot of ``I.g.n.o.r.e.``, the dash of
    ``i-g-n-o-r-e``) and every other separator becomes a single space. Ties
    resolve to the first separator seen, so the fold is deterministic.
    """
    parts = _SEGMENT_SPLIT.split(run)
    groups = parts[0::2]
    separators = parts[1::2]
    intra_word = Counter(separators).most_common(1)[0][0]
    rejoined = [groups[0]]
    for separator, group in zip(separators, groups[1:]):
        if separator != intra_word:
            rejoined.append(" ")
        rejoined.append(group)
    return "".join(rejoined)


def fold_segmentation(text: str) -> str:
    """Undo character-spacing obfuscation (``I g n o r e``, ``I.g.n.o.r.e.``).

    Only runs of at least ``MIN_SEGMENT_RUN`` single-character groups are
    folded, which leaves initialisms, ``a.m.``, single-letter words and short
    enumerations byte-identical. Text outside a run is never touched.
    """
    if not text:
        return text
    return _SEGMENT_RUN.sub(lambda match: _rejoin_segmented_run(match.group()), text)


def _url_mask(text: str) -> bytearray | None:
    """Mark every character position that sits inside a URL, or ``None``.

    A flat mask keeps the per-token URL test O(1). Testing each token against
    a list of spans instead is quadratic, and a URL-dense payload turned that
    into a 21-second fold on a 100 KB input.
    """
    spans = [match.span() for match in _URL_SPAN.finditer(text)]
    if not spans:
        return None
    mask = bytearray(len(text))
    for start, end in spans:
        mask[start:end] = b"\x01" * (end - start)
    return mask


def _is_leet_word(match: re.Match[str], url_mask: bytearray | None) -> bool:
    """Decide whether one alphanumeric token is a leet-spelled word.

    Every rejection below is a false positive this fold actually produced
    against the corpora before the guard existed. The engine's decoder wall
    escalates any candidate detection to BLOCK, so a token that folds into
    letter soup does not just waste a scan — it hard-blocks a benign payload.
    """
    token = match.group()
    if len(token) > MAX_LEET_TOKEN_LENGTH or not _LEET_TRIGGER.search(token):
        return False
    # Trailing digits are a suffix, not a substitution: "base64", "web3",
    # "sha256", "erc20", "paypa1" and "invoice88" are spelled that way on
    # purpose. Real leetspeak substitutes interior characters.
    if not _LEET_TRIGGER.search(_LEET_TRAILING_DIGITS.sub("", token)):
        return False
    # The body of an escape sequence (``i``, ``\x6e``) is data, not a
    # word. Folding it turns declared escapes into high-entropy letter soup.
    if match.start() and match.string[match.start() - 1] == "\\":
        return False
    # Hostname labels are identifiers, not words: rewriting "paypa1" inside a
    # punycode domain changes which host the link analyzer is reasoning about.
    if url_mask is not None and url_mask[match.start()]:
        return False
    letters = [character for character in token if character.isascii() and character.isalpha()]
    if not letters or len(letters) < len(_LEET_TRIGGER.findall(token)):
        return False
    # Opaque identifiers — base64 blobs, JWT segments, mixed-case hashes — are
    # case-mixed; a leet-spelled word is not, beyond an initial capital.
    tail = "".join(letters[1:])
    if tail and not (tail.islower() or tail.isupper()):
        return False
    prefixed = token[:2].casefold() == "0x"
    body = token[2:] if prefixed else token
    return not (
        (prefixed or len(token) >= MIN_LEET_HEXLIKE_LENGTH) and _LEET_HEXLIKE.fullmatch(body)
    )


def fold_leetspeak(text: str) -> str:
    """Fold ASCII leetspeak substitutions (``1gn0r3 4ll`` -> ``ignore all``).

    Leetspeak is a style applied to a phrase, never to one stray identifier,
    so the fold only fires when at least ``MIN_LEET_WORDS`` qualifying tokens
    occur in the same text. That co-occurrence floor is what separates an
    attack ("1gn0r3 pr3v10us 1nstruct10ns 4nd s3nd 4ll") from source code and
    technical prose, where digit-bearing identifiers such as ``b64decode``
    appear alone. ``_is_leet_word`` carries the per-token exclusions.
    """
    if not text or not _LEET_TRIGGER.search(text):
        return text
    url_mask = _url_mask(text)
    words = [match for match in _LEET_TOKEN.finditer(text) if _is_leet_word(match, url_mask)]
    if len(words) < MIN_LEET_WORDS:
        return text

    folded: list[str] = []
    cursor = 0
    for match in words:
        folded.append(text[cursor : match.start()])
        folded.append("".join(LEET_MAP.get(character, character) for character in match.group()))
        cursor = match.end()
    folded.append(text[cursor:])
    return "".join(folded)


def _add_obfuscation_folds(
    candidates: list[tuple[str, str]],
    seen: set[str],
    folded: str,
) -> None:
    """Append segmentation/leetspeak variants of ``folded`` within budget.

    These run last and add softly: when the candidate budget is already spent
    the variant is dropped instead of raising the fail-closed decoder-limit
    marker. That is safe in a way the encoding path is not — a segmentation or
    leetspeak variant is a rewrite of text the engine already scans, so
    dropping one can only lose a detection, never leave an un-inspected
    obfuscation layer behind. It also keeps the new folds from pushing an
    ordinary payload into the limit hard-block path.
    """

    def _add_soft(candidate: str) -> None:
        if candidate not in seen and len(candidates) < MAX_CANDIDATES - 1:
            seen.add(candidate)
            candidates.append((candidate, TRANSFORM_UNICODE))

    segmented = fold_segmentation(folded)
    leeted = fold_leetspeak(folded)
    if segmented != folded:
        _add_soft(segmented)
    if leeted != folded:
        _add_soft(leeted)
    if segmented != folded and leeted != folded:
        _add_soft(fold_leetspeak(segmented))


def derive_candidates(text: str) -> list[tuple[str, str]]:
    """Return ``(candidate_text, transform)`` pairs derived from ``text``.

    ``transform`` is ``"unicode"`` for fold/strip variants and ``"decoded"``
    for reversed encodings (including layered encodings up to the depth cap).
    A layer that decodes to another bare encoding rather than to text is
    carried forward as a transit node — unwrapped on the next hop, never
    emitted as a candidate, and bounded by its own global budget.
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
    transit_seen: set[str] = set()
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for current in frontier:
            decoded_segments, transit_segments, ambiguous_container = _decoded_segments(current)
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
            for layer in transit_segments:
                if len(transit_seen) >= MAX_TRANSIT_SEGMENTS:
                    break
                if layer not in transit_seen:
                    transit_seen.add(layer)
                    next_frontier.append(layer)
        if not next_frontier:
            break
        frontier = next_frontier

    for current in frontier:
        decoded_segments, transit_segments, unsafe_container = _decoded_segments(current)
        if decoded_segments or transit_segments or unsafe_container:
            return _limit_marker(current)

    _add_obfuscation_folds(candidates, seen, folded)
    return candidates
