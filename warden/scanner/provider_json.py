"""Strict JSON decoding for untrusted model-provider responses."""

import json


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("provider response contains duplicate object keys")
        parsed[key] = value
    return parsed


def _reject_non_finite_number(_value: str) -> object:
    raise ValueError("provider response contains a non-finite number")


def load_provider_json(document: str | bytes) -> object:
    """Decode one strict JSON document received from a model provider."""
    try:
        return json.loads(
            document,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("provider response must be valid JSON") from exc
