"""Pinnable append-only history for externally published APA log checkpoints."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Sequence
from typing import cast

from warden import protection
from warden.badges import b64u_decode, b64u_encode

GENESIS_HISTORY_HASH = "0" * 64
_HISTORY_FIELDS = {"schema_version", "status", "history_head_hash", "anchors"}
_ANCHOR_FIELDS = {"anchor_seq", "previous_anchor_hash", "checkpoint"}
_CHECKPOINT_FIELDS = {
    "spec_version",
    "issuer",
    "seq",
    "head_hash",
    "issued_at",
    "issuer_sig",
}


class AnchorHistoryError(ValueError):
    """The public anchor history failed structural or cryptographic validation."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _is_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _anchor_hash(anchor: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(anchor).encode("utf-8")).hexdigest()


def _validate_checkpoint_shape(checkpoint: object) -> dict[str, object]:
    if not isinstance(checkpoint, dict) or set(checkpoint) != _CHECKPOINT_FIELDS:
        raise AnchorHistoryError("anchor checkpoint must be an exact six-field object")
    if checkpoint.get("spec_version") != "apa-log/0.1":
        raise AnchorHistoryError("anchor checkpoint version is unsupported")
    if checkpoint.get("issuer") != "warden":
        raise AnchorHistoryError("anchor checkpoint issuer is invalid")
    sequence = checkpoint.get("seq")
    issued_at = checkpoint.get("issued_at")
    if type(sequence) is not int or not 0 <= sequence <= protection.MAX_SAFE_UNIX_SECONDS:
        raise AnchorHistoryError("anchor checkpoint sequence is invalid")
    if type(issued_at) is not int or not 0 <= issued_at <= protection.MAX_SAFE_UNIX_SECONDS:
        raise AnchorHistoryError("anchor checkpoint timestamp is invalid")
    if not _is_hash(checkpoint.get("head_hash")):
        raise AnchorHistoryError("anchor checkpoint head hash is invalid")
    signature = checkpoint.get("issuer_sig")
    if not isinstance(signature, str) or not signature.startswith("sig:"):
        raise AnchorHistoryError("anchor checkpoint signature is malformed")
    try:
        decoded_signature = b64u_decode(signature)
    except ValueError as exc:
        raise AnchorHistoryError("anchor checkpoint signature is malformed") from exc
    if len(decoded_signature) != 64 or b64u_encode(decoded_signature, "sig") != signature:
        raise AnchorHistoryError("anchor checkpoint signature is malformed")
    return checkpoint


def _checkpoint_matches_log(
    checkpoint: dict[str, object],
    entries: Sequence[dict[str, object]],
) -> bool:
    sequence = int(checkpoint["seq"])
    if sequence > len(entries):
        return False
    previous_hash = GENESIS_HISTORY_HASH
    for expected_sequence, entry in enumerate(entries[:sequence], start=1):
        if (
            not isinstance(entry, dict)
            or entry.get("seq") != expected_sequence
            or entry.get("prev_hash") != previous_hash
        ):
            return False
        previous_hash = hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()
    return checkpoint.get("head_hash") == previous_hash


def empty_anchor_history() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "unpublished",
        "history_head_hash": GENESIS_HISTORY_HASH,
        "anchors": [],
    }


def validate_anchor_history(
    document: object,
    entries: Sequence[dict[str, object]],
    *,
    pinned_history_head: str | None = None,
    verify_signatures: bool = True,
) -> tuple[str, ...]:
    if not isinstance(document, dict) or set(document) != _HISTORY_FIELDS:
        raise AnchorHistoryError("anchor history must be an exact four-field object")
    if document.get("schema_version") != 1:
        raise AnchorHistoryError("anchor history schema is unsupported")
    anchors = document.get("anchors")
    if not isinstance(anchors, list):
        raise AnchorHistoryError("anchor history anchors must be an array")
    if document.get("status") not in {"unpublished", "published"}:
        raise AnchorHistoryError("anchor history status is invalid")

    previous_anchor_hash = GENESIS_HISTORY_HASH
    previous_checkpoint_seq = -1
    previous_issued_at = -1
    observed_hashes: list[str] = []
    for expected_sequence, anchor in enumerate(anchors, start=1):
        if not isinstance(anchor, dict) or set(anchor) != _ANCHOR_FIELDS:
            raise AnchorHistoryError("anchor history entry has unexpected fields")
        if anchor.get("anchor_seq") != expected_sequence:
            raise AnchorHistoryError("anchor history sequence is not contiguous")
        if anchor.get("previous_anchor_hash") != previous_anchor_hash:
            raise AnchorHistoryError("anchor history hash chain is broken")
        checkpoint = _validate_checkpoint_shape(anchor.get("checkpoint"))
        checkpoint_seq = int(checkpoint["seq"])
        issued_at = int(checkpoint["issued_at"])
        if checkpoint_seq <= previous_checkpoint_seq:
            raise AnchorHistoryError("anchor checkpoint sequence must increase")
        if issued_at < previous_issued_at:
            raise AnchorHistoryError("anchor checkpoint timestamps must not decrease")
        if verify_signatures and not protection.verify_log_checkpoint(checkpoint):
            raise AnchorHistoryError("anchor checkpoint signature is invalid")
        if not _checkpoint_matches_log(checkpoint, entries):
            raise AnchorHistoryError("anchor checkpoint does not match the supplied log prefix")
        previous_checkpoint_seq = checkpoint_seq
        previous_issued_at = issued_at
        previous_anchor_hash = _anchor_hash(anchor)
        observed_hashes.append(previous_anchor_hash)

    expected_status = "published" if anchors else "unpublished"
    if document.get("status") != expected_status:
        raise AnchorHistoryError("anchor history status does not match its entries")
    if document.get("history_head_hash") != previous_anchor_hash:
        raise AnchorHistoryError("anchor history head hash does not match its entries")
    if pinned_history_head is not None:
        if not _is_hash(pinned_history_head):
            raise AnchorHistoryError("pinned history head must be lowercase SHA-256 hex")
        if pinned_history_head not in observed_hashes:
            raise AnchorHistoryError("pinned history head is absent from the verified chain")
    return tuple(observed_hashes)


def append_checkpoint(
    document: object,
    checkpoint: dict[str, object],
    entries: Sequence[dict[str, object]],
    *,
    pinned_history_head: str | None = None,
    verify_signatures: bool = True,
) -> dict[str, object]:
    validate_anchor_history(
        document,
        entries,
        pinned_history_head=pinned_history_head,
        verify_signatures=verify_signatures,
    )
    validated_document = cast(dict[str, object], document)
    anchors = cast(list[dict[str, object]], validated_document["anchors"])
    if anchors and anchors[-1].get("checkpoint") == checkpoint:
        return copy.deepcopy(document)

    candidate = cast(dict[str, object], copy.deepcopy(document))
    candidate_anchors = cast(list[dict[str, object]], candidate["anchors"])
    previous_hash = str(candidate["history_head_hash"])
    candidate_anchors.append(
        {
            "anchor_seq": len(candidate_anchors) + 1,
            "previous_anchor_hash": previous_hash,
            "checkpoint": copy.deepcopy(checkpoint),
        }
    )
    candidate["status"] = "published"
    candidate["history_head_hash"] = _anchor_hash(candidate_anchors[-1])
    validate_anchor_history(
        candidate,
        entries,
        pinned_history_head=pinned_history_head,
        verify_signatures=verify_signatures,
    )
    return candidate
