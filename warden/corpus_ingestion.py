"""Offline ingestion of explicitly reviewed, allowlisted corpus records."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote
from uuid import uuid4

from warden.core.verdict import ReasonCode
from warden.dataset_promotion import (
    canonical_dataset_payload,
    promote_reviewed_training_batch,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST_PATH = ROOT / "spec" / "corpus-source-allowlist-v1.json"
DEFAULT_MANIFEST_PATH = ROOT / "corpus" / "license-manifest.json"
DEFAULT_TRAINING_ATTACKS_PATH = ROOT / "corpus" / "attacks.jsonl"
DEFAULT_TRAINING_BENIGN_PATH = ROOT / "corpus" / "benign.jsonl"
DEFAULT_HELD_OUT_ATTACKS_PATH = ROOT / "benchmark" / "held_out_attacks.jsonl"
DEFAULT_HELD_OUT_BENIGN_PATH = ROOT / "benchmark" / "held_out_benign.jsonl"

ALLOWED_SPDX = frozenset({"MIT", "Apache-2.0", "CC-BY-4.0"})
_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SOURCE_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SOURCE_KEYS = {
    "source_id",
    "name",
    "repository_url",
    "revision",
    "license_spdx",
    "license_url",
    "paths",
}
_PROVENANCE_KEYS = {
    "source_id",
    "source_revision",
    "source_path",
    "source_record_id",
    "source_url",
    "source_file_sha256",
    "license_spdx",
    "license_url",
}
_FIRST_PARTY_GAUNTLET_KEYS = {
    "source",
    "source_certificate_id",
    "source_benchmark_case_id",
    "rights_basis",
    "training_consent_sha256",
    "training_reviewed_at",
}
_CERTIFICATE_ID_RE = re.compile(r"[0-9a-f]{32}")
_RECORD_ID_RE = re.compile(r"(py|json|jsonl|parquet):(\S.*)", re.DOTALL)
_DOTTED_PATH_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_ROW_LOCATOR_RE = re.compile(r"([0-9]+)(/.*)?", re.DOTALL)
_RECORD_SCHEMES = {
    ".py": "py",
    ".json": "json",
    ".jsonl": "jsonl",
    ".parquet": "parquet",
}
_BENCHMARK_CASE_ID_RE = re.compile(r"gauntlet-[0-9a-f]{16}")
_UTC_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
TrainingDataset = Literal["attacks", "benign"]


def _read_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path} must be a regular non-symlink file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path} must contain valid UTF-8 JSON") from exc


def _valid_source_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and "." not in path.parts
        and not any(character in value for character in "*?[]")
    )


def load_source_allowlist(path: Path = DEFAULT_ALLOWLIST_PATH) -> dict[str, dict[str, object]]:
    raw = _read_json(path)
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "allowed_spdx",
        "sources",
    }:
        raise ValueError("corpus source allowlist has an invalid top-level schema")
    if raw["schema_version"] != 1 or raw["allowed_spdx"] != sorted(ALLOWED_SPDX):
        raise ValueError("corpus source allowlist has an invalid schema version or SPDX guard")
    sources = raw["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError("corpus source allowlist must contain at least one source")

    validated: dict[str, dict[str, object]] = {}
    for source in sources:
        if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
            raise ValueError("corpus source allowlist contains an invalid source definition")
        source_id = source["source_id"]
        revision = source["revision"]
        licenses = source["license_spdx"]
        paths = source["paths"]
        if (
            not isinstance(source_id, str)
            or _SOURCE_ID_RE.fullmatch(source_id) is None
            or source_id in validated
            or not isinstance(source["name"], str)
            or not source["name"]
            or not isinstance(source["repository_url"], str)
            or not str(source["repository_url"]).startswith("https://")
            or not isinstance(revision, str)
            or _REVISION_RE.fullmatch(revision) is None
            or not isinstance(source["license_url"], str)
            or not str(source["license_url"]).startswith("https://")
            or not isinstance(licenses, list)
            or licenses != sorted(set(licenses))
            or not licenses
            or not set(licenses).issubset(ALLOWED_SPDX)
            or not isinstance(paths, list)
            or paths != sorted(set(paths))
            or not paths
            or not all(_valid_source_path(item) for item in paths)
        ):
            raise ValueError(f"corpus source allowlist definition is invalid: {source_id!r}")
        validated[source_id] = dict(source)
    if list(validated) != sorted(validated):
        raise ValueError("corpus source allowlist sources must be sorted by source_id")
    return validated


def _run_git(checkout: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("source checkout failed local Git verification")
    return completed.stdout.strip()


def _canonical_repository_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    if normalized.startswith("git@") and ":" in normalized:
        host_path = normalized[4:].replace(":", "/", 1)
        normalized = f"https://{host_path}"
    elif normalized.startswith("ssh://git@"):
        normalized = f"https://{normalized.removeprefix('ssh://git@')}"
    return normalized.removesuffix(".git")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_local_checkout(
    checkout: Path,
    source: dict[str, object],
    source_paths: set[str],
) -> dict[str, str]:
    if checkout.is_symlink() or not checkout.is_dir():
        raise ValueError("source checkout must be a regular non-symlink directory")
    resolved_checkout = checkout.resolve()
    if (
        Path(_run_git(resolved_checkout, "rev-parse", "--show-toplevel")).resolve()
        != resolved_checkout
    ):
        raise ValueError("source checkout must be the Git worktree root")
    if _run_git(resolved_checkout, "rev-parse", "HEAD") != source["revision"]:
        raise ValueError("source checkout HEAD does not match the allowlisted revision")
    origin = _canonical_repository_url(
        _run_git(resolved_checkout, "config", "--get", "remote.origin.url")
    )
    if origin != _canonical_repository_url(str(source["repository_url"])):
        raise ValueError("source checkout origin does not match the allowlisted repository")

    allowed_paths = set(source["paths"])
    if not source_paths or not source_paths.issubset(allowed_paths):
        raise ValueError("review mapping names a source path that is not exactly allowlisted")

    digests: dict[str, str] = {}
    for source_path in sorted(source_paths):
        candidate = resolved_checkout.joinpath(*PurePosixPath(source_path).parts)
        resolved_candidate = candidate.resolve()
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or not resolved_candidate.is_relative_to(resolved_checkout)
        ):
            raise ValueError("allowlisted source path must resolve to a regular checkout file")
        _run_git(resolved_checkout, "ls-files", "--error-unmatch", "--", source_path)
        if _run_git(
            resolved_checkout,
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            source_path,
        ):
            raise ValueError("allowlisted source file has uncommitted changes")
        with candidate.open("rb") as handle:
            if handle.read(200).startswith(b"version https://git-lfs.github.com/spec/v1"):
                raise ValueError("allowlisted Git LFS source content is not checked out")
        digests[source_path] = _sha256_file(candidate)
    return digests


def load_review_mapping(path: Path, dataset: TrainingDataset) -> list[dict[str, str]]:
    if dataset not in {"attacks", "benign"}:
        raise ValueError("training dataset must be attacks or benign")
    if path.is_symlink() or not path.is_file():
        raise ValueError("review mapping must be a regular non-symlink JSONL file")
    expected_keys = {"source_path", "source_record_id", "payload"}
    if dataset == "attacks":
        expected_keys |= {"category", "expected_verdict"}

    reviewed: list[dict[str, str]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is invalid JSON") from exc
            if not isinstance(record, dict) or set(record) != expected_keys:
                raise ValueError(f"{path}:{line_number} has an invalid review mapping schema")
            if (
                not _valid_source_path(record["source_path"])
                or not isinstance(record["source_record_id"], str)
                or not record["source_record_id"].strip()
                or len(record["source_record_id"]) > 512
                or not isinstance(record["payload"], str)
                or not record["payload"].strip()
                or len(record["payload"]) > 4_000
            ):
                raise ValueError(f"{path}:{line_number} has invalid reviewed source material")
            try:
                record["payload"].encode("utf-8")
                record["source_record_id"].encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    f"{path}:{line_number} review mapping must be valid UTF-8"
                ) from exc
            if dataset == "attacks" and (
                record["category"] not in {reason.value for reason in ReasonCode}
                or record["expected_verdict"] not in {"SANITIZE", "BLOCK"}
            ):
                raise ValueError(f"{path}:{line_number} lacks a human-reviewed attack mapping")
            reviewed.append({key: str(value) for key, value in record.items()})
    if not reviewed:
        raise ValueError("review mapping must contain at least one record")
    return reviewed


def _read_source_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cited source file is not decodable UTF-8 text: {path.name}") from exc


def _load_parquet_rows(path: Path) -> list[dict[str, object]]:
    try:
        from pyarrow import parquet
    except ImportError as exc:
        raise ValueError(
            "cited source file is Parquet but pyarrow is not installed; "
            "install pyarrow in the review environment to verify Parquet provenance"
        ) from exc
    try:
        return parquet.read_table(path).to_pylist()
    except Exception as exc:  # noqa: BLE001 - any pyarrow failure is an unusable source file
        raise ValueError(f"cited Parquet source file could not be read: {path.name}") from exc


def load_source_document(path: Path) -> object:
    """Parse one allowlisted source file into the structure its record ids address.

    Python sources become an AST, JSON becomes its decoded value, JSONL becomes the list
    of decoded lines, and Parquet becomes the list of row dicts. Parsing once per file
    keeps a review mapping with thousands of rows from re-reading the same source.
    """
    suffix = path.suffix
    if suffix == ".py":
        try:
            return ast.parse(_read_source_text(path))
        except SyntaxError as exc:
            raise ValueError(f"cited Python source file does not parse: {path.name}") from exc
    if suffix == ".json":
        try:
            return json.loads(_read_source_text(path))
        except json.JSONDecodeError as exc:
            raise ValueError(f"cited JSON source file does not parse: {path.name}") from exc
    if suffix == ".jsonl":
        records: list[object] = []
        for line_number, line in enumerate(_read_source_text(path).splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"cited JSONL source file does not parse at line {line_number}: {path.name}"
                ) from exc
        return records
    if suffix == ".parquet":
        return _load_parquet_rows(path)
    raise ValueError(f"cited source file has an unsupported format: {path.name}")


def _resolve_json_pointer(document: object, pointer: str) -> object:
    """Resolve an RFC 6901 JSON Pointer, failing closed on any missing step."""
    if not pointer.startswith("/"):
        raise ValueError("source_record_id JSON pointer must start with '/'")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                raise ValueError(f"source_record_id does not resolve: no member {token!r}")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise ValueError(f"source_record_id does not resolve: no index {token!r}")
            current = current[int(token)]
        else:
            raise ValueError(f"source_record_id does not resolve: {token!r} has no container")
    return current


def _resolve_python_symbol(module: ast.Module, dotted: str) -> object:
    if _DOTTED_PATH_RE.fullmatch(dotted) is None:
        raise ValueError("source_record_id Python locator must be a dotted symbol path")
    *containers, terminal = dotted.split(".")
    scope: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef = module
    for name in containers:
        for node in scope.body:
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name == name
            ):
                scope = node
                break
        else:
            raise ValueError(f"source_record_id does not resolve: no Python scope {name!r}")
    if terminal == "__doc__":
        docstring = ast.get_docstring(scope, clean=False)
        if docstring is None:
            raise ValueError("source_record_id does not resolve: the cited scope has no docstring")
        return docstring
    for node in scope.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        if any(isinstance(target, ast.Name) and target.id == terminal for target in targets) and (
            isinstance(node.value, ast.Constant)
        ):
            return node.value.value
    raise ValueError(f"source_record_id does not resolve: no string assignment named {terminal!r}")


def _resolve_indexed_row(
    rows: list[object], locator: str, *, one_based: bool, label: str
) -> object:
    match = _ROW_LOCATOR_RE.fullmatch(locator)
    if match is None:
        raise ValueError(f"source_record_id {label} locator must be a row number and pointer")
    index = int(match.group(1)) - (1 if one_based else 0)
    if index < 0 or index >= len(rows):
        raise ValueError(f"source_record_id does not resolve: {label} row {match.group(1)}")
    row = rows[index]
    pointer = match.group(2)
    return _resolve_json_pointer(row, pointer) if pointer else row


def resolve_source_record(document: object, source_path: str, source_record_id: str) -> str:
    """Resolve ``source_record_id`` inside a parsed source file to its literal text.

    Record ids are ``<scheme>:<locator>``, where the scheme must match the cited file's
    format so a reviewer cannot address a Parquet row as if it were a Python symbol:

    ``py:InjectionTask0.GOAL``       a string assignment or ``__doc__`` in a Python source
    ``json:/text_attack_test/3``     an RFC 6901 JSON Pointer into a ``.json`` document
    ``jsonl:12/Attacker Instruction``  1-based line, then an optional pointer into it
    ``parquet:57/text``              0-based row, then an optional pointer into the row

    The resolved value must be a string. Anything else, or any unresolvable step, fails
    closed: an unresolvable citation is exactly the shape a laundered row takes.
    """
    match = _RECORD_ID_RE.fullmatch(source_record_id)
    if match is None:
        raise ValueError(
            "source_record_id must be '<py|json|jsonl|parquet>:<locator>' naming a real record"
        )
    scheme, locator = match.group(1), match.group(2)
    expected = _RECORD_SCHEMES.get(PurePosixPath(source_path).suffix)
    if scheme != expected:
        raise ValueError(
            f"source_record_id scheme {scheme!r} does not match the cited source file format"
        )
    if scheme == "py":
        resolved = _resolve_python_symbol(document, locator)  # type: ignore[arg-type]
    elif scheme == "json":
        resolved = _resolve_json_pointer(document, locator)
    elif scheme == "jsonl":
        resolved = _resolve_indexed_row(
            document,  # type: ignore[arg-type]
            locator,
            one_based=True,
            label="JSONL",
        )
    else:
        resolved = _resolve_indexed_row(
            document,  # type: ignore[arg-type]
            locator,
            one_based=False,
            label="Parquet",
        )
    if not isinstance(resolved, str):
        raise ValueError("source_record_id must resolve to text, not a container or number")
    return resolved


def verify_payload_provenance(payload: str, record_text: str) -> None:
    """Require the reviewed payload to actually occur in the record it cites.

    Both sides are folded with ``canonical_dataset_payload`` -- the same NFKC, invisible
    and homoglyph fold, casefold, and whitespace collapse that decides whether two corpus
    rows are duplicates. Reusing it means the fold that answers "is this row already in
    the corpus" and the fold that answers "did this row really come from that source"
    cannot disagree, and it tolerates the whitespace and case drift of copying a string
    out of a Parquet cell or a wrapped Python literal. It deliberately does not collapse
    punctuation, so punctuation stays load-bearing evidence rather than something a
    reviewer can rewrite around fabricated text.
    """
    if canonical_dataset_payload(payload) not in canonical_dataset_payload(record_text):
        raise ValueError(
            "reviewed payload does not occur in the cited source record; "
            "provenance metadata may only be stamped on text taken from the source"
        )


def _source_record_url(source: dict[str, object], source_path: str) -> str:
    return (
        f"{str(source['repository_url']).rstrip('/')}/blob/{source['revision']}/"
        f"{quote(source_path, safe='/')}"
    )


def build_training_entries(
    source: dict[str, object],
    reviewed: list[dict[str, str]],
    source_file_digests: dict[str, str],
    dataset: TrainingDataset,
    checkout: Path,
) -> list[dict[str, object]]:
    """Stamp provenance onto reviewed rows, but only after proving each row is real.

    Verifying the checkout proves the *file* is the allowlisted one; it says nothing
    about the text a reviewer typed next to it. Every row is therefore resolved back to
    the record it cites and required to occur in that record's text before it may carry
    a source id, revision, file digest, and licence into a signed hardening pack.
    """
    documents: dict[str, object] = {}
    entries: list[dict[str, object]] = []
    for record in reviewed:
        source_path = record["source_path"]
        if source_path not in documents:
            documents[source_path] = load_source_document(
                checkout.resolve().joinpath(*PurePosixPath(source_path).parts)
            )
        verify_payload_provenance(
            record["payload"],
            resolve_source_record(documents[source_path], source_path, record["source_record_id"]),
        )
        identity = (f"{source['source_id']}\0{source_path}\0{record['source_record_id']}").encode(
            "utf-8"
        )
        entry: dict[str, object] = {
            "id": f"external-{source['source_id']}-{hashlib.sha256(identity).hexdigest()[:16]}",
            "payload": record["payload"],
            "note": "third-party-human-reviewed",
            "source_id": source["source_id"],
            "source_revision": source["revision"],
            "source_path": source_path,
            "source_record_id": record["source_record_id"],
            "source_url": _source_record_url(source, source_path),
            "source_file_sha256": source_file_digests[source_path],
            "license_spdx": list(source["license_spdx"]),
            "license_url": source["license_url"],
        }
        if dataset == "attacks":
            entry.update(
                {
                    "category": record["category"],
                    "expected_verdict": record["expected_verdict"],
                    "expected_classes": [record["category"]],
                }
            )
        else:
            entry.update({"expected_verdict": "ALLOW", "expected_classes": []})
        entries.append(entry)
    return entries


def _load_corpus_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    entries: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is invalid JSON") from exc
            if not isinstance(entry, dict):
                raise ValueError(f"{path}:{line_number} must contain a JSON object")
            entries.append(entry)
    return entries


def build_license_manifest(
    *,
    allowlist_path: Path = DEFAULT_ALLOWLIST_PATH,
    training_attacks_path: Path = DEFAULT_TRAINING_ATTACKS_PATH,
    training_benign_path: Path = DEFAULT_TRAINING_BENIGN_PATH,
    entries_by_dataset: Mapping[str, list[dict[str, object]]] | None = None,
) -> dict[str, object]:
    sources = load_source_allowlist(allowlist_path)
    cases: list[dict[str, object]] = []
    first_party_cases: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for dataset, path in (
        ("training-attacks", training_attacks_path),
        ("training-benign", training_benign_path),
    ):
        entries = (
            entries_by_dataset[dataset]
            if entries_by_dataset is not None
            else _load_corpus_jsonl(path)
        )
        for entry in entries:
            present_provenance = _PROVENANCE_KEYS.intersection(entry)
            present_first_party = _FIRST_PARTY_GAUNTLET_KEYS.intersection(entry)
            if present_provenance and present_first_party:
                raise ValueError("corpus row mixes third-party and first-party provenance")
            if not present_provenance:
                if not present_first_party:
                    continue
                if present_first_party != _FIRST_PARTY_GAUNTLET_KEYS:
                    raise ValueError("first-party corpus row has incomplete provenance metadata")
                case_id = entry.get("id")
                payload = entry.get("payload")
                if (
                    not isinstance(case_id, str)
                    or case_id in seen_ids
                    or not isinstance(payload, str)
                    or dataset != "training-attacks"
                    or entry["source"] != "human-reviewed-gauntlet-training"
                    or _CERTIFICATE_ID_RE.fullmatch(str(entry["source_certificate_id"])) is None
                    or _BENCHMARK_CASE_ID_RE.fullmatch(str(entry["source_benchmark_case_id"]))
                    is None
                    or entry["rights_basis"] != "submitter-training-use-consent"
                    or _SHA256_RE.fullmatch(str(entry["training_consent_sha256"])) is None
                    or _UTC_TIMESTAMP_RE.fullmatch(str(entry["training_reviewed_at"])) is None
                ):
                    raise ValueError("first-party corpus row has invalid provenance metadata")
                seen_ids.add(case_id)
                first_party_cases.append(
                    {
                        "case_id": case_id,
                        "dataset": dataset,
                        "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                        "source": entry["source"],
                        "certificate_id": entry["source_certificate_id"],
                        "benchmark_case_id": entry["source_benchmark_case_id"],
                        "rights_basis": entry["rights_basis"],
                        "training_consent_sha256": entry["training_consent_sha256"],
                        "training_reviewed_at": entry["training_reviewed_at"],
                    }
                )
                continue
            if present_provenance != _PROVENANCE_KEYS:
                raise ValueError("third-party corpus row has incomplete provenance metadata")
            case_id = entry.get("id")
            payload = entry.get("payload")
            licenses = entry.get("license_spdx")
            source_id = entry.get("source_id")
            source_path = entry.get("source_path")
            source_record_id = entry.get("source_record_id")
            source_url = entry.get("source_url")
            license_url = entry.get("license_url")
            if (
                not isinstance(case_id, str)
                or case_id in seen_ids
                or not isinstance(payload, str)
                or not isinstance(source_id, str)
                or _SOURCE_ID_RE.fullmatch(source_id) is None
                or not _valid_source_path(source_path)
                or not isinstance(source_record_id, str)
                or not source_record_id
                or not isinstance(source_url, str)
                or not source_url.startswith("https://")
                or not isinstance(license_url, str)
                or not license_url.startswith("https://")
                or not isinstance(licenses, list)
                or licenses != sorted(set(licenses))
                or not licenses
                or not set(licenses).issubset(ALLOWED_SPDX)
                or _REVISION_RE.fullmatch(str(entry["source_revision"])) is None
                or _SHA256_RE.fullmatch(str(entry["source_file_sha256"])) is None
            ):
                raise ValueError("third-party corpus row has invalid provenance metadata")
            source = sources.get(source_id)
            if (
                source is None
                or entry["source_revision"] != source["revision"]
                or source_path not in source["paths"]
                or licenses != source["license_spdx"]
                or license_url != source["license_url"]
                or source_url != _source_record_url(source, str(source_path))
            ):
                raise ValueError("third-party corpus row does not match the exact source allowlist")
            seen_ids.add(case_id)
            cases.append(
                {
                    "case_id": case_id,
                    "dataset": dataset,
                    "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    **{key: entry[key] for key in sorted(_PROVENANCE_KEYS)},
                }
            )
    cases.sort(key=lambda item: str(item["case_id"]))
    first_party_cases.sort(key=lambda item: str(item["case_id"]))
    return {
        "schema_version": 2,
        "notice_file": "THIRD-PARTY-NOTICES",
        "cases": cases,
        "first_party_cases": first_party_cases,
    }


def license_manifest_bytes(manifest: dict[str, object]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def write_license_manifest(manifest: dict[str, object], path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("license manifest target must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    serialized = license_manifest_bytes(manifest)
    try:
        with temporary.open("xb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def ingest_reviewed_corpus(
    *,
    source_id: str,
    checkout: Path,
    review_path: Path,
    dataset: TrainingDataset,
    reviewer_approved: bool,
    allowlist_path: Path = DEFAULT_ALLOWLIST_PATH,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    training_attacks_path: Path = DEFAULT_TRAINING_ATTACKS_PATH,
    training_benign_path: Path = DEFAULT_TRAINING_BENIGN_PATH,
    held_out_attacks_path: Path = DEFAULT_HELD_OUT_ATTACKS_PATH,
    held_out_benign_path: Path = DEFAULT_HELD_OUT_BENIGN_PATH,
) -> dict[str, object]:
    if reviewer_approved is not True:
        raise ValueError("explicit human reviewer approval is required")
    sources = load_source_allowlist(allowlist_path)
    source = sources.get(source_id)
    if source is None:
        raise ValueError("source_id is not allowlisted")
    reviewed = load_review_mapping(review_path, dataset)
    source_paths = {record["source_path"] for record in reviewed}
    source_file_digests = verify_local_checkout(checkout, source, source_paths)
    entries = build_training_entries(source, reviewed, source_file_digests, dataset, checkout)
    promoted = promote_reviewed_training_batch(
        entries,
        dataset=dataset,
        reviewer_approved=True,
        training_attacks_path=training_attacks_path,
        training_benign_path=training_benign_path,
        held_out_attacks_path=held_out_attacks_path,
        held_out_benign_path=held_out_benign_path,
    )
    manifest = build_license_manifest(
        allowlist_path=allowlist_path,
        training_attacks_path=training_attacks_path,
        training_benign_path=training_benign_path,
    )
    write_license_manifest(manifest, manifest_path)
    return {
        "source_id": source_id,
        "dataset": f"training-{dataset}",
        "reviewed": len(entries),
        "promoted": promoted,
        "manifest_cases": len(manifest["cases"]),
    }
