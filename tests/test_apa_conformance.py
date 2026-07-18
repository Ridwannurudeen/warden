"""Machine-readable APA v0.1 schema and conformance contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
SCHEMAS = SPEC / "schemas"


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_every_published_schema_is_valid_draft_2020_12() -> None:
    expected = {
        "apa-attestation-v0.1.schema.json",
        "apa-issuer-v0.1.schema.json",
        "apa-log-checkpoint-v0.1.schema.json",
        "apa-log-entry-v0.1.schema.json",
        "apa-protection-proof-v0.1.schema.json",
        "warden-breaker-v1.schema.json",
    }

    assert {path.name for path in SCHEMAS.glob("*.schema.json")} == expected
    for name in expected:
        schema = _load_json(SCHEMAS / name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert str(schema["$id"]).startswith("https://warden.gudman.xyz/spec/schemas/")
        Draft202012Validator.check_schema(schema)


def test_conformance_vectors_match_their_declared_schemas() -> None:
    manifest = _load_json(SPEC / "conformance-v0.1.json")
    assert manifest["profile"] == "apa/0.1-conformance"
    vectors = manifest["vectors"]
    assert isinstance(vectors, list)
    assert {vector["id"] for vector in vectors} == {
        "active-attestation",
        "expired-attestation",
        "revoked-attestation",
        "tampered-attestation",
        "protection-proof",
        "issuer-document",
        "apa-log-entry",
        "breaker-log-entry",
        "log-checkpoint",
        "breaker-certificate",
    }

    for vector in vectors:
        schema = _load_json(SCHEMAS / str(vector["schema"]))
        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(vector["value"]))
        assert bool(errors) is not bool(vector["schema_valid"]), (
            vector["id"],
            [error.message for error in errors],
        )


def test_reference_conformance_runner_accepts_the_frozen_vectors() -> None:
    completed = subprocess.run(
        [sys.executable, "spec/run_conformance.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "10 vectors passed" in completed.stdout


def test_conformance_pack_is_documented_and_continuously_verified() -> None:
    guide = (SPEC / "CONFORMANCE.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python spec/run_conformance.py" in guide
    assert "does not certify endpoint safety" in guide
    assert "python spec/run_conformance.py" in workflow
