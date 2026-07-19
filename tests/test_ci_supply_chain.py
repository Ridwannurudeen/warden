"""Immutable GitHub Actions and secret-scanning workflow contracts."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDENCY_POLICY = ROOT / "docs" / "DEPENDENCY_UPDATE_POLICY.md"
PINNED_ACTIONS = {
    "actions/checkout": "df4cb1c069e1874edd31b4311f1884172cec0e10",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-node": "a0853c24544627f65ddf259abe73b1d18a591444",
}
TRUFFLEHOG_VERSION = "3.95.9"
TRUFFLEHOG_LINUX_AMD64_SHA256 = "f6d1106b85107d79527ed7a5b98b592beadd8b770dc3c9e8c1ad99e1b2cf127e"
TRUFFLEHOG_ALLOWED_SYNTHETIC_FINDING = {
    "detector": "URI",
    "commit": "fea29c05936fde91e227f6a08aee49b7f613d37c",
    "file": "tests/test_reliability_operations.py",
    "line": "422",
}


def test_every_github_action_is_pinned_to_the_verified_immutable_commit() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(
        r"^\s*(?:-\s+)?uses:\s+([^@\s]+)@([0-9a-f]+)",
        workflow,
        re.MULTILINE,
    )

    assert uses
    assert {owner for owner, _ in uses} == set(PINNED_ACTIONS)
    for owner, commit in uses:
        assert re.fullmatch(r"[0-9a-f]{40}", commit)
        assert commit == PINNED_ACTIONS[owner]
    assert not re.search(
        r"^\s*(?:-\s+)?uses:\s+\S+@(?![0-9a-f]{40}(?:\s|$))",
        workflow,
        re.MULTILINE,
    )


def test_secret_scan_is_read_only_has_full_history_and_fails_on_detected_credentials() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    secret_job = workflow.split("secret-scan:", 1)[1].split("\n  test:", 1)[0]

    assert "permissions:\n  contents: read\n" in workflow
    assert "fetch-depth: 0" in secret_job
    assert secret_job.count("persist-credentials: false") == 1
    assert f'TRUFFLEHOG_VERSION: "{TRUFFLEHOG_VERSION}"' in secret_job
    assert f"TRUFFLEHOG_SHA256: {TRUFFLEHOG_LINUX_AMD64_SHA256}" in secret_job
    assert "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" in secret_job
    assert "sha256sum --check --strict" in secret_job
    assert (
        'tar --extract --gzip --file "$archive" --directory "$binary_dir" trufflehog' in secret_job
    )
    assert '"$binary_dir/trufflehog" --version' in secret_job
    assert '"$TRUFFLEHOG_BIN" git "file://${GITHUB_WORKSPACE}"' in secret_job
    assert "--branch HEAD" in secret_job
    assert "--since-commit" not in secret_job
    assert "--fail" in secret_job
    assert "--results=verified,unknown" in secret_job
    assert "--fail-on-scan-errors" in secret_job
    assert "--no-update" in secret_job
    assert "--json" in secret_job
    assert "--github-actions" not in secret_job
    excluded = re.search(r"--exclude-globs=([^\s]+)", secret_job)
    assert excluded is not None
    assert set(excluded.group(1).split(",")) == {
        "benchmark/held_out_benign.jsonl",
        "sdk/python/tests/test_ph5_reverse_proxy.py",
        "tests/test_apa_browser_verifier.py",
    }
    for key, value in TRUFFLEHOG_ALLOWED_SYNTHETIC_FINDING.items():
        env_name = f"TRUFFLEHOG_ALLOWED_{key.upper()}"
        assert f'{env_name}: "{value}"' in secret_job
    assert 'if [ "$scan_status" -ne 0 ] && [ "$scan_status" -ne 183 ]' in secret_job
    assert "known_finding_count != 1" in secret_job
    assert "unexpected_findings" in secret_job
    assert '"Raw"' not in secret_job
    assert '"RawV2"' not in secret_job
    assert workflow.count("permissions:") == 1
    assert not re.search(r"^\s+[a-z-]+:\s+write$", workflow, re.MULTILINE)
    assert "write-all" not in workflow
    assert "${{ secrets." not in workflow
    assert "pull-requests: write" not in workflow
    assert "security-events: write" not in workflow
    assert "trufflesecurity/trufflehog@" not in workflow
    assert workflow.count("persist-credentials: false") == 2


def test_dependency_updates_require_reviewed_lock_refresh_and_full_gates() -> None:
    policy = DEPENDENCY_POLICY.read_text(encoding="utf-8")
    normalized = " ".join(policy.split())

    assert (
        "uv pip compile pyproject.toml sdk/python/pyproject.toml "
        "--extra dev --extra langchain --extra llamaindex --generate-hashes "
        "--python-platform x86_64-unknown-linux-gnu --python-version 3.11 "
        "-o requirements.lock"
    ) in policy
    for command in (
        "python -m pip_audit --require-hashes -r requirements.lock --disable-pip",
        "python -m pytest -q",
        "python -m build --no-isolation",
        "python -m twine check dist/*",
        "npm ci",
        "npm audit --audit-level=high",
        "npm test",
        "npm run build",
        "npm pack --dry-run",
    ):
        assert f"`{command}`" in policy
    assert "reviewed pull request" in normalized
    assert "must not be auto-merged" in normalized
    assert "release notes" in normalized
    assert "rollback" in normalized
