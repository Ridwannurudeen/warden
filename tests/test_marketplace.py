"""Marketplace snapshot, indexing, and static rendering tests."""

import json
import sqlite3
from argparse import Namespace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import scripts.build_index as build_index_script
import warden.marketplace.fetch as marketplace_fetch
from scripts.build_index import build, load_apa_attestations, load_evidence_links
from warden.badges import b64u_encode, ed25519_sign_record, issue_badge
from warden.engine import WardenEngine
from warden.marketplace.fetch import (
    MarketplaceAgent,
    MarketplaceService,
    SnapshotMetadata,
    fetch_snapshot,
    load_snapshot,
    parse_search_output,
)
from warden.marketplace.index import IndexedAgent, index_agent
from warden.marketplace.render import (
    associate_attestations,
    associate_badges,
    render_marketplace,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _agent(**overrides) -> MarketplaceAgent:
    values = {
        "agentId": "3808",
        "name": "Warden",
        "profileDescription": "Normal settlement note.",
        "categoryCode": ["SOFTWARE_SERVICES"],
        "soldCount": 1,
        "feedbackRate": None,
        "securityRate": None,
        "onlineStatus": 1,
        "profilePicture": "https://static.okx.com/avatar.png",
        "communicationAddress": "0xBdaEF4FC4e2cf0173d0096B5487137fb808AaED9",
        "services": [],
    }
    values.update(overrides)
    return MarketplaceAgent.model_validate(values)


def _coverage(
    *,
    sampled: int,
    expected: int | None = None,
    captured_at: str = "2026-07-13T15:30:00Z",
) -> SnapshotMetadata:
    expected = sampled if expected is None else expected
    return SnapshotMetadata(
        schema_version=2,
        captured_at=captured_at,
        query="Warden",
        page_size=10,
        sampled=sampled,
        expected=expected,
        dropped=max(expected - sampled, 0),
    )


def _signed_attestation(
    issuer_key: Ed25519PrivateKey,
    *,
    endpoint_host: str = "warden.gudman.xyz",
    **overrides: object,
) -> dict[str, object]:
    endpoint_key = Ed25519PrivateKey.generate()
    verified_at = overrides.get("verified_at", 1_784_000_000)
    expires_at = overrides.get("expires_at", int(verified_at) + 3_600)
    record: dict[str, object] = {
        "spec_version": "apa/0.1",
        "predicate_type": "https://warden.gudman.xyz/spec/protection/v1",
        "attestation_id": "0123456789abcdef0123456789abcdef",
        "issuer": "warden",
        "protector": "warden",
        "endpoint_host": endpoint_host,
        "pub": b64u_encode(endpoint_key.public_key().public_bytes_raw(), "ed25519"),
        "tier": "guard-live",
        "status": "active",
        "scans_24h": 42,
        "verified_at": verified_at,
        "expires_at": expires_at,
    }
    record.update(overrides)
    return ed25519_sign_record(record, issuer_key, "issuer_sig")


def _issuer_pub(issuer_key: Ed25519PrivateKey) -> str:
    return b64u_encode(issuer_key.public_key().public_bytes_raw(), "ed25519")


def test_parse_captured_onchainos_search_fixture():
    page = parse_search_output(_fixture("onchainos_agent_search_page.json"))

    assert page.page == 1
    assert page.page_size == 10
    assert page.total == 1
    assert page.agents[0].agent_id == "3808"
    assert [service.service_id for service in page.agents[0].services] == ["31669", "31670"]


def test_marketplace_cli_subprocess_receives_only_allowlisted_environment(monkeypatch):
    monkeypatch.setenv("HOME", "/opt/warden-index")
    monkeypatch.setenv("PATH", "/opt/warden/current/.venv/bin:/usr/local/bin:/usr/bin:/bin")
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "must-not-reach-cli")
    monkeypatch.setenv("WARDEN_ISSUER_KEY", "must-not-reach-cli")
    monkeypatch.setenv("X402_PRIVATE_KEY", "must-not-reach-cli")
    captured: dict[str, object] = {}

    def run(command, **kwargs):
        captured.update(kwargs)
        return marketplace_fetch.subprocess.CompletedProcess(
            command,
            returncode=0,
            stdout="marketplace-json",
            stderr="",
        )

    monkeypatch.setattr(marketplace_fetch.subprocess, "run", run)

    assert marketplace_fetch._run_cli(["onchainos", "agent", "search"]) == "marketplace-json"
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["HOME"] == "/opt/warden-index"
    assert environment["PATH"] == "/opt/warden/current/.venv/bin:/usr/local/bin:/usr/bin:/bin"
    assert set(environment) <= {
        "HOME",
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "PATHEXT",
        "COMSPEC",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    }
    assert not {"WARDEN_BADGE_SECRET", "WARDEN_ISSUER_KEY", "X402_PRIVATE_KEY"} & set(environment)


def test_committed_snapshot_has_honest_schema_v2_coverage():
    snapshot = load_snapshot(ROOT / "data" / "marketplace" / "agents-v1.jsonl")

    assert snapshot.metadata.model_dump() == {
        "schema_version": 2,
        "captured_at": "2026-07-16T02:47:26Z",
        "query": "a",
        "page_size": 100,
        "sampled": 730,
        "expected": 752,
        "dropped": 22,
    }
    assert len(snapshot.agents) == 730


def test_committed_warden_marketplace_numbers_are_explicitly_snapshot_dated():
    agent_html = (ROOT / "site" / "agents" / "3808.html").read_text(encoding="utf-8")
    index_html = (ROOT / "site" / "agents" / "index.html").read_text(encoding="utf-8")

    assert "<span>Sold at snapshot</span><strong class=\"num\">14</strong>" in agent_html
    assert (
        "<span>Buyer review at snapshot</span><strong class=\"num\">4 / 5</strong>"
        in agent_html
    )
    assert "<span>Sold at 2026-07-16 snapshot</span>" in index_html
    assert "<span>Buyer review at 2026-07-16 snapshot</span>" in index_html
    assert (
        "Agent: Warden; Agent ID: 3808; Category: SOFTWARE_SERVICES; "
        "Sold at 2026-07-16 snapshot: 14;"
    ) in index_html
    assert "Buyer review at 2026-07-16 snapshot: 4 / 5" in index_html
    assert '<span class="num" data-label="Sold at 2026-07-16 snapshot">14</span>' in index_html
    assert (
        '<span class="num" data-label="Buyer review at 2026-07-16 snapshot">4 / 5</span>'
        in index_html
    )


def test_fetch_paginates_until_empty_and_persists_snapshot(tmp_path):
    outputs = iter(
        [
            _fixture("onchainos_agent_search_page.json"),
            _fixture("onchainos_agent_search_empty.json"),
        ]
    )
    calls: list[list[str]] = []

    def run_command(command: list[str]) -> str:
        calls.append(command)
        return next(outputs)

    snapshot_path = tmp_path / "agents-v1.jsonl"
    snapshot = fetch_snapshot(
        snapshot_path,
        query="Warden",
        page_size=10,
        captured_at="2026-07-13T15:30:00Z",
        command_runner=run_command,
    )
    loaded = load_snapshot(snapshot_path)

    assert [command[command.index("--page") + 1] for command in calls] == ["1", "2"]
    assert snapshot.metadata.schema_version == 2
    assert snapshot.metadata.captured_at == "2026-07-13T15:30:00Z"
    assert snapshot.metadata.sampled == 1
    assert snapshot.metadata.expected == 1
    assert snapshot.metadata.dropped == 0
    assert loaded == snapshot
    assert loaded.agents[0].services[0].service_id == "31669"


def test_fetch_uses_unique_agents_and_maximum_reported_total_for_coverage(tmp_path):
    def page(page_number: int, total: int, agent_ids: list[str]) -> str:
        return json.dumps(
            {
                "ok": True,
                "data": {
                    "list": [
                        {"agentId": agent_id, "name": f"Agent {agent_id}", "services": []}
                        for agent_id in agent_ids
                    ],
                    "page": page_number,
                    "pageSize": 2,
                    "total": total,
                },
            }
        )

    outputs = iter(
        [
            page(1, 4, ["7", "8"]),
            page(2, 6, ["8", "9"]),
            page(3, 5, []),
        ]
    )

    snapshot = fetch_snapshot(
        tmp_path / "agents-v1.jsonl",
        page_size=2,
        captured_at="2026-07-13T15:30:00Z",
        command_runner=lambda command: next(outputs),
    )

    assert [agent.agent_id for agent in snapshot.agents] == ["7", "8", "9"]
    assert snapshot.metadata.sampled == 3
    assert snapshot.metadata.expected == 6
    assert snapshot.metadata.dropped == 3


def test_fetch_rejects_nonempty_page_without_new_agents(tmp_path):
    output = _fixture("onchainos_agent_search_page.json")

    with pytest.raises(RuntimeError, match="no new agent IDs"):
        fetch_snapshot(
            tmp_path / "agents-v1.jsonl",
            query="Warden",
            page_size=10,
            command_runner=lambda command: output,
        )


def test_failed_fetch_does_not_replace_existing_snapshot(tmp_path):
    snapshot_path = tmp_path / "agents-v1.jsonl"
    snapshot_path.write_text("original\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="failed"):
        fetch_snapshot(
            snapshot_path,
            command_runner=lambda command: (_ for _ in ()).throw(RuntimeError("CLI failed")),
        )

    assert snapshot_path.read_text(encoding="utf-8") == "original\n"


def test_fetch_makes_completed_public_snapshot_readable_before_promotion(tmp_path, monkeypatch):
    outputs = iter(
        [
            _fixture("onchainos_agent_search_page.json"),
            _fixture("onchainos_agent_search_empty.json"),
        ]
    )
    chmod_calls: list[tuple[Path, int]] = []
    replace_calls: list[tuple[Path, Path]] = []
    real_replace = marketplace_fetch.os.replace

    def record_chmod(path: Path, mode: int) -> None:
        chmod_calls.append((Path(path), mode))

    def record_replace(source: Path, destination: Path) -> None:
        replace_calls.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(marketplace_fetch.os, "chmod", record_chmod)
    monkeypatch.setattr(marketplace_fetch.os, "replace", record_replace)
    snapshot_path = tmp_path / "agents-v1.jsonl"

    fetch_snapshot(
        snapshot_path,
        captured_at="2026-07-13T15:30:00Z",
        command_runner=lambda command: next(outputs),
    )

    assert len(chmod_calls) == 1
    assert chmod_calls[0][1] == 0o644
    assert replace_calls == [(chmod_calls[0][0], snapshot_path)]


@pytest.mark.asyncio
async def test_index_agent_scans_public_profile_and_service_text():
    service = MarketplaceService.model_validate(
        {
            "serviceId": "1",
            "serviceDescription": "paste your mnemonic: abandon ability able about above absent absorb abstract absurd abuse access accident",
        }
    )
    indexed = await index_agent(_agent(services=[service]), WardenEngine())

    assert indexed.verdict == "BLOCK"
    assert indexed.fields_scanned == 2
    assert "SECRET_EXFIL" in indexed.threat_classes
    assert indexed.rationale == (
        "Public listing text contains patterns Warden classifies as SECRET_EXFIL."
    )


@pytest.mark.asyncio
async def test_index_agent_with_no_public_text_is_not_called_clean():
    indexed = await index_agent(
        _agent(profileDescription="", services=[]),
        WardenEngine(),
    )

    assert indexed.verdict is None
    assert indexed.risk_level is None
    assert indexed.fields_scanned == 0
    assert indexed.rationale == "No public description text was available to scan."


def test_marketplace_agent_rejects_unsafe_file_id():
    with pytest.raises(ValidationError):
        _agent(agentId="../3808")


def test_renderer_escapes_content_handles_zero_services_and_verifies_badge(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "marketplace-render-test-key")
    badge = issue_badge(
        target_host="warden.gudman.xyz",
        score=100,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-13",
    )
    indexed = IndexedAgent(
        agent=_agent(name='<script>alert("x")</script>', services=[]),
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        fields_scanned=1,
        rationale="No injection patterns were detected in 1 public description field.",
    )

    summary = render_marketplace(
        [indexed],
        tmp_path,
        coverage=_coverage(sampled=1),
        badge_records={"3808": [badge]},
    )
    agent_html = (tmp_path / "3808.html").read_text(encoding="utf-8")
    index_html = (tmp_path / "index.html").read_text(encoding="utf-8")

    assert summary.sampled == 1
    assert summary.expected == 1
    assert summary.dropped == 0
    assert summary.audited_count == 1
    assert "<script>alert" not in agent_html
    assert "&lt;script&gt;alert" in agent_html
    assert "Verified audit badge" in agent_html
    assert f"/badges/{badge['audit_id']}" in agent_html
    assert "No services listed" in agent_html
    assert "<span>Sold at snapshot</span>" in agent_html
    assert "<span>Buyer review at snapshot</span>" in agent_html
    assert "1</span> agent indexed" in index_html
    assert 'src="http' not in agent_html
    assert 'rel="canonical" href="https://warden.gudman.xyz/agents/3808"' in agent_html


def test_renderer_does_not_attach_tampered_badge(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "marketplace-render-test-key")
    badge = issue_badge(
        target_host="warden.gudman.xyz",
        score=100,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-13",
    )
    badge["score"] = 0
    indexed = IndexedAgent(
        agent=_agent(),
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        fields_scanned=1,
        rationale="No injection patterns were detected in 1 public description field.",
    )

    render_marketplace(
        [indexed],
        tmp_path,
        coverage=_coverage(sampled=1),
        badge_records={"3808": [badge]},
    )

    assert "No linked Warden audit" in (tmp_path / "3808.html").read_text(encoding="utf-8")


def test_marketplace_index_renders_search_filters_sorting_and_separate_evidence_states(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "marketplace-controls-test-key")
    badge = issue_badge(
        target_host="signal.example.org",
        score=90,
        grade="A",
        blocked=18,
        total=20,
        issued_at="2026-07-13",
    )
    signal = IndexedAgent(
        agent=_agent(
            agentId="7",
            name="Signal Agent",
            categoryCode=["SECURITY", "SOFTWARE_SERVICES"],
            soldCount=12,
            securityRate=4.5,
        ),
        verdict="SANITIZE",
        risk_level="LOW",
        threat_classes=["TOOL_HIJACK"],
        fields_scanned=1,
        rationale="Public listing text contains a tool-shaped pattern.",
    )
    unscanned = IndexedAgent(
        agent=_agent(
            agentId="8",
            name="No Description Agent",
            profileDescription="",
            categoryCode=[],
            soldCount=None,
            securityRate=None,
        ),
        verdict=None,
        risk_level=None,
        threat_classes=[],
        fields_scanned=0,
        rationale="No public description text was available to scan.",
    )

    render_marketplace(
        [signal, unscanned],
        tmp_path,
        coverage=_coverage(sampled=2),
        badge_records={"7": [badge]},
    )
    index_html = (tmp_path / "index.html").read_text(encoding="utf-8")

    for control in (
        "data-agent-search",
        "data-agent-category",
        "data-agent-match",
        "data-agent-audit",
        "data-agent-sort",
        "data-agent-reset",
        "data-agent-controls",
        "data-agent-rendered",
        "data-agent-more",
        "data-agent-empty",
    ):
        assert control in index_html
    assert index_html.count("data-agent-row") == 2
    assert "data-agent-row hidden" not in index_html
    assert 'data-agent-controls hidden aria-label="Search, filter, and sort agents"' in index_html
    assert '<span class="num" data-agent-rendered>2</span>' in index_html
    assert '<span class="num" data-agent-visible>2</span>' in index_html
    assert "data-agent-more hidden" in index_html
    assert 'aria-live="polite" aria-atomic="true"' in index_html
    assert "Search and filter controls require JavaScript" in index_html
    assert 'data-match="signal"' in index_html
    assert 'data-match="unscanned"' in index_html
    assert 'data-audit="audited"' in index_html
    assert 'data-audit="not-audited"' in index_html
    assert "Public listing text only" in index_html
    assert "<span>Sold at 2026-07-13 snapshot</span>" in index_html
    assert "<span>Buyer review at 2026-07-13 snapshot</span>" in index_html
    assert "What this does not mean" in index_html
    assert 'id="methodology"' in index_html
    assert "Linked signed audit" in index_html
    assert "Configure an authorized endpoint audit" in index_html
    assert 'href="/hire"' in index_html
    assert 'aria-label="Open public listing-text record' not in index_html
    assert (
        'aria-label="Agent: Signal Agent; Agent ID: 7; Category: SECURITY, '
        "SOFTWARE_SERVICES; Sold: 12; Public listing text: Public-text pattern "
        "match; Verdict: SANITIZE; Endpoint audit: Linked signed audit; APA "
        "attestation: No linked APA guard proof; Buyer "
        'review average: 4.5 / 5"'
    ) in index_html
    assert '<span class="sr-only">Agent: </span>' not in index_html
    assert '<script src="/agents.js" defer></script>' in index_html


def test_renderer_distinguishes_complete_and_degraded_capture_coverage(tmp_path):
    indexed = IndexedAgent(
        agent=_agent(),
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        fields_scanned=1,
        rationale="No injection patterns were detected in 1 public description field.",
    )

    complete_dir = tmp_path / "complete"
    degraded_dir = tmp_path / "degraded"
    inconsistent_dir = tmp_path / "inconsistent"
    render_marketplace([indexed], complete_dir, coverage=_coverage(sampled=1))
    render_marketplace(
        [indexed],
        degraded_dir,
        coverage=_coverage(sampled=1, expected=3),
    )
    render_marketplace(
        [indexed],
        inconsistent_dir,
        coverage=_coverage(sampled=1, expected=0),
    )

    complete_html = (complete_dir / "index.html").read_text(encoding="utf-8")
    degraded_html = (degraded_dir / "index.html").read_text(encoding="utf-8")
    inconsistent_html = (inconsistent_dir / "index.html").read_text(encoding="utf-8")
    assert "Complete discovery response for marketplace query &quot;Warden&quot;" in complete_html
    assert "Partial/degraded discovery response" not in complete_html
    assert (
        "Partial/degraded discovery response for marketplace query &quot;Warden&quot;"
        in degraded_html
    )
    assert "1 unique agent sampled" in degraded_html
    assert "highest reported result total for that query was 3" in degraded_html
    assert "2 expected agents were not present in this response" in degraded_html
    assert "API dropped" not in degraded_html
    assert "sample exceeded the highest reported result total" in inconsistent_html
    assert "upstream counts disagree" in inconsistent_html
    assert "0 expected agents were not present" not in inconsistent_html


@pytest.mark.asyncio
async def test_build_index_attaches_badge_for_unique_marketplace_service_host(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "marketplace-build-test-key")
    outputs = iter(
        [
            _fixture("onchainos_agent_search_page.json"),
            _fixture("onchainos_agent_search_empty.json"),
        ]
    )
    snapshot_path = tmp_path / "agents-v1.jsonl"
    fetch_snapshot(
        snapshot_path,
        query="Warden",
        page_size=10,
        captured_at="2026-07-13T15:30:00Z",
        command_runner=lambda command: next(outputs),
    )
    badge = issue_badge(
        target_host="warden.gudman.xyz",
        score=100,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-13",
    )
    badge_store = tmp_path / "issued.jsonl"
    badge_store.write_text(json.dumps(badge) + "\n", encoding="utf-8")
    badge_links = tmp_path / "badge-links-v1.json"
    badge_links.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "links": [{"auditId": badge["audit_id"], "agentId": "3808"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "agents"
    hire_catalog = tmp_path / "warden-services.json"
    marketplace_summary = tmp_path / "marketplace-summary.json"
    atomic_paths: list[Path] = []
    write_json_atomic = build_index_script._write_json_atomic

    def record_atomic_write(path: Path, document: dict[str, object]) -> None:
        atomic_paths.append(path)
        write_json_atomic(path, document)

    monkeypatch.setattr(build_index_script, "_write_json_atomic", record_atomic_write)

    await build(
        Namespace(
            refresh=False,
            query="Warden",
            page_size=10,
            snapshot=snapshot_path,
            output=output,
            hire_catalog=hire_catalog,
            marketplace_summary=marketplace_summary,
            badge_store=badge_store,
            badge_links=badge_links,
            apa_db=tmp_path / "missing-protection.db",
            apa_issuer_pub=None,
            apa_issuer_history=None,
        )
    )

    summary = json.loads(marketplace_summary.read_text(encoding="utf-8"))
    assert atomic_paths == [hire_catalog, marketplace_summary]
    assert summary == {
        "schemaVersion": 2,
        "capturedAt": "2026-07-13T15:30:00Z",
        "query": "Warden",
        "sampled": 1,
        "expected": 1,
        "dropped": 0,
        "matchedCount": 0,
        "auditedCount": 1,
    }
    assert "Verified audit badge" in (output / "3808.html").read_text(encoding="utf-8")


def test_atomic_json_write_preserves_existing_file_when_replace_fails(tmp_path, monkeypatch):
    target = tmp_path / "summary.json"
    target.write_text("original\n", encoding="utf-8")

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(build_index_script.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        build_index_script._write_json_atomic(target, {"schemaVersion": 2})

    assert target.read_text(encoding="utf-8") == "original\n"
    assert list(tmp_path.glob("*.tmp")) == []


def test_badge_association_requires_an_explicit_reviewed_link(monkeypatch):
    monkeypatch.setenv("WARDEN_BADGE_SECRET", "marketplace-association-test-key")
    service = MarketplaceService.model_validate(
        {"serviceId": "1", "endpoint": "https://shared.example.org/service"}
    )
    indexed = [
        IndexedAgent(
            agent=_agent(agentId=agent_id, services=[service]),
            verdict="ALLOW",
            risk_level="NONE",
            threat_classes=[],
            fields_scanned=1,
            rationale="No injection patterns were detected.",
        )
        for agent_id in ("3808", "4844")
    ]
    badge = issue_badge(
        target_host="shared.example.org",
        score=100,
        grade="A",
        blocked=20,
        total=20,
        issued_at="2026-07-13",
    )

    assert associate_badges(indexed, [badge], {}) == {}
    assert associate_badges(indexed, [badge], {str(badge["audit_id"]): "3808"}) == {"3808": [badge]}


def test_badge_link_manifest_rejects_conflicting_agent_ownership(tmp_path):
    audit_id = "0123456789abcdef"
    manifest = tmp_path / "badge-links-v1.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "links": [
                    {"auditId": audit_id, "agentId": "3808"},
                    {"auditId": audit_id, "agentId": "4844"},
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="multiple agents"):
        load_evidence_links(manifest)


def test_evidence_manifest_preserves_audits_and_adds_explicit_apa_links(tmp_path):
    manifest = tmp_path / "badge-links-v1.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "links": [
                    {"auditId": "0123456789abcdef", "agentId": "3808"},
                    {
                        "attestationId": "fedcba9876543210fedcba9876543210",
                        "agentId": "4844",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    links = load_evidence_links(manifest)

    assert links.audit_by_id == {"0123456789abcdef": "3808"}
    assert links.attestation_by_id == {"fedcba9876543210fedcba9876543210": "4844"}


@pytest.mark.parametrize(
    "links, message",
    [
        (
            [
                {
                    "auditId": "0123456789abcdef",
                    "attestationId": "fedcba9876543210fedcba9876543210",
                    "agentId": "3808",
                }
            ],
            "exactly one",
        ),
        (
            [{"attestationId": "not-an-attestation", "agentId": "3808"}],
            "32-hex",
        ),
        (
            [
                {
                    "attestationId": "fedcba9876543210fedcba9876543210",
                    "agentId": "3808",
                },
                {
                    "attestationId": "fedcba9876543210fedcba9876543210",
                    "agentId": "4844",
                },
            ],
            "multiple agents",
        ),
    ],
)
def test_evidence_manifest_rejects_ambiguous_or_conflicting_apa_links(tmp_path, links, message):
    manifest = tmp_path / "badge-links-v1.json"
    manifest.write_text(
        json.dumps({"schemaVersion": 2, "links": links}),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match=message):
        load_evidence_links(manifest)


def test_apa_association_requires_valid_signature_reviewed_link_and_matching_service_host():
    issuer_key = Ed25519PrivateKey.generate()
    issuer_pub = _issuer_pub(issuer_key)
    service = MarketplaceService.model_validate(
        {"serviceId": "1", "endpoint": "https://warden.gudman.xyz/scan"}
    )
    indexed = [
        IndexedAgent(
            agent=_agent(services=[service]),
            verdict="ALLOW",
            risk_level="NONE",
            threat_classes=[],
            fields_scanned=1,
            rationale="No injection patterns were detected.",
        )
    ]
    record = _signed_attestation(issuer_key)
    attestation_id = str(record["attestation_id"])
    link = {attestation_id: "3808"}

    with pytest.raises(ValueError, match="canonical"):
        associate_attestations(indexed, [record], link, issuer_pub + "=")

    assert associate_attestations(indexed, [record], {}, issuer_pub) == {}
    assert associate_attestations(indexed, [record], link, issuer_pub) == {"3808": [record]}

    tampered = dict(record)
    tampered["scans_24h"] = 999_999
    assert associate_attestations(indexed, [tampered], link, issuer_pub) == {}

    missing_required_field = dict(record)
    missing_required_field.pop("scans_24h")
    missing_required_field = ed25519_sign_record(missing_required_field, issuer_key, "issuer_sig")
    assert associate_attestations(indexed, [missing_required_field], link, issuer_pub) == {}

    wrong_signature_prefix = dict(record)
    wrong_signature_prefix["issuer_sig"] = str(record["issuer_sig"]).replace("sig:", "other:", 1)
    assert associate_attestations(indexed, [wrong_signature_prefix], link, issuer_pub) == {}

    wrong_issuer = _signed_attestation(issuer_key, issuer="another-registry")
    assert associate_attestations(indexed, [wrong_issuer], link, issuer_pub) == {}

    wrong_protector = _signed_attestation(issuer_key, protector="another-firewall")
    assert associate_attestations(indexed, [wrong_protector], link, issuer_pub) == {}

    host_mismatch = _signed_attestation(issuer_key, endpoint_host="other.example.org")
    assert associate_attestations(indexed, [host_mismatch], link, issuer_pub) == {}

    overlong = _signed_attestation(
        issuer_key,
        expires_at=int(record["verified_at"]) + 3_601,
    )
    assert associate_attestations(indexed, [overlong], link, issuer_pub) == {}

    unsafe_timestamp = _signed_attestation(
        issuer_key,
        verified_at=build_index_script.MAX_SAFE_UNIX_SECONDS - 3_599,
    )
    assert associate_attestations(indexed, [unsafe_timestamp], link, issuer_pub) == {}


def test_apa_association_accepts_a_retired_public_key_only_through_its_signed_cutoff(
    tmp_path,
):
    current_key = Ed25519PrivateKey.generate()
    retired_key = Ed25519PrivateKey.generate()
    current_pub = _issuer_pub(current_key)
    retired_pub = _issuer_pub(retired_key)
    history_path = tmp_path / "issuer-history.json"
    history_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "warden-issuer-retired",
                        "pub": retired_pub,
                        "not_after": 1_800_000_000,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    history = build_index_script.load_apa_issuer_history(history_path, current_pub)
    service = MarketplaceService.model_validate(
        {"serviceId": "1", "endpoint": "https://warden.gudman.xyz/scan"}
    )
    indexed = [
        IndexedAgent(
            agent=_agent(services=[service]),
            verdict="ALLOW",
            risk_level="NONE",
            threat_classes=[],
            fields_scanned=1,
            rationale="No injection patterns were detected.",
        )
    ]
    accepted = _signed_attestation(retired_key, verified_at=1_799_999_999)
    late = _signed_attestation(
        retired_key,
        attestation_id="fedcba9876543210fedcba9876543210",
        verified_at=1_800_000_001,
    )
    links = {
        str(accepted["attestation_id"]): "3808",
        str(late["attestation_id"]): "3808",
    }

    assert associate_attestations(indexed, [accepted, late], links, current_pub, history) == {
        "3808": [accepted]
    }


def test_index_rejects_a_history_key_that_keeps_the_current_key_sentinel(tmp_path):
    current_key = Ed25519PrivateKey.generate()
    retired_key = Ed25519PrivateKey.generate()
    history_path = tmp_path / "issuer-history.json"
    history_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": "not-actually-retired",
                        "pub": _issuer_pub(retired_key),
                        "not_after": build_index_script.MAX_SAFE_UNIX_SECONDS,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="finite retirement cutoff"):
        build_index_script.load_apa_issuer_history(
            history_path,
            _issuer_pub(current_key),
        )


@pytest.mark.parametrize(
    ("service_endpoint", "endpoint_host"),
    [
        ("https://[2001:4860:4860::8888]/scan", "[2001:4860:4860::8888]"),
        ("https://[2001:4860:4860::8888]:8443/scan", "[2001:4860:4860::8888]:8443"),
    ],
)
def test_apa_association_accepts_the_core_issuer_ipv6_endpoint_host_format(
    service_endpoint, endpoint_host
):
    issuer_key = Ed25519PrivateKey.generate()
    record = _signed_attestation(issuer_key, endpoint_host=endpoint_host)
    indexed = [
        IndexedAgent(
            agent=_agent(
                services=[
                    MarketplaceService.model_validate(
                        {"serviceId": "1", "endpoint": service_endpoint}
                    )
                ]
            ),
            verdict="ALLOW",
            risk_level="NONE",
            threat_classes=[],
            fields_scanned=1,
            rationale="No injection patterns were detected.",
        )
    ]

    assert associate_attestations(
        indexed,
        [record],
        {str(record["attestation_id"]): "3808"},
        _issuer_pub(issuer_key),
    ) == {"3808": [record]}


def test_renderer_keeps_apa_guard_proof_separate_from_audit_and_certification(tmp_path):
    issuer_key = Ed25519PrivateKey.generate()
    issuer_pub = _issuer_pub(issuer_key)
    record = _signed_attestation(issuer_key)
    service = MarketplaceService.model_validate(
        {"serviceId": "1", "endpoint": "https://warden.gudman.xyz/scan"}
    )
    indexed = IndexedAgent(
        agent=_agent(services=[service]),
        verdict="ALLOW",
        risk_level="NONE",
        threat_classes=[],
        fields_scanned=1,
        rationale="No injection patterns were detected.",
    )

    summary = render_marketplace(
        [indexed],
        tmp_path,
        coverage=_coverage(sampled=1),
        attestation_records={"3808": [record]},
        apa_issuer_pub=issuer_pub,
    )
    agent_html = (tmp_path / "3808.html").read_text(encoding="utf-8")
    index_html = (tmp_path / "index.html").read_text(encoding="utf-8")

    assert summary.audited_count == 0
    assert "No linked Warden audit" in agent_html
    assert "Linked signed APA guard proof; open record for current status" in agent_html
    assert f"/apa/attestation/{record['attestation_id']}" in agent_html
    assert "not an endpoint audit or security certification" in agent_html
    assert "Linked signed APA guard proof; open record for current status" in index_html
    assert "APA guard proof: active" not in index_html
    assert 'data-audit="audited"' not in index_html
    assert "Verified audit badge" not in agent_html


@pytest.mark.asyncio
async def test_build_index_links_a_valid_sqlite_apa_record_without_counting_an_audit(
    tmp_path, monkeypatch
):
    outputs = iter(
        [
            _fixture("onchainos_agent_search_page.json"),
            _fixture("onchainos_agent_search_empty.json"),
        ]
    )
    snapshot_path = tmp_path / "agents-v1.jsonl"
    fetch_snapshot(
        snapshot_path,
        query="Warden",
        page_size=10,
        captured_at="2026-07-13T15:30:00Z",
        command_runner=lambda command: next(outputs),
    )
    issuer_key = Ed25519PrivateKey.generate()
    record = _signed_attestation(issuer_key)
    apa_db = tmp_path / "protection.db"
    with sqlite3.connect(apa_db) as connection:
        connection.execute(
            "CREATE TABLE attestations ("
            "attestation_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, created_at INTEGER NOT NULL"
            ")"
        )
        connection.execute(
            "INSERT INTO attestations (attestation_id, record_json, created_at) VALUES (?, ?, ?)",
            (record["attestation_id"], json.dumps(record), record["verified_at"]),
        )
    real_connect = sqlite3.connect
    opened_connections: list[sqlite3.Connection] = []

    def tracked_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened_connections.append(connection)
        return connection

    monkeypatch.setattr(build_index_script.sqlite3, "connect", tracked_connect)

    assert load_apa_attestations(apa_db) == [record]
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened_connections[0].execute("SELECT 1")

    evidence_links = tmp_path / "badge-links-v1.json"
    evidence_links.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "links": [{"attestationId": record["attestation_id"], "agentId": "3808"}],
            }
        ),
        encoding="utf-8",
    )
    badge_store = tmp_path / "issued.jsonl"
    badge_store.write_text("", encoding="utf-8")
    output = tmp_path / "agents"
    marketplace_summary = tmp_path / "marketplace-summary.json"

    await build(
        Namespace(
            refresh=False,
            query="Warden",
            page_size=10,
            snapshot=snapshot_path,
            output=output,
            hire_catalog=tmp_path / "warden-services.json",
            marketplace_summary=marketplace_summary,
            badge_store=badge_store,
            badge_links=evidence_links,
            apa_db=apa_db,
            apa_issuer_pub=_issuer_pub(issuer_key),
            apa_issuer_history=None,
        )
    )

    summary = json.loads(marketplace_summary.read_text(encoding="utf-8"))
    agent_html = (output / "3808.html").read_text(encoding="utf-8")
    assert summary["auditedCount"] == 0
    assert f"/apa/attestation/{record['attestation_id']}" in agent_html
    assert "Linked signed APA guard proof; open record for current status" in agent_html
