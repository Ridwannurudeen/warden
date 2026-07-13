"""Fetch and persist public OKX.AI marketplace snapshots."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

SNAPSHOT_SCHEMA_VERSION = 1

CommandRunner = Callable[[list[str]], str]


class MarketplaceService(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    service_id: str = Field(alias="serviceId")
    service_name: str = Field(default="", alias="serviceName")
    endpoint: str = ""
    fee_amount: str | float | int | None = Field(default=None, alias="feeAmount")
    fee_token: str = Field(default="", alias="feeToken")
    service_description: str = Field(default="", alias="serviceDescription")
    service_type: str = Field(default="", alias="serviceType")

    @field_validator("service_id", mode="before")
    @classmethod
    def validate_service_id(cls, value: object) -> str:
        normalized = str(value).strip()
        if not normalized.isdecimal():
            raise ValueError("serviceId must be a decimal identifier")
        return normalized

    @field_validator(
        "service_name",
        "endpoint",
        "fee_token",
        "service_description",
        "service_type",
        mode="before",
    )
    @classmethod
    def normalize_string(cls, value: object) -> str:
        return "" if value is None else str(value)


class MarketplaceAgent(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    agent_id: str = Field(alias="agentId")
    name: str = ""
    profile_description: str = Field(default="", alias="profileDescription")
    category_codes: list[str] = Field(default_factory=list, alias="categoryCode")
    sold_count: int | None = Field(default=None, alias="soldCount")
    feedback_rate: float | None = Field(default=None, alias="feedbackRate")
    security_rate: float | None = Field(default=None, alias="securityRate")
    online_status: int | None = Field(default=None, alias="onlineStatus")
    profile_picture: str = Field(default="", alias="profilePicture")
    communication_address: str = Field(default="", alias="communicationAddress")
    services: list[MarketplaceService] = Field(default_factory=list)

    @field_validator("agent_id", mode="before")
    @classmethod
    def validate_agent_id(cls, value: object) -> str:
        normalized = str(value).strip()
        if not normalized.isdecimal():
            raise ValueError("agentId must be a decimal identifier")
        return normalized

    @field_validator(
        "name",
        "profile_description",
        "profile_picture",
        "communication_address",
        mode="before",
    )
    @classmethod
    def normalize_string(cls, value: object) -> str:
        return "" if value is None else str(value)

    @field_validator("category_codes", mode="before")
    @classmethod
    def normalize_categories(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        raise ValueError("categoryCode must be a string or list")

    @field_validator("services", mode="before")
    @classmethod
    def normalize_services(cls, value: object) -> list[object]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        raise ValueError("services must be a list")


class SearchPageData(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    agents: list[MarketplaceAgent] = Field(alias="list")
    page: int
    page_size: int = Field(alias="pageSize")
    total: int | None = None


class SearchEnvelope(BaseModel):
    ok: bool
    data: SearchPageData


class SnapshotMetadata(BaseModel):
    schema_version: int
    fetched_at: str
    query: str
    page_size: int
    agent_count: int


class MarketplaceSnapshot(BaseModel):
    metadata: SnapshotMetadata
    agents: list[MarketplaceAgent]


def parse_search_output(output: str) -> SearchPageData:
    try:
        raw = json.loads(output)
        envelope = SearchEnvelope.model_validate(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("onchainos agent search returned an invalid JSON envelope") from exc
    if not envelope.ok:
        raise RuntimeError("onchainos agent search returned ok:false")
    return envelope.data


def _run_cli(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("onchainos CLI is not installed") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown CLI error"
        raise RuntimeError(f"onchainos agent search failed: {message}")
    return completed.stdout


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_snapshot(
    snapshot_path: Path,
    *,
    query: str = "a",
    page_size: int = 100,
    fetched_at: str | None = None,
    command_runner: CommandRunner | None = None,
) -> MarketplaceSnapshot:
    runner = command_runner or _run_cli
    agents_by_id: dict[str, MarketplaceAgent] = {}
    page_number = 1

    while True:
        command = [
            "onchainos",
            "agent",
            "search",
            "--query",
            query,
            "--page",
            str(page_number),
            "--page-size",
            str(page_size),
        ]
        page = parse_search_output(runner(command))
        if not page.agents:
            break

        new_ids = 0
        for agent in page.agents:
            if agent.agent_id not in agents_by_id:
                agents_by_id[agent.agent_id] = agent
                new_ids += 1
        if new_ids == 0:
            raise RuntimeError("nonempty marketplace page contained no new agent IDs")
        page_number += 1

    agents = sorted(agents_by_id.values(), key=lambda agent: int(agent.agent_id))
    snapshot = MarketplaceSnapshot(
        metadata=SnapshotMetadata(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            fetched_at=fetched_at or _utc_timestamp(),
            query=query,
            page_size=page_size,
            agent_count=len(agents),
        ),
        agents=agents,
    )
    _write_snapshot(snapshot_path, snapshot)
    return snapshot


def _write_snapshot(path: Path, snapshot: MarketplaceSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            metadata = {"kind": "snapshot", **snapshot.metadata.model_dump(mode="json")}
            handle.write(json.dumps(metadata, ensure_ascii=False, sort_keys=True) + "\n")
            for agent in snapshot.agents:
                record = {
                    "kind": "agent",
                    "agent": agent.model_dump(mode="json", by_alias=True),
                }
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def load_snapshot(path: Path) -> MarketplaceSnapshot:
    with path.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    if not records or records[0].get("kind") != "snapshot":
        raise RuntimeError("marketplace snapshot metadata record is missing")

    metadata_record = dict(records[0])
    metadata_record.pop("kind", None)
    metadata = SnapshotMetadata.model_validate(metadata_record)
    agents = [
        MarketplaceAgent.model_validate(record["agent"])
        for record in records[1:]
        if record.get("kind") == "agent"
    ]
    if len(agents) != metadata.agent_count:
        raise RuntimeError("marketplace snapshot agent count does not match metadata")
    return MarketplaceSnapshot(metadata=metadata, agents=agents)
