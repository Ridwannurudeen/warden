"""Fetch and persist public OKX.AI marketplace snapshots."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal, Protocol

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

SNAPSHOT_SCHEMA_VERSION = 2
MAX_MARKETPLACE_PAGES = 100
MAX_FEE_TEXT_LENGTH = 64

CommandRunner = Callable[[list[str]], str]


class MarketplaceService(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    # OKX moved the search row's `serviceId` to a UUID and kept the numeric identifier as
    # `id`. The numeric one is what the published catalog, the stored snapshots, and the
    # rendered "Service #33460" identity use, so prefer it and fall back to `serviceId`
    # for rows and snapshots written before the change.
    service_id: str = Field(
        validation_alias=AliasChoices("id", "serviceId"),
        serialization_alias="serviceId",
    )
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

    @field_validator("fee_amount", mode="before")
    @classmethod
    def validate_fee_amount(cls, value: object) -> object:
        if value is None:
            return None
        text = str(value)
        if len(text) > MAX_FEE_TEXT_LENGTH:
            raise ValueError("feeAmount is too long")
        try:
            amount = Decimal(text)
        except InvalidOperation as exc:
            raise ValueError("feeAmount must be numeric") from exc
        if not amount.is_finite():
            raise ValueError("feeAmount must be finite")
        sign, digits, exponent = amount.as_tuple()
        if exponent >= 0:
            fixed_length = len(digits) + exponent
        else:
            fixed_length = max(len(digits) + exponent, 1) + 1 - exponent
        if sign:
            fixed_length += 1
        if fixed_length > MAX_FEE_TEXT_LENGTH:
            raise ValueError("feeAmount fixed-point representation is too long")
        return value

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
    feedback_rate: float | None = Field(default=None, alias="feedbackRate", allow_inf_nan=False)
    security_rate: float | None = Field(default=None, alias="securityRate", allow_inf_nan=False)
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

    agents: list[MarketplaceAgent] = Field(alias="list", max_length=100)
    page: int = Field(ge=1)
    page_size: int = Field(alias="pageSize", ge=1, le=100)
    total: int | None = Field(default=None, ge=0)


class ServiceListRow(BaseModel):
    """One row of `onchainos agent service-list`.

    The row carries both a numeric `id` and a UUID `serviceId`; only the numeric one
    satisfies `MarketplaceService.service_id`, and it is the identifier the published
    catalog and the marketplace snapshot already use.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    numeric_id: str = Field(alias="id")
    service_name: str = Field(default="", alias="serviceName")
    service_description: str = Field(default="", alias="serviceDescription")
    service_type: str = Field(default="", alias="serviceType")
    endpoint: str = ""
    fee: str | float | int | None = None
    contract_address: str = Field(default="", alias="contractAddress")

    @field_validator("numeric_id", mode="before")
    @classmethod
    def normalize_numeric_id(cls, value: object) -> str:
        # The CLI returns `id` as a JSON number while the snapshot stores it as a string.
        normalized = str(value).strip()
        if not normalized.isdecimal():
            raise ValueError("service-list id must be a decimal identifier")
        return normalized

    @field_validator(
        "service_name",
        "service_description",
        "service_type",
        "endpoint",
        "contract_address",
        mode="before",
    )
    @classmethod
    def normalize_optional_text(cls, value: object) -> str:
        # An A2A row carries no endpoint and reports it as null rather than omitting it.
        return "" if value is None else str(value)

    def to_service(self) -> MarketplaceService:
        return MarketplaceService.model_validate(
            {
                "serviceId": self.numeric_id,
                "serviceName": self.service_name,
                "serviceDescription": self.service_description,
                "serviceType": self.service_type,
                "endpoint": self.endpoint,
                "feeAmount": self.fee,
                "feeToken": self.contract_address,
            }
        )


class ServiceListEntry(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    agent_info: MarketplaceAgent = Field(alias="agentInfo")
    rows: list[ServiceListRow] = Field(default_factory=list, alias="list")


class ServiceListEnvelope(BaseModel):
    ok: bool
    data: list[ServiceListEntry]


class MarketplaceProviderAdapter(Protocol):
    def search_page(self, *, query: str, page: int, page_size: int) -> SearchPageData: ...


class SearchEnvelope(BaseModel):
    ok: bool
    data: SearchPageData


class SnapshotMetadata(BaseModel):
    schema_version: Literal[2]
    captured_at: str
    query: str
    page_size: int
    sampled: int = Field(ge=0)
    expected: int = Field(ge=0)
    dropped: int = Field(ge=0)

    @field_validator("captured_at")
    @classmethod
    def validate_captured_at(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("captured_at must be a UTC timestamp with second precision") from exc
        return value

    @model_validator(mode="after")
    def validate_coverage(self) -> SnapshotMetadata:
        if self.dropped != max(self.expected - self.sampled, 0):
            raise ValueError("dropped must equal max(expected - sampled, 0)")
        return self


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


def parse_service_list_output(output: str) -> MarketplaceAgent:
    """Build one agent from `agent service-list`, whose services the search index omits.

    `agent search` only returns listed agents, so a provider under review disappears from
    it entirely. `service-list` still answers for the owner, which is why this is a
    separate source rather than a variation on the census.
    """
    try:
        raw = json.loads(output)
        envelope = ServiceListEnvelope.model_validate(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            "onchainos agent service-list returned an invalid JSON envelope"
        ) from exc
    if not envelope.ok:
        raise RuntimeError("onchainos agent service-list returned ok:false")
    if len(envelope.data) != 1:
        raise RuntimeError("onchainos agent service-list must return exactly one agent")
    entry = envelope.data[0]
    return entry.agent_info.model_copy(
        update={"services": [row.to_service() for row in entry.rows]}
    )


def _run_cli(command: list[str]) -> str:
    home = os.getenv("HOME") or (os.getenv("USERPROFILE") if os.name == "nt" else None)
    path = os.getenv("PATH")
    if not home or not path:
        raise RuntimeError("onchainos CLI requires HOME and PATH")
    environment = {"HOME": home, "PATH": path}
    if os.name == "nt":
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            "PATHEXT",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
        ):
            value = os.getenv(name)
            if value:
                environment[name] = value
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("onchainos CLI is not installed") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown CLI error"
        raise RuntimeError(f"onchainos agent search failed: {message}")
    return completed.stdout


class OnchainOSCLIAdapter:
    def __init__(self, command_runner: CommandRunner | None = None) -> None:
        self._command_runner = command_runner if command_runner is not None else _run_cli

    def search_page(self, *, query: str, page: int, page_size: int) -> SearchPageData:
        command = [
            "onchainos",
            "agent",
            "search",
            "--query",
            query,
            "--page",
            str(page),
            "--page-size",
            str(page_size),
        ]
        return parse_search_output(self._command_runner(command))

    def provider_agent(self, *, agent_id: str) -> MarketplaceAgent:
        command = [
            "onchainos",
            "agent",
            "service-list",
            "--agent-id",
            agent_id,
        ]
        return parse_service_list_output(self._command_runner(command))


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_snapshot(
    snapshot_path: Path,
    *,
    query: str = "a",
    page_size: int = 100,
    captured_at: str | None = None,
    command_runner: CommandRunner | None = None,
    adapter: MarketplaceProviderAdapter | None = None,
) -> MarketplaceSnapshot:
    if not 1 <= page_size <= 100:
        raise ValueError("page_size must be between 1 and 100")
    if adapter is not None and command_runner is not None:
        raise ValueError("adapter and command_runner cannot both be provided")
    provider = (
        adapter if adapter is not None else OnchainOSCLIAdapter(command_runner=command_runner)
    )
    agents_by_id: dict[str, MarketplaceAgent] = {}
    reported_totals: list[int] = []
    page_number = 1

    while True:
        if page_number > MAX_MARKETPLACE_PAGES:
            raise RuntimeError("marketplace search exceeded page limit")
        page = provider.search_page(query=query, page=page_number, page_size=page_size)
        if page.page != page_number or page.page_size != page_size or len(page.agents) > page_size:
            raise RuntimeError("marketplace page returned inconsistent pagination metadata")
        if page.total is not None:
            reported_totals.append(page.total)
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
    if not reported_totals:
        raise RuntimeError("marketplace search did not report an expected total")
    sampled = len(agents)
    expected = max(reported_totals)
    snapshot = MarketplaceSnapshot(
        metadata=SnapshotMetadata(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            captured_at=captured_at or _utc_timestamp(),
            query=query,
            page_size=page_size,
            sampled=sampled,
            expected=expected,
            dropped=max(expected - sampled, 0),
        ),
        agents=agents,
    )
    _write_snapshot(snapshot_path, snapshot)
    return snapshot


def fetch_provider_agent(
    agent_id: str,
    *,
    command_runner: CommandRunner | None = None,
    adapter: MarketplaceProviderAdapter | None = None,
) -> MarketplaceAgent:
    if adapter is not None and command_runner is not None:
        raise ValueError("adapter and command_runner cannot both be provided")
    provider = (
        adapter if adapter is not None else OnchainOSCLIAdapter(command_runner=command_runner)
    )
    agent = provider.provider_agent(agent_id=agent_id)
    if agent.agent_id != agent_id:
        raise RuntimeError(f"onchainos agent service-list returned agent #{agent.agent_id}")
    return agent


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
        os.chmod(temporary_path, 0o644)
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
    if len(agents) != metadata.sampled:
        raise RuntimeError("marketplace snapshot sampled count does not match metadata")
    if len({agent.agent_id for agent in agents}) != len(agents):
        raise RuntimeError("marketplace snapshot contains duplicate agent IDs")
    return MarketplaceSnapshot(metadata=metadata, agents=agents)
