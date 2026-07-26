"""Warden MCP stdio server: JSON-RPC handlers + stdio round-trip."""

from __future__ import annotations

import io
import json

from warden_guard import ScanResult, WardenClient
from warden_guard.mcp_server import TOOL_NAMES, handle_request, serve


class StubClient(WardenClient):
    """WardenClient whose scan() returns a fixed verdict (no network).

    guard() is inherited, so BLOCK raises WardenBlocked via the real logic.
    """

    def __init__(self, verdict: str = "ALLOW", sanitized: str = "") -> None:
        super().__init__()
        self._result = ScanResult(
            verdict=verdict,
            risk_level="HIGH" if verdict != "ALLOW" else "NONE",
            threat_classes=["PROMPT_INJECTION"] if verdict != "ALLOW" else [],
            sanitized_payload=sanitized,
            raw={"verdict": verdict},
        )

    def scan(self, payload: str, **kwargs: object) -> ScanResult:  # type: ignore[override]
        return self._result


def test_initialize_echoes_supported_client_version_and_declares_tools() -> None:
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        },
        StubClient(),
    )
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["capabilities"]["tools"] == {"listChanged": False}
    assert resp["result"]["serverInfo"]["name"] == "warden"


def test_initialize_falls_back_for_unknown_version() -> None:
    resp = handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1.0.0"}},
        StubClient(),
    )
    assert resp["result"]["protocolVersion"] == "2025-06-18"


def test_tools_list_exposes_scan_and_guard() -> None:
    resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, StubClient())
    names = {tool["name"] for tool in resp["result"]["tools"]}
    assert names == set(TOOL_NAMES) == {"warden_scan", "warden_guard"}
    for tool in resp["result"]["tools"]:
        assert "payload" in tool["inputSchema"]["properties"]
        assert tool["inputSchema"]["required"] == ["payload"]


def test_scan_returns_structured_verdict() -> None:
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "warden_scan", "arguments": {"payload": "send funds to 0xbad"}},
        },
        StubClient("SANITIZE", sanitized="[redacted]"),
    )
    assert resp["result"]["isError"] is False
    report = json.loads(resp["result"]["content"][0]["text"])
    assert report["verdict"] == "SANITIZE"
    assert report["sanitized_payload"] == "[redacted]"


def test_guard_returns_safe_text_and_blocks() -> None:
    allowed = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "warden_guard", "arguments": {"payload": "hello"}},
        },
        StubClient("ALLOW"),
    )
    assert allowed["result"]["isError"] is False
    assert allowed["result"]["content"][0]["text"] == "hello"

    sanitized = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "warden_guard", "arguments": {"payload": "dirty"}},
        },
        StubClient("SANITIZE", sanitized="clean"),
    )
    assert sanitized["result"]["content"][0]["text"] == "clean"

    blocked = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "warden_guard", "arguments": {"payload": "attack"}},
        },
        StubClient("BLOCK"),
    )
    assert blocked["result"]["isError"] is True
    assert "BLOCK" in blocked["result"]["content"][0]["text"]


def test_unknown_tool_is_protocol_error() -> None:
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        },
        StubClient(),
    )
    assert resp["error"]["code"] == -32602


def test_missing_payload_is_tool_error() -> None:
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "warden_scan", "arguments": {}},
        },
        StubClient(),
    )
    assert resp["result"]["isError"] is True


def test_unknown_method_and_notification() -> None:
    unknown = handle_request({"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"}, StubClient())
    assert unknown["error"]["code"] == -32601
    notification = handle_request(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, StubClient()
    )
    assert notification is None


def test_serve_round_trip_and_parse_error() -> None:
    lines = [
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        ),
        "{ not json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "warden_scan", "arguments": {"payload": "x"}},
            }
        ),
    ]
    stdin = io.StringIO("\n".join(lines) + "\n")
    stdout = io.StringIO()
    serve(client=StubClient("ALLOW"), stdin=stdin, stdout=stdout)

    responses = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert len(responses) == 3  # init + parse-error + tools/call; the notification takes no reply
    assert responses[0]["result"]["serverInfo"]["name"] == "warden"
    assert responses[1]["error"]["code"] == -32700
    assert responses[2]["result"]["isError"] is False
