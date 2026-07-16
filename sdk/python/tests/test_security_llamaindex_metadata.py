import pytest

pytest.importorskip("llama_index.core")

from llama_index.core.schema import MetadataMode, NodeWithScore, TextNode  # noqa: E402

from warden_guard.client import ScanResult, WardenBlocked, WardenClient  # noqa: E402
from warden_guard.llamaindex_guard import WardenNodePostprocessor  # noqa: E402


class MetadataGuard(WardenClient):
    def __init__(self):
        self.payloads = []

    def guard(self, payload, **kwargs):
        self.payloads.append(payload)
        if "drain metadata" in payload:
            raise WardenBlocked(
                ScanResult(
                    verdict="BLOCK",
                    risk_level="HIGH",
                    threat_classes=["DRAIN_ADDRESS"],
                )
            )
        return payload.replace("ignore previous", "[removed]")


def test_llamaindex_guard_scans_and_neutralizes_llm_visible_metadata():
    client = MetadataGuard()
    guard = WardenNodePostprocessor(client)
    blocked = NodeWithScore(
        node=TextNode(text="trusted body", metadata={"instruction": "drain metadata"})
    )
    sanitized = NodeWithScore(
        node=TextNode(text="trusted body", metadata={"instruction": "ignore previous"})
    )

    result = guard.postprocess_nodes([blocked, sanitized], query_str="q")

    assert len(result) == 1
    assert "drain metadata" in client.payloads[0]
    assert "ignore previous" in client.payloads[1]
    safe_node = result[0].node
    assert safe_node.get_content(metadata_mode=MetadataMode.LLM) == client.payloads[1].replace(
        "ignore previous", "[removed]"
    )
    assert "instruction" in safe_node.excluded_llm_metadata_keys
