"""LlamaIndex adapter — guard retrieved nodes before they reach the LLM.

Optional integration. Requires LlamaIndex:

    pip install warden-agent-guard[llamaindex]

Add the postprocessor to a query engine so poisoned retrieved context is dropped
or sanitized before synthesis:

    from warden_guard import WardenClient
    from warden_guard.llamaindex_guard import WardenNodePostprocessor

    guard = WardenNodePostprocessor(WardenClient(local=True, fail_open=False))
    engine = index.as_query_engine(node_postprocessors=[guard])

Per node: BLOCK drops the node from the result, SANITIZE replaces the exact
LLM-visible text and excludes the original metadata from synthesis, and ALLOW
leaves it unchanged.
"""

from __future__ import annotations

from pydantic import PrivateAttr

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import MetadataMode, NodeWithScore, QueryBundle
except ImportError as exc:  # pragma: no cover - exercised only without LlamaIndex
    raise ImportError(
        "warden_guard.llamaindex_guard requires LlamaIndex; "
        "install warden-agent-guard[llamaindex]"
    ) from exc

from warden_guard.client import WardenBlocked, WardenClient


class WardenNodePostprocessor(BaseNodePostprocessor):
    """A LlamaIndex node postprocessor that enforces a Warden verdict per node."""

    _client: WardenClient = PrivateAttr()

    def __init__(self, client: WardenClient, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._client = client

    @classmethod
    def class_name(cls) -> str:
        return "WardenNodePostprocessor"

    def _postprocess_nodes(
        self,
        nodes: list[NodeWithScore],
        query_bundle: QueryBundle | None = None,
    ) -> list[NodeWithScore]:
        guarded: list[NodeWithScore] = []
        for node in nodes:
            content = node.node.get_content(metadata_mode=MetadataMode.LLM)
            try:
                safe = self._client.guard(content)
            except WardenBlocked:
                continue
            if safe != content:
                node.node.set_content(safe)
                node.node.excluded_llm_metadata_keys = list(
                    dict.fromkeys(
                        [
                            *node.node.excluded_llm_metadata_keys,
                            *node.node.metadata,
                        ]
                    )
                )
            guarded.append(node)
        return guarded
