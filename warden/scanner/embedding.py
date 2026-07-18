"""Optional provider-neutral embedding similarity for paid thorough scans."""

import asyncio
import math
import os
import re
from concurrent.futures import Future
from dataclasses import dataclass
from threading import Lock
from typing import Mapping, Protocol, Sequence

import httpx

from warden.scanner.provider_json import load_provider_json

EMBEDDING_TIMEOUT_SECONDS = 2.0
MAX_EMBEDDING_RESPONSE_BYTES = 2_097_152
MAX_EMBEDDING_DIMENSIONS = 8_192
ENABLED_VALUES = frozenset({"1", "true", "yes", "on"})
HOST_RE = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


@dataclass(frozen=True)
class EmbeddingMatch:
    similarity: float
    reference: str


class EmbeddingAnalyzer(Protocol):
    async def match(
        self,
        content: str,
        references: Sequence[str],
    ) -> EmbeddingMatch: ...


class HttpEmbeddingAnalyzer:
    """Call a configured HTTPS embedding endpoint and cache reference vectors."""

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str,
        timeout_seconds: float = EMBEDDING_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            url = httpx.URL(endpoint)
        except httpx.InvalidURL as exc:
            raise ValueError("embedding endpoint must be an absolute HTTPS URL") from exc
        if url.scheme != "https" or not url.host or HOST_RE.fullmatch(url.host) is None:
            raise ValueError("embedding endpoint must be an absolute HTTPS URL")
        if not model.strip():
            raise ValueError("embedding model is required")
        if not api_key:
            raise ValueError("embedding API key is required")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("embedding timeout must be a positive finite number")

        self._endpoint = str(url)
        self._model = model.strip()
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._reference_texts: tuple[str, ...] | None = None
        self._reference_vectors: tuple[tuple[float, ...], ...] | None = None
        self._reference_lock = Lock()
        self._reference_initializations: dict[
            tuple[str, ...],
            Future[tuple[tuple[float, ...], ...]],
        ] = {}
        self._reference_tasks: set[asyncio.Task[None]] = set()

    async def match(
        self,
        content: str,
        references: Sequence[str],
    ) -> EmbeddingMatch:
        reference_texts = tuple(references)
        if not reference_texts:
            return EmbeddingMatch(similarity=0.0, reference="")

        reference_vectors = await self._get_reference_vectors(reference_texts)
        (query_vector,) = await self._embed((content,))
        if len(query_vector) != len(reference_vectors[0]):
            raise ValueError("embedding query and reference dimensions must match")

        similarities = [
            self._cosine_similarity(query_vector, reference_vector)
            for reference_vector in reference_vectors
        ]
        best_index = max(range(len(similarities)), key=similarities.__getitem__)
        return EmbeddingMatch(
            similarity=round(similarities[best_index], 6),
            reference=reference_texts[best_index],
        )

    async def _get_reference_vectors(
        self,
        references: tuple[str, ...],
    ) -> tuple[tuple[float, ...], ...]:
        with self._reference_lock:
            if self._reference_texts == references and self._reference_vectors is not None:
                return self._reference_vectors
            initialization = self._reference_initializations.get(references)
            should_initialize = initialization is None
            if initialization is None:
                initialization = Future()
                self._reference_initializations[references] = initialization

        if should_initialize:
            task = asyncio.create_task(
                self._initialize_reference_vectors(references, initialization)
            )
            with self._reference_lock:
                self._reference_tasks.add(task)

        return await asyncio.shield(asyncio.wrap_future(initialization))

    async def _initialize_reference_vectors(
        self,
        references: tuple[str, ...],
        initialization: Future[tuple[tuple[float, ...], ...]],
    ) -> None:
        try:
            vectors = await self._embed(references)
        except asyncio.CancelledError:
            if not initialization.done():
                initialization.set_exception(
                    RuntimeError("embedding reference initialization was cancelled")
                )
            raise
        except BaseException as exc:
            if not initialization.done():
                initialization.set_exception(exc)
            if not isinstance(exc, Exception):
                raise
        else:
            with self._reference_lock:
                self._reference_texts = references
                self._reference_vectors = vectors
            if not initialization.done():
                initialization.set_result(vectors)
        finally:
            current_task = asyncio.current_task()
            with self._reference_lock:
                if self._reference_initializations.get(references) is initialization:
                    self._reference_initializations.pop(references)
                if current_task is not None:
                    self._reference_tasks.discard(current_task)

    async def _embed(
        self,
        texts: Sequence[str],
    ) -> tuple[tuple[float, ...], ...]:
        async with asyncio.timeout(self._timeout_seconds):
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    self._endpoint,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Accept-Encoding": "identity",
                    },
                    json={
                        "model": self._model,
                        "input": list(texts),
                    },
                ) as response:
                    response.raise_for_status()
                    content_encoding = response.headers.get("content-encoding", "").strip().lower()
                    if content_encoding and content_encoding != "identity":
                        raise ValueError("embedding response must not be compressed")
                    chunks: list[bytes] = []
                    if response.is_stream_consumed:
                        if len(response.content) > MAX_EMBEDDING_RESPONSE_BYTES:
                            raise ValueError("embedding response exceeds size limit")
                        chunks = [response.content]
                    else:
                        response_size = 0
                        async for chunk in response.aiter_raw(
                            chunk_size=MAX_EMBEDDING_RESPONSE_BYTES // 2
                        ):
                            response_size += len(chunk)
                            if response_size > MAX_EMBEDDING_RESPONSE_BYTES:
                                raise ValueError("embedding response exceeds size limit")
                            chunks.append(chunk)

        return self._parse_vectors(b"".join(chunks), len(texts))

    @staticmethod
    def _parse_vectors(
        raw_response: bytes,
        expected_count: int,
    ) -> tuple[tuple[float, ...], ...]:
        response_data = load_provider_json(raw_response)
        if not isinstance(response_data, dict):
            raise ValueError("embedding response must be a JSON object")
        data = response_data.get("data")
        if not isinstance(data, list) or len(data) != expected_count:
            raise ValueError("embedding response must contain one vector per input")

        indexed_vectors: dict[int, tuple[float, ...]] = {}
        dimension: int | None = None
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("embedding response entries must be JSON objects")
            index = item.get("index")
            raw_vector = item.get("embedding")
            if isinstance(index, bool) or not isinstance(index, int):
                raise ValueError("embedding response index must be an integer")
            if index < 0 or index >= expected_count or index in indexed_vectors:
                raise ValueError("embedding response indices must be unique and in range")
            if not isinstance(raw_vector, list):
                raise ValueError("embedding response vector must be an array")
            if not 1 <= len(raw_vector) <= MAX_EMBEDDING_DIMENSIONS:
                raise ValueError("embedding response vector dimension is invalid")

            vector: list[float] = []
            for value in raw_vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError("embedding vector values must be numbers")
                number = float(value)
                if not math.isfinite(number):
                    raise ValueError("embedding vector values must be finite")
                vector.append(number)
            if dimension is None:
                dimension = len(vector)
            elif len(vector) != dimension:
                raise ValueError("embedding response vectors must share one dimension")
            indexed_vectors[index] = tuple(vector)

        if set(indexed_vectors) != set(range(expected_count)):
            raise ValueError("embedding response indices are incomplete")
        return tuple(indexed_vectors[index] for index in range(expected_count))

    @staticmethod
    def _cosine_similarity(
        left: tuple[float, ...],
        right: tuple[float, ...],
    ) -> float:
        if len(left) != len(right):
            raise ValueError("embedding vector dimensions must match")
        if not left:
            raise ValueError("embedding vectors must not be empty")

        left_scale = max(abs(value) for value in left)
        right_scale = max(abs(value) for value in right)
        if left_scale == 0 or right_scale == 0:
            return 0.0

        scaled_left = tuple(value / left_scale for value in left)
        scaled_right = tuple(value / right_scale for value in right)
        left_magnitude = math.sqrt(math.fsum(value * value for value in scaled_left))
        right_magnitude = math.sqrt(math.fsum(value * value for value in scaled_right))
        similarity = math.fsum(a * b for a, b in zip(scaled_left, scaled_right)) / (
            left_magnitude * right_magnitude
        )
        if not math.isfinite(similarity):
            raise ValueError("embedding cosine similarity must be finite")
        return max(-1.0, min(1.0, similarity))


def build_embedding_analyzer_from_env(
    environ: Mapping[str, str] | None = None,
) -> HttpEmbeddingAnalyzer | None:
    """Build the optional embedding tier only inside an explicitly paid runtime."""
    values = os.environ if environ is None else environ
    enabled = values.get("WARDEN_EMBEDDING_ENABLED", "").strip().lower()
    endpoint = values.get("WARDEN_EMBEDDING_ENDPOINT", "").strip()
    model = values.get("WARDEN_EMBEDDING_MODEL", "").strip()
    api_key = values.get("WARDEN_EMBEDDING_API_KEY", "").strip()
    paywall_key = values.get("OKX_API_KEY", "").strip()
    if enabled not in ENABLED_VALUES or not endpoint or not model or not api_key or not paywall_key:
        return None

    timeout_seconds = EMBEDDING_TIMEOUT_SECONDS
    raw_timeout = values.get("WARDEN_EMBEDDING_TIMEOUT_SECONDS", "").strip()
    if raw_timeout:
        try:
            parsed_timeout = float(raw_timeout)
        except ValueError:
            parsed_timeout = None
        if parsed_timeout is not None and math.isfinite(parsed_timeout) and parsed_timeout > 0:
            timeout_seconds = parsed_timeout

    try:
        return HttpEmbeddingAnalyzer(
            endpoint=endpoint,
            model=model,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    except ValueError:
        return None
