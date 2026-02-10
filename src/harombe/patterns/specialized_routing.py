"""Specialized Routing pattern.

Routes queries to local or cloud based on task complexity, using the
existing ``ComplexityClassifier`` from the coordination module.

Simple tasks go to the fast local model; complex tasks go to the
more capable cloud model.
"""

from collections.abc import AsyncIterator
from typing import Any

from harombe.coordination.router import ComplexityClassifier, TaskComplexity
from harombe.llm.client import CompletionResponse, Message

from .base import PatternBase
from .registry import register_pattern


@register_pattern("specialized_routing")
class SpecializedRouting(PatternBase):
    """Route by task complexity — simple to local, complex to cloud."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
        *,
        classifier: ComplexityClassifier | None = None,
        cloud_threshold: TaskComplexity = TaskComplexity.COMPLEX,
    ) -> None:
        """
        Args:
            local_client: Fast local LLM
            cloud_client: Powerful cloud LLM
            classifier: Complexity classifier (default creates new)
            cloud_threshold: Minimum complexity to route to cloud.
                COMPLEX = only complex to cloud (default).
                MEDIUM  = medium + complex to cloud.
        """
        super().__init__(name="specialized_routing")
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.classifier = classifier or ComplexityClassifier()
        self.cloud_threshold = cloud_threshold

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()

        query = self._extract_latest_query(messages)
        complexity = self.classifier.classify_query(query, messages)

        if complexity.value >= self.cloud_threshold.value:
            resp = await self.cloud_client.complete(messages, tools, temperature, max_tokens)
            self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        else:
            resp = await self.local_client.complete(messages, tools, temperature, max_tokens)
            self.metrics.record_request(target="local", latency_ms=self._elapsed_ms(start))

        return resp

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        query = self._extract_latest_query(messages)
        complexity = self.classifier.classify_query(query, messages)

        if complexity.value >= self.cloud_threshold.value:
            async for chunk in self.cloud_client.stream_complete(messages, tools, temperature):
                yield chunk
        else:
            async for chunk in self.local_client.stream_complete(messages, tools, temperature):
                yield chunk

    @staticmethod
    def _extract_latest_query(messages: list[Message]) -> str:
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""
