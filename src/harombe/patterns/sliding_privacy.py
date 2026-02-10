"""Sliding Privacy pattern.

Provides a user-adjustable privacy *dial* from 0.0 (all cloud) to
1.0 (all local).  Intermediate values mix the two backends based on
the sensitivity of each request.

The dial maps to a threshold on the ``SensitivityLevel`` ordinal.
Requests whose sensitivity is above the threshold go local;
below the threshold go to cloud.
"""

from collections.abc import AsyncIterator
from typing import Any

from harombe.llm.client import CompletionResponse, Message
from harombe.privacy.classifier import SensitivityClassifier
from harombe.privacy.models import SensitivityLevel

from .base import PatternBase
from .registry import register_pattern

# Ordered sensitivity values for threshold comparison
_LEVEL_VALUES: dict[SensitivityLevel, float] = {
    SensitivityLevel.PUBLIC: 0.0,
    SensitivityLevel.INTERNAL: 0.33,
    SensitivityLevel.CONFIDENTIAL: 0.66,
    SensitivityLevel.RESTRICTED: 1.0,
}


@register_pattern("sliding_privacy")
class SlidingPrivacy(PatternBase):
    """Privacy dial: 0.0 = all cloud, 1.0 = all local."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
        *,
        privacy_level: float = 0.5,
        classifier: SensitivityClassifier | None = None,
    ) -> None:
        super().__init__(name="sliding_privacy")
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.privacy_level = max(0.0, min(1.0, privacy_level))
        self.classifier = classifier or SensitivityClassifier()

    @property
    def privacy_level(self) -> float:
        return self._privacy_level

    @privacy_level.setter
    def privacy_level(self, value: float) -> None:
        self._privacy_level = max(0.0, min(1.0, value))

    def _should_use_local(self, messages: list[Message]) -> bool:
        """Decide routing based on dial + sensitivity."""
        # Extreme settings bypass classification
        if self.privacy_level >= 1.0:
            return True
        if self.privacy_level <= 0.0:
            return False

        query = self._extract_latest_query(messages)
        result = self.classifier.classify(query, messages)
        sensitivity_value = _LEVEL_VALUES[result.level]

        # If the content sensitivity exceeds the dial threshold, use local
        return sensitivity_value >= self.privacy_level

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()

        if self._should_use_local(messages):
            result: CompletionResponse = await self.local_client.complete(
                messages, tools, temperature, max_tokens
            )
            self.metrics.record_request(target="local", latency_ms=self._elapsed_ms(start))
        else:
            result = await self.cloud_client.complete(messages, tools, temperature, max_tokens)
            self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        return result

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        if self._should_use_local(messages):
            async for chunk in self.local_client.stream_complete(messages, tools, temperature):
                yield chunk
        else:
            async for chunk in self.cloud_client.stream_complete(messages, tools, temperature):
                yield chunk

    @staticmethod
    def _extract_latest_query(messages: list[Message]) -> str:
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""
