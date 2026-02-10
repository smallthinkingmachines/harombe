"""Smart Escalation pattern.

Try the local model first. If the response shows low confidence
(hedging language, refusals, very short answers), escalate to
the cloud model. No LLM call is used for the confidence check —
it relies on heuristic detection only.
"""

import re
from collections.abc import AsyncIterator
from typing import Any

from harombe.llm.client import CompletionResponse, Message

from .base import PatternBase
from .registry import register_pattern

# Hedging / low-confidence indicators
_HEDGE_PHRASES: list[str] = [
    "i'm not sure",
    "i am not sure",
    "i don't know",
    "i do not know",
    "i'm unable to",
    "i am unable to",
    "i cannot",
    "i can't",
    "it's unclear",
    "it is unclear",
    "i might be wrong",
    "not entirely certain",
    "i think maybe",
    "i'm not confident",
    "as an ai",
    "as a language model",
]

_REFUSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:sorry|apolog\w+),?\s+(?:but\s+)?i\s+(?:can(?:'t|not)|am\s+unable)", re.I),
    re.compile(r"(?:unfortunately|regrettably),?\s+i\s+(?:can(?:'t|not)|don'?t)", re.I),
]


def compute_confidence(text: str) -> float:
    """Heuristic confidence score for an LLM response.

    Returns a value in [0.0, 1.0] where lower means less confident.
    """
    if not text.strip():
        return 0.0

    score = 1.0
    text_lower = text.lower()

    # Penalty for hedging phrases
    for phrase in _HEDGE_PHRASES:
        if phrase in text_lower:
            score -= 0.25
            break  # one penalty per category

    # Penalty for refusal patterns
    for pat in _REFUSAL_PATTERNS:
        if pat.search(text_lower):
            score -= 0.35
            break

    # Penalty for very short responses (likely unhelpful)
    word_count = len(text.split())
    if word_count < 5:
        score -= 0.3
    elif word_count < 15:
        score -= 0.1

    # Penalty for excessive question marks (model confused?)
    if text.count("?") >= 3:
        score -= 0.15

    return max(0.0, min(1.0, score))


@register_pattern("smart_escalation")
class SmartEscalation(PatternBase):
    """Try local first, escalate to cloud on low confidence."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
        *,
        confidence_threshold: float = 0.5,
    ) -> None:
        super().__init__(name="smart_escalation")
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.confidence_threshold = confidence_threshold

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()

        # Try local first
        local_response = await self.local_client.complete(messages, tools, temperature, max_tokens)
        confidence = compute_confidence(local_response.content)

        if confidence >= self.confidence_threshold:
            self.metrics.record_request(target="local", latency_ms=self._elapsed_ms(start))
            result: CompletionResponse = local_response
            return result

        # Escalate to cloud
        self.metrics.record_escalation()
        cloud_response: CompletionResponse = await self.cloud_client.complete(
            messages, tools, temperature, max_tokens
        )
        self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        return cloud_response

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        # Streaming cannot do post-hoc confidence checks, so always use local
        async for chunk in self.local_client.stream_complete(messages, tools, temperature):
            yield chunk
