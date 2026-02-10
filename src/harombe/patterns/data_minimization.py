"""Data Minimization pattern.

The local model classifies each sentence as ESSENTIAL, CONTEXTUAL,
SENSITIVE, or IRRELEVANT.  Only ESSENTIAL + CONTEXTUAL sentences are
forwarded to the cloud model, minimizing exposure.

Because the classification is done locally (via the local LLM), no
sensitive data leaves the machine before the filtering step.
"""

import re
from collections.abc import AsyncIterator
from enum import StrEnum
from typing import Any

from harombe.llm.client import CompletionResponse, Message

from .base import PatternBase
from .registry import register_pattern


class SentenceCategory(StrEnum):
    ESSENTIAL = "essential"
    CONTEXTUAL = "contextual"
    SENSITIVE = "sensitive"
    IRRELEVANT = "irrelevant"


_CLASSIFICATION_PROMPT = """\
Classify each numbered sentence into exactly one category.
Reply ONLY with one line per sentence in the format: <number>: <category>

Categories:
- ESSENTIAL: Directly answers or asks the core question
- CONTEXTUAL: Provides helpful background context
- SENSITIVE: Contains personal data, credentials, or private information
- IRRELEVANT: Off-topic, filler, or unnecessary

Sentences:
{sentences}"""


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences using a simple regex."""
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _parse_classifications(response_text: str, sentence_count: int) -> list[SentenceCategory]:
    """Parse the local model's classification response.

    Falls back to ESSENTIAL for any unparseable line (safe default).
    """
    results: list[SentenceCategory] = [SentenceCategory.ESSENTIAL] * sentence_count
    category_map = {c.value.lower(): c for c in SentenceCategory}

    for line in response_text.strip().splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        num_part, cat_part = line.split(":", 1)
        try:
            idx = int(num_part.strip()) - 1
        except ValueError:
            continue
        cat_key = cat_part.strip().lower()
        if 0 <= idx < sentence_count and cat_key in category_map:
            results[idx] = category_map[cat_key]

    return results


@register_pattern("data_minimization")
class DataMinimization(PatternBase):
    """Filter messages down to essential + contextual before cloud."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
        *,
        include_contextual: bool = True,
    ) -> None:
        super().__init__(name="data_minimization")
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.include_contextual = include_contextual

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()

        # Classify sentences in the latest user message
        query = self._extract_latest_query(messages)
        sentences = _split_sentences(query)

        if len(sentences) <= 1:
            # Nothing to minimize, send directly to cloud
            resp = await self.cloud_client.complete(messages, tools, temperature, max_tokens)
            self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
            return resp

        # Ask local model to classify
        numbered = "\n".join(f"{i+1}: {s}" for i, s in enumerate(sentences))
        classify_msg = [
            Message(role="user", content=_CLASSIFICATION_PROMPT.format(sentences=numbered))
        ]
        classify_response = await self.local_client.complete(classify_msg)
        categories = _parse_classifications(classify_response.content, len(sentences))

        # Filter: keep ESSENTIAL + (optionally) CONTEXTUAL
        allowed = {SentenceCategory.ESSENTIAL}
        if self.include_contextual:
            allowed.add(SentenceCategory.CONTEXTUAL)

        kept = [s for s, c in zip(sentences, categories, strict=False) if c in allowed]

        if not kept:
            # If everything got filtered, fall back to local
            resp = await self.local_client.complete(messages, tools, temperature, max_tokens)
            self.metrics.record_request(target="local", latency_ms=self._elapsed_ms(start))
            return resp

        # Rebuild messages with filtered content
        minimized_query = " ".join(kept)
        minimized_messages = [
            msg
            if msg.role != "user" or msg.content != query
            else Message(
                role="user",
                content=minimized_query,
                tool_calls=msg.tool_calls,
                tool_call_id=msg.tool_call_id,
                name=msg.name,
            )
            for msg in messages
        ]

        resp = await self.cloud_client.complete(minimized_messages, tools, temperature, max_tokens)
        self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        return resp

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        # No filtering for streaming — use local directly
        async for chunk in self.local_client.stream_complete(messages, tools, temperature):
            yield chunk

    @staticmethod
    def _extract_latest_query(messages: list[Message]) -> str:
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""
