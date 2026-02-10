"""Debate pattern.

Two-round debate between local and cloud models:

1. **Independent answers** — Both models answer the user query independently.
2. **Mutual critique** — Each model critiques the other's answer.
3. **Synthesis** — The cloud model synthesizes a final answer incorporating
   the best of both perspectives.

This pattern is heavier (multiple LLM calls) but produces higher-quality
answers for complex or nuanced questions.
"""

from collections.abc import AsyncIterator
from typing import Any

from harombe.llm.client import CompletionResponse, Message

from .base import PatternBase
from .registry import register_pattern

_CRITIQUE_PROMPT = """\
You are reviewing another AI's answer to a user question.

User question: {question}

Other AI's answer:
{answer}

Provide a brief critique: What did they get right? What did they miss or get wrong? \
Be specific and constructive."""

_SYNTHESIS_PROMPT = """\
You are synthesizing the best answer from a debate between two AI models.

User question: {question}

Model A's answer:
{answer_a}

Model A's critique of Model B:
{critique_a}

Model B's answer:
{answer_b}

Model B's critique of Model A:
{critique_b}

Synthesize a final, comprehensive answer that incorporates the strongest points \
from both models and addresses the critiques. Do NOT mention that there was a debate \
or that multiple models were involved — just give the best answer."""


@register_pattern("debate")
class Debate(PatternBase):
    """Two-round debate between local and cloud for high-quality answers."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
    ) -> None:
        super().__init__(name="debate")
        self.local_client = local_client
        self.cloud_client = cloud_client

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()
        question = self._extract_latest_query(messages)

        # Round 1: Independent answers
        local_answer = await self.local_client.complete(messages, tools, temperature, max_tokens)
        cloud_answer = await self.cloud_client.complete(messages, tools, temperature, max_tokens)

        # Round 2: Mutual critique
        local_critique_msg = [
            Message(
                role="user",
                content=_CRITIQUE_PROMPT.format(question=question, answer=cloud_answer.content),
            )
        ]
        cloud_critique_msg = [
            Message(
                role="user",
                content=_CRITIQUE_PROMPT.format(question=question, answer=local_answer.content),
            )
        ]

        local_critique = await self.local_client.complete(local_critique_msg)
        cloud_critique = await self.cloud_client.complete(cloud_critique_msg)

        # Round 3: Synthesis (cloud synthesizes the final answer)
        synthesis_msg = [
            Message(
                role="user",
                content=_SYNTHESIS_PROMPT.format(
                    question=question,
                    answer_a=local_answer.content,
                    critique_a=local_critique.content,
                    answer_b=cloud_answer.content,
                    critique_b=cloud_critique.content,
                ),
            )
        ]
        final = await self.cloud_client.complete(synthesis_msg, tools, temperature, max_tokens)

        self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        return final

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        # Debate requires multiple round-trips, can't stream the full debate.
        # Fall back to local streaming.
        async for chunk in self.local_client.stream_complete(messages, tools, temperature):
            yield chunk

    @staticmethod
    def _extract_latest_query(messages: list[Message]) -> str:
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""
