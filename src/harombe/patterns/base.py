"""Base class for multi-model collaboration patterns.

Each pattern wraps one or more LLMClient instances and itself satisfies
the LLMClient protocol, so patterns are composable via nesting.
"""

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from harombe.llm.client import CompletionResponse, Message


@dataclass
class PatternMetrics:
    """Tracks runtime statistics for a pattern."""

    total_requests: int = 0
    local_requests: int = 0
    cloud_requests: int = 0
    escalations: int = 0
    average_latency_ms: float = 0.0
    _latencies: list[float] = field(default_factory=list, repr=False)

    def record_request(self, *, target: str, latency_ms: float) -> None:
        """Record a completed request.

        Args:
            target: "local" or "cloud"
            latency_ms: Time taken in milliseconds
        """
        self.total_requests += 1
        if target == "local":
            self.local_requests += 1
        else:
            self.cloud_requests += 1
        self._latencies.append(latency_ms)
        self.average_latency_ms = sum(self._latencies) / len(self._latencies)

    def record_escalation(self) -> None:
        """Record an escalation from local to cloud."""
        self.escalations += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "local_requests": self.local_requests,
            "cloud_requests": self.cloud_requests,
            "escalations": self.escalations,
            "average_latency_ms": round(self.average_latency_ms, 2),
        }


class PatternBase:
    """Abstract base for collaboration patterns.

    Subclasses must implement ``complete`` and ``stream_complete``
    so they satisfy the ``LLMClient`` protocol.
    """

    def __init__(self, *, name: str) -> None:
        self.name = name
        self.metrics = PatternMetrics()

    # -- helpers for subclasses --

    def _start_timer(self) -> float:
        return time.perf_counter()

    def _elapsed_ms(self, start: float) -> float:
        return (time.perf_counter() - start) * 1000

    # -- LLMClient protocol (abstract) --

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        raise NotImplementedError

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        raise NotImplementedError
        yield  # make it a generator  # pragma: no cover
