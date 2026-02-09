"""LLM client protocol and data types."""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class Message:
    """A message in the conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: list["ToolCall"] | None = None
    tool_call_id: str | None = None  # For tool response messages
    name: str | None = None  # Tool name for tool response messages


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class CompletionResponse:
    """Response from LLM completion."""

    content: str
    tool_calls: list[ToolCall] | None = None
    finish_reason: str = "stop"


class LLMClient(Protocol):
    """Protocol for LLM client implementations."""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """Generate a completion from the LLM.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override
            max_tokens: Maximum tokens to generate

        Returns:
            CompletionResponse with content and optional tool calls
        """
        ...

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> Any:
        """Stream a completion from the LLM.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override

        Yields:
            Content chunks as they arrive
        """
        ...
