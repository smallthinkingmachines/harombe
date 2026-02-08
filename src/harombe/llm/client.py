"""LLM client protocol and data types."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class Message:
    """A message in the conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_calls: Optional[List["ToolCall"]] = None
    tool_call_id: Optional[str] = None  # For tool response messages
    name: Optional[str] = None  # Tool name for tool response messages


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""

    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class CompletionResponse:
    """Response from LLM completion."""

    content: str
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: str = "stop"


class LLMClient(Protocol):
    """Protocol for LLM client implementations."""

    async def complete(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
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
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
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
