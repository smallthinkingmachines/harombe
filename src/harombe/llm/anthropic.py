"""Anthropic Claude LLM client using httpx.

Implements the LLMClient protocol for the Anthropic Messages API.
Uses httpx directly (already a project dependency) to avoid adding
the anthropic SDK as a dependency.
"""

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import httpx

from harombe.llm.client import CompletionResponse, Message, ToolCall

logger = logging.getLogger(__name__)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"


class AnthropicClient:
    """LLM client for the Anthropic Messages API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout: int = 120,
        temperature: float = 0.7,
    ):
        """Initialize Anthropic client.

        Args:
            api_key: Anthropic API key
            model: Model name (e.g., "claude-sonnet-4-20250514")
            max_tokens: Default max tokens for responses
            timeout: Request timeout in seconds
            temperature: Default sampling temperature
        """
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

        self.client = httpx.AsyncClient(
            base_url="https://api.anthropic.com",
            headers={
                "x-api-key": api_key,
                "anthropic-version": ANTHROPIC_API_VERSION,
                "content-type": "application/json",
            },
            timeout=httpx.Timeout(timeout),
        )

    def _convert_messages(self, messages: list[Message]) -> tuple[str | None, list[dict[str, Any]]]:
        """Convert internal Message format to Anthropic format.

        Anthropic requires the system message to be separate from the
        messages array, so we extract it.

        Args:
            messages: List of Message objects

        Returns:
            Tuple of (system_prompt, anthropic_messages)
        """
        system_prompt = None
        anthropic_messages: list[dict[str, Any]] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
                continue

            if msg.role == "assistant" and msg.tool_calls:
                # Anthropic uses content blocks for tool use
                content_blocks: list[dict[str, Any]] = []
                if msg.content:
                    content_blocks.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    content_blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    )
                anthropic_messages.append(
                    {
                        "role": "assistant",
                        "content": content_blocks,
                    }
                )

            elif msg.role == "tool":
                # Anthropic uses tool_result content blocks
                anthropic_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id,
                                "content": msg.content,
                            }
                        ],
                    }
                )

            else:
                anthropic_messages.append(
                    {
                        "role": msg.role,
                        "content": msg.content,
                    }
                )

        return system_prompt, anthropic_messages

    def _convert_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI function format to Anthropic tool format.

        Args:
            tools: Tools in OpenAI format

        Returns:
            Tools in Anthropic format
        """
        anthropic_tools = []
        for tool in tools:
            func = tool.get("function", tool)
            anthropic_tools.append(
                {
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        return anthropic_tools

    def _parse_tool_calls(self, content_blocks: list[dict[str, Any]]) -> tuple[str, list[ToolCall]]:
        """Parse Anthropic response content blocks into text + tool calls.

        Args:
            content_blocks: Anthropic response content blocks

        Returns:
            Tuple of (text_content, tool_calls)
        """
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for block in content_blocks:
            if block["type"] == "text":
                text_parts.append(block["text"])
            elif block["type"] == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block["id"],
                        name=block["name"],
                        arguments=block["input"],
                    )
                )

        return "\n".join(text_parts), tool_calls

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """Generate a completion from Anthropic Claude.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override
            max_tokens: Maximum tokens to generate

        Returns:
            CompletionResponse with content and optional tool calls
        """
        system_prompt, anthropic_messages = self._convert_messages(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if tools:
            payload["tools"] = self._convert_tools(tools)

        response = await self.client.post("/v1/messages", json=payload)
        response.raise_for_status()
        data = response.json()

        content_text, tool_calls = self._parse_tool_calls(data["content"])

        stop_reason = data.get("stop_reason", "end_turn")
        finish_reason = "tool_calls" if stop_reason == "tool_use" else "stop"

        return CompletionResponse(
            content=content_text,
            tool_calls=tool_calls if tool_calls else None,
            finish_reason=finish_reason,
        )

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        """Stream a completion from Anthropic Claude.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature override

        Yields:
            Content chunks as strings
        """
        system_prompt, anthropic_messages = self._convert_messages(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": True,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if tools:
            payload["tools"] = self._convert_tools(tools)

        async with self.client.stream("POST", "/v1/messages", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = json.loads(line[6:])
                if data["type"] == "content_block_delta":
                    delta = data.get("delta", {})
                    if delta.get("type") == "text_delta":
                        yield delta["text"]

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self.client.aclose()
