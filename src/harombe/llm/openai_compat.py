"""Base client for OpenAI-compatible inference servers."""

import json
from collections.abc import AsyncIterator
from typing import Any

from openai import AsyncOpenAI

from harombe.llm.client import CompletionResponse, Message, ToolCall


class OpenAICompatibleClient:
    """Base LLM client for any OpenAI-compatible inference server.

    vLLM, SGLang, Ollama, and llama.cpp all expose OpenAI-compatible
    ``/v1/chat/completions`` endpoints.  This base class encapsulates the
    shared request/response logic so that backend-specific subclasses only
    need to supply config defaults and (optionally) override health checks.
    """

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str = "none",
        timeout: int = 120,
        temperature: float = 0.7,
    ) -> None:
        """Initialise the client.

        Args:
            model: Model name served by the backend.
            base_url: OpenAI-compatible endpoint (must include ``/v1``).
            api_key: API key (many backends ignore this but the SDK requires one).
            timeout: Request timeout in seconds.
            temperature: Default sampling temperature.
        """
        self.model = model
        self.temperature = temperature
        self.client = AsyncOpenAI(base_url=base_url, api_key=api_key, timeout=timeout)

    def _convert_messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        """Convert internal Message format to OpenAI format."""
        openai_messages: list[dict[str, Any]] = []

        for msg in messages:
            message_dict: dict[str, Any] = {
                "role": msg.role,
                "content": msg.content,
            }

            if msg.tool_calls:
                message_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]

            if msg.tool_call_id:
                message_dict["tool_call_id"] = msg.tool_call_id
            if msg.name:
                message_dict["name"] = msg.name

            openai_messages.append(message_dict)

        return openai_messages

    def _parse_tool_calls(self, tool_calls: Any) -> list[ToolCall]:
        """Parse tool calls from an OpenAI-compatible response."""
        if not tool_calls:
            return []

        parsed: list[ToolCall] = []
        for tc in tool_calls:
            args = json.loads(tc.function.arguments)
            parsed.append(
                ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args,
                )
            )
        return parsed

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """Generate a completion.

        Args:
            messages: Conversation history.
            tools: Available tools in OpenAI function format.
            temperature: Sampling temperature override.
            max_tokens: Maximum tokens to generate.

        Returns:
            CompletionResponse with content and optional tool calls.
        """
        openai_messages = self._convert_messages(messages)

        params: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": temperature if temperature is not None else self.temperature,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"

        if max_tokens:
            params["max_tokens"] = max_tokens

        response = await self.client.chat.completions.create(**params)

        choice = response.choices[0]
        message = choice.message

        tool_calls = self._parse_tool_calls(message.tool_calls)

        return CompletionResponse(
            content=message.content or "",
            tool_calls=tool_calls if tool_calls else None,
            finish_reason=choice.finish_reason or "stop",
        )

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        """Stream a completion.

        Args:
            messages: Conversation history.
            tools: Available tools in OpenAI function format.
            temperature: Sampling temperature override.

        Yields:
            Content chunks as strings.
        """
        openai_messages = self._convert_messages(messages)

        params: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": True,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"

        stream = await self.client.chat.completions.create(**params)

        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
