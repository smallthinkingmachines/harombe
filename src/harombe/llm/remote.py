"""Remote LLM client for distributed inference."""

from dataclasses import asdict
from typing import Any

import httpx

from harombe.llm.client import CompletionResponse, LLMClient, Message, ToolCall


class RemoteLLMClient(LLMClient):
    """
    LLM client that connects to a remote harombe node.

    Implements the same interface as OllamaClient but proxies requests
    to another harombe instance running on a different machine.
    """

    def __init__(
        self, host: str, port: int = 8000, timeout: int = 120, auth_token: str | None = None
    ) -> None:
        """
        Initialize remote LLM client.

        Args:
            host: Remote node hostname or IP
            port: Remote node port
            timeout: Request timeout in seconds
            auth_token: Optional authentication token
        """
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self.auth_token = auth_token
        self._client = httpx.AsyncClient(timeout=timeout)

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """
        Send completion request to remote node.

        Args:
            messages: Conversation history
            tools: Available tools in OpenAI function format
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            CompletionResponse from remote node
        """
        headers: dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        payload: dict[str, Any] = {
            "messages": [asdict(msg) for msg in messages],
            "tools": tools,
            "temperature": temperature or 0.7,
        }

        response = await self._client.post(
            f"{self.base_url}/api/complete",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()

        data = response.json()

        # Convert tool_calls from dict to ToolCall objects
        tool_calls = None
        if data.get("tool_calls"):
            tool_calls = [ToolCall(**tc) for tc in data["tool_calls"]]

        return CompletionResponse(
            content=data["content"],
            tool_calls=tool_calls,
            finish_reason=data.get("finish_reason", "stop"),
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "RemoteLLMClient":
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any
    ) -> None:
        await self.close()
