"""Remote LLM client for distributed inference."""

from dataclasses import asdict
from typing import List, Optional

import httpx

from harombe.llm.client import CompletionResponse, LLMClient, Message, ToolCall
from harombe.tools.base import ToolSchema


class RemoteLLMClient(LLMClient):
    """
    LLM client that connects to a remote harombe node.

    Implements the same interface as OllamaClient but proxies requests
    to another harombe instance running on a different machine.
    """

    def __init__(self, host: str, port: int = 8000, timeout: int = 120, auth_token: Optional[str] = None):
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
        messages: List[Message],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
    ) -> CompletionResponse:
        """
        Send completion request to remote node.

        Args:
            messages: Conversation history
            tools: Available tool schemas
            temperature: Sampling temperature

        Returns:
            CompletionResponse from remote node
        """
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        # Convert tools to JSON Schema format
        tools_json = None
        if tools:
            tools_json = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": {
                            "type": "object",
                            "properties": tool.parameters,
                            "required": [
                                name
                                for name, param in tool.parameters.items()
                                if param.get("required", False)
                            ],
                        },
                    },
                }
                for tool in tools
            ]

        payload = {
            "messages": [asdict(msg) for msg in messages],
            "tools": tools_json,
            "temperature": temperature,
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

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
