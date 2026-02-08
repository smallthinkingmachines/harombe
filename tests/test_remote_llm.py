"""Tests for remote LLM client."""

import pytest
import respx
from httpx import Response

from harombe.llm.client import CompletionResponse, Message, ToolCall
from harombe.llm.remote import RemoteLLMClient
from harombe.tools.base import ToolSchema


@pytest.mark.asyncio
@respx.mock
async def test_remote_llm_complete_basic():
    """Test basic completion request to remote node."""
    # Mock remote node response
    mock_response = {
        "content": "Hello! How can I help you?",
        "tool_calls": None,
    }

    respx.post("http://remote-node:8000/api/complete").mock(
        return_value=Response(200, json=mock_response)
    )

    client = RemoteLLMClient(host="remote-node", port=8000)

    messages = [Message(role="user", content="Hello")]
    response = await client.complete(messages)

    assert isinstance(response, CompletionResponse)
    assert response.content == "Hello! How can I help you?"
    assert response.tool_calls is None

    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_remote_llm_complete_with_tools():
    """Test completion request with tool calls."""
    # Mock remote node response with tool call
    mock_response = {
        "content": "",
        "tool_calls": [
            {
                "id": "call_123",
                "name": "shell",
                "arguments": {"command": "ls -la"},
            }
        ],
    }

    respx.post("http://remote-node:8000/api/complete").mock(
        return_value=Response(200, json=mock_response)
    )

    client = RemoteLLMClient(host="remote-node", port=8000)

    messages = [Message(role="user", content="List files")]
    tools = [
        ToolSchema(
            name="shell",
            description="Execute shell command",
            parameters={"command": {"type": "string"}},
            dangerous=True,
        )
    ]

    response = await client.complete(messages, tools=tools)

    assert response.content == ""
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "shell"

    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_remote_llm_with_auth():
    """Test remote client with authentication token."""
    mock_response = {
        "content": "Authenticated response",
        "tool_calls": None,
    }

    # Capture the request to verify auth header
    route = respx.post("http://secure-node:8000/api/complete").mock(
        return_value=Response(200, json=mock_response)
    )

    client = RemoteLLMClient(
        host="secure-node",
        port=8000,
        auth_token="secret-token-123",
    )

    messages = [Message(role="user", content="Test")]
    await client.complete(messages)

    # Verify auth header was sent
    assert route.called
    request = route.calls.last.request
    assert "Authorization" in request.headers
    assert request.headers["Authorization"] == "Bearer secret-token-123"

    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_remote_llm_error_handling():
    """Test error handling for failed requests."""
    # Mock server error
    respx.post("http://failing-node:8000/api/complete").mock(
        return_value=Response(500, json={"detail": "Internal server error"})
    )

    client = RemoteLLMClient(host="failing-node", port=8000)

    messages = [Message(role="user", content="Test")]

    with pytest.raises(Exception):  # httpx will raise on non-2xx status
        await client.complete(messages)

    await client.close()


@pytest.mark.asyncio
async def test_remote_llm_context_manager():
    """Test RemoteLLMClient as async context manager."""
    async with RemoteLLMClient(host="node", port=8000) as client:
        assert client is not None
        assert client._client is not None

    # Client should be closed after context exit
    assert client._client.is_closed
