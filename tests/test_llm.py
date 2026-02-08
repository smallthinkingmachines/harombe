"""Tests for LLM client."""

import json

import pytest
import respx
from httpx import Response

from harombe.llm.client import Message, ToolCall
from harombe.llm.ollama import OllamaClient


@pytest.fixture
def ollama_client():
    """Create an Ollama client for testing."""
    return OllamaClient(
        model="qwen2.5:7b",
        base_url="http://localhost:11434/v1",
        temperature=0.7,
    )


@pytest.mark.asyncio
@respx.mock
async def test_complete_simple_response(ollama_client):
    """Test simple completion without tool calls."""
    # Mock OpenAI-compatible response
    mock_response = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "qwen2.5:7b",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you?",
                },
                "finish_reason": "stop",
            }
        ],
    }

    respx.post("http://localhost:11434/v1/chat/completions").mock(
        return_value=Response(200, json=mock_response)
    )

    messages = [Message(role="user", content="Hi")]
    response = await ollama_client.complete(messages)

    assert response.content == "Hello! How can I help you?"
    assert response.tool_calls is None
    assert response.finish_reason == "stop"


@pytest.mark.asyncio
@respx.mock
async def test_complete_with_tool_calls(ollama_client):
    """Test completion with tool calls."""
    mock_response = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "qwen2.5:7b",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "web_search",
                                "arguments": json.dumps({"query": "Python", "max_results": 3}),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
    }

    respx.post("http://localhost:11434/v1/chat/completions").mock(
        return_value=Response(200, json=mock_response)
    )

    messages = [Message(role="user", content="Search for Python")]
    tools = [{"type": "function", "function": {"name": "web_search"}}]

    response = await ollama_client.complete(messages, tools=tools)

    assert response.content == ""
    assert response.tool_calls is not None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "web_search"
    assert response.tool_calls[0].arguments["query"] == "Python"


@pytest.mark.asyncio
async def test_convert_messages(ollama_client):
    """Test message format conversion."""
    messages = [
        Message(role="system", content="You are helpful"),
        Message(role="user", content="Hello"),
        Message(
            role="assistant",
            content="",
            tool_calls=[
                ToolCall(id="call_1", name="search", arguments={"q": "test"})
            ],
        ),
        Message(
            role="tool",
            content="Results here",
            tool_call_id="call_1",
            name="search",
        ),
    ]

    converted = ollama_client._convert_messages(messages)

    assert len(converted) == 4
    assert converted[0]["role"] == "system"
    assert converted[1]["role"] == "user"

    # Check tool call conversion
    assert "tool_calls" in converted[2]
    assert converted[2]["tool_calls"][0]["function"]["name"] == "search"

    # Check tool response conversion
    assert converted[3]["role"] == "tool"
    assert converted[3]["tool_call_id"] == "call_1"
    assert converted[3]["name"] == "search"
