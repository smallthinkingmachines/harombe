"""Tests for the Anthropic LLM client."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from harombe.llm.anthropic import AnthropicClient
from harombe.llm.client import Message, ToolCall


@pytest.fixture
def client():
    return AnthropicClient(api_key="test-key", model="claude-sonnet-4-20250514")


class TestAnthropicClientMessageConversion:
    def test_extracts_system_message(self, client):
        messages = [
            Message(role="system", content="You are helpful."),
            Message(role="user", content="Hi"),
        ]
        system, msgs = client._convert_messages(messages)
        assert system == "You are helpful."
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"

    def test_no_system_message(self, client):
        messages = [Message(role="user", content="Hi")]
        system, msgs = client._convert_messages(messages)
        assert system is None
        assert len(msgs) == 1

    def test_user_message(self, client):
        messages = [Message(role="user", content="Hello")]
        _, msgs = client._convert_messages(messages)
        assert msgs[0] == {"role": "user", "content": "Hello"}

    def test_assistant_with_tool_calls(self, client):
        messages = [
            Message(
                role="assistant",
                content="Let me check.",
                tool_calls=[ToolCall(id="tc1", name="search", arguments={"q": "test"})],
            )
        ]
        _, msgs = client._convert_messages(messages)
        content = msgs[0]["content"]
        assert len(content) == 2
        assert content[0] == {"type": "text", "text": "Let me check."}
        assert content[1]["type"] == "tool_use"
        assert content[1]["id"] == "tc1"
        assert content[1]["name"] == "search"
        assert content[1]["input"] == {"q": "test"}

    def test_tool_response_message(self, client):
        messages = [
            Message(
                role="tool",
                content="Result: found",
                tool_call_id="tc1",
                name="search",
            )
        ]
        _, msgs = client._convert_messages(messages)
        assert msgs[0]["role"] == "user"
        assert msgs[0]["content"][0]["type"] == "tool_result"
        assert msgs[0]["content"][0]["tool_use_id"] == "tc1"


class TestAnthropicClientToolConversion:
    def test_converts_openai_format(self, client):
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "search",
                    "description": "Search the web",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    },
                },
            }
        ]
        result = client._convert_tools(tools)
        assert len(result) == 1
        assert result[0]["name"] == "search"
        assert result[0]["description"] == "Search the web"
        assert "properties" in result[0]["input_schema"]


class TestAnthropicClientResponseParsing:
    def test_parse_text_response(self, client):
        blocks = [{"type": "text", "text": "Hello world"}]
        text, tool_calls = client._parse_tool_calls(blocks)
        assert text == "Hello world"
        assert tool_calls == []

    def test_parse_tool_use(self, client):
        blocks = [
            {"type": "text", "text": "Let me search."},
            {
                "type": "tool_use",
                "id": "tc_1",
                "name": "search",
                "input": {"query": "test"},
            },
        ]
        text, tool_calls = client._parse_tool_calls(blocks)
        assert text == "Let me search."
        assert len(tool_calls) == 1
        assert tool_calls[0].id == "tc_1"
        assert tool_calls[0].name == "search"
        assert tool_calls[0].arguments == {"query": "test"}


class TestAnthropicClientComplete:
    @pytest.mark.asyncio
    async def test_complete_basic(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "Hello!"}],
                "stop_reason": "end_turn",
                "model": "claude-sonnet-4-20250514",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        )

        with patch.object(client.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            messages = [Message(role="user", content="Hi")]
            response = await client.complete(messages)

            assert response.content == "Hello!"
            assert response.finish_reason == "stop"
            assert response.tool_calls is None

    @pytest.mark.asyncio
    async def test_complete_with_tools(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "Searching..."},
                    {
                        "type": "tool_use",
                        "id": "tc_1",
                        "name": "web_search",
                        "input": {"query": "weather"},
                    },
                ],
                "stop_reason": "tool_use",
                "model": "claude-sonnet-4-20250514",
                "usage": {"input_tokens": 20, "output_tokens": 15},
            },
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        )

        with patch.object(client.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            messages = [Message(role="user", content="What's the weather?")]
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "description": "Search",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ]
            response = await client.complete(messages, tools=tools)

            assert response.finish_reason == "tool_calls"
            assert response.tool_calls is not None
            assert len(response.tool_calls) == 1
            assert response.tool_calls[0].name == "web_search"

    @pytest.mark.asyncio
    async def test_complete_with_system_prompt(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "I am helpful."}],
                "stop_reason": "end_turn",
                "model": "claude-sonnet-4-20250514",
                "usage": {"input_tokens": 15, "output_tokens": 5},
            },
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        )

        with patch.object(client.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            messages = [
                Message(role="system", content="You are helpful."),
                Message(role="user", content="Hello"),
            ]
            await client.complete(messages)

            call_args = mock_post.call_args
            payload = call_args.kwargs.get(
                "json", call_args.args[1] if len(call_args.args) > 1 else None
            )
            if payload is None:
                # Try positional or keyword
                for arg in call_args.args:
                    if isinstance(arg, dict) and "model" in arg:
                        payload = arg
                        break
            assert payload["system"] == "You are helpful."

    @pytest.mark.asyncio
    async def test_complete_passes_temperature(self, client):
        mock_response = httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "OK"}],
                "stop_reason": "end_turn",
                "model": "claude-sonnet-4-20250514",
                "usage": {"input_tokens": 5, "output_tokens": 2},
            },
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        )

        with patch.object(client.client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            messages = [Message(role="user", content="Hi")]
            await client.complete(messages, temperature=0.5)

            call_args = mock_post.call_args
            payload = call_args.kwargs.get("json")
            assert payload["temperature"] == 0.5
