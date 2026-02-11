"""Tests for multi-backend LLM clients (vLLM, SGLang, llama.cpp)."""

import json

import pytest
import respx
from httpx import Response

from harombe.llm.client import Message, ToolCall
from harombe.llm.llamacpp import LlamaCppClient
from harombe.llm.ollama import OllamaClient
from harombe.llm.openai_compat import OpenAICompatibleClient
from harombe.llm.sglang import SGLangClient
from harombe.llm.vllm import VLLMClient

# -- Fixtures ----------------------------------------------------------------


@pytest.fixture
def vllm_client() -> VLLMClient:
    return VLLMClient(model="meta-llama/Llama-3.1-8B-Instruct", base_url="http://gpu:8000/v1")


@pytest.fixture
def sglang_client() -> SGLangClient:
    return SGLangClient(model="meta-llama/Llama-3.1-8B-Instruct", base_url="http://gpu:30000/v1")


@pytest.fixture
def llamacpp_client() -> LlamaCppClient:
    return LlamaCppClient(model="default", base_url="http://cpu:8080/v1")


# -- Helpers -----------------------------------------------------------------

SIMPLE_RESPONSE = {
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "created": 1677652288,
    "model": "test-model",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello from backend!",
            },
            "finish_reason": "stop",
        }
    ],
}

TOOL_CALL_RESPONSE = {
    "id": "chatcmpl-456",
    "object": "chat.completion",
    "created": 1677652288,
    "model": "test-model",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "web_search",
                            "arguments": json.dumps({"query": "test"}),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ],
}


# -- Inheritance tests -------------------------------------------------------


def test_vllm_inherits_base():
    assert issubclass(VLLMClient, OpenAICompatibleClient)


def test_sglang_inherits_base():
    assert issubclass(SGLangClient, OpenAICompatibleClient)


def test_llamacpp_inherits_base():
    assert issubclass(LlamaCppClient, OpenAICompatibleClient)


def test_ollama_inherits_base():
    assert issubclass(OllamaClient, OpenAICompatibleClient)


# -- Default URL tests -------------------------------------------------------


def test_vllm_default_url():
    client = VLLMClient(model="m")
    assert client.client.base_url is not None
    assert "8000" in str(client.client.base_url)


def test_sglang_default_url():
    client = SGLangClient(model="m")
    assert client.client.base_url is not None
    assert "30000" in str(client.client.base_url)


def test_llamacpp_default_url():
    client = LlamaCppClient()
    assert client.client.base_url is not None
    assert "8080" in str(client.client.base_url)


def test_llamacpp_default_model():
    client = LlamaCppClient()
    assert client.model == "default"


# -- API key tests -----------------------------------------------------------


def test_vllm_api_key_none():
    client = VLLMClient(model="m", api_key=None)
    assert client.client.api_key == "none"


def test_vllm_api_key_set():
    client = VLLMClient(model="m", api_key="sk-test-key")
    assert client.client.api_key == "sk-test-key"


def test_sglang_api_key_none():
    client = SGLangClient(model="m", api_key=None)
    assert client.client.api_key == "none"


def test_ollama_api_key():
    client = OllamaClient(model="m")
    assert client.client.api_key == "ollama"


# -- Completion tests --------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_vllm_complete(vllm_client: VLLMClient) -> None:
    respx.post("http://gpu:8000/v1/chat/completions").mock(
        return_value=Response(200, json=SIMPLE_RESPONSE)
    )
    messages = [Message(role="user", content="Hi")]
    response = await vllm_client.complete(messages)

    assert response.content == "Hello from backend!"
    assert response.tool_calls is None
    assert response.finish_reason == "stop"


@pytest.mark.asyncio
@respx.mock
async def test_sglang_complete(sglang_client: SGLangClient) -> None:
    respx.post("http://gpu:30000/v1/chat/completions").mock(
        return_value=Response(200, json=SIMPLE_RESPONSE)
    )
    messages = [Message(role="user", content="Hi")]
    response = await sglang_client.complete(messages)

    assert response.content == "Hello from backend!"
    assert response.tool_calls is None
    assert response.finish_reason == "stop"


@pytest.mark.asyncio
@respx.mock
async def test_llamacpp_complete(llamacpp_client: LlamaCppClient) -> None:
    respx.post("http://cpu:8080/v1/chat/completions").mock(
        return_value=Response(200, json=SIMPLE_RESPONSE)
    )
    messages = [Message(role="user", content="Hi")]
    response = await llamacpp_client.complete(messages)

    assert response.content == "Hello from backend!"
    assert response.tool_calls is None
    assert response.finish_reason == "stop"


# -- Tool call tests ---------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_vllm_tool_calls(vllm_client: VLLMClient) -> None:
    respx.post("http://gpu:8000/v1/chat/completions").mock(
        return_value=Response(200, json=TOOL_CALL_RESPONSE)
    )
    messages = [Message(role="user", content="Search")]
    tools = [{"type": "function", "function": {"name": "web_search"}}]

    response = await vllm_client.complete(messages, tools=tools)

    assert response.tool_calls is not None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "web_search"
    assert response.tool_calls[0].arguments == {"query": "test"}
    assert response.finish_reason == "tool_calls"


@pytest.mark.asyncio
@respx.mock
async def test_sglang_tool_calls(sglang_client: SGLangClient) -> None:
    respx.post("http://gpu:30000/v1/chat/completions").mock(
        return_value=Response(200, json=TOOL_CALL_RESPONSE)
    )
    messages = [Message(role="user", content="Search")]
    tools = [{"type": "function", "function": {"name": "web_search"}}]

    response = await sglang_client.complete(messages, tools=tools)

    assert response.tool_calls is not None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "web_search"


@pytest.mark.asyncio
@respx.mock
async def test_llamacpp_tool_calls(llamacpp_client: LlamaCppClient) -> None:
    respx.post("http://cpu:8080/v1/chat/completions").mock(
        return_value=Response(200, json=TOOL_CALL_RESPONSE)
    )
    messages = [Message(role="user", content="Search")]
    tools = [{"type": "function", "function": {"name": "web_search"}}]

    response = await llamacpp_client.complete(messages, tools=tools)

    assert response.tool_calls is not None
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "web_search"


# -- Message conversion tests -----------------------------------------------


def test_convert_messages_with_tool_calls(vllm_client: VLLMClient) -> None:
    messages = [
        Message(role="system", content="You are helpful"),
        Message(role="user", content="Hello"),
        Message(
            role="assistant",
            content="",
            tool_calls=[ToolCall(id="call_1", name="search", arguments={"q": "test"})],
        ),
        Message(role="tool", content="Results here", tool_call_id="call_1", name="search"),
    ]

    converted = vllm_client._convert_messages(messages)

    assert len(converted) == 4
    assert converted[0]["role"] == "system"
    assert converted[1]["role"] == "user"
    assert "tool_calls" in converted[2]
    assert converted[2]["tool_calls"][0]["function"]["name"] == "search"
    assert converted[3]["role"] == "tool"
    assert converted[3]["tool_call_id"] == "call_1"
    assert converted[3]["name"] == "search"


# -- Temperature / max_tokens tests -----------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_complete_with_temperature_override(vllm_client: VLLMClient) -> None:
    route = respx.post("http://gpu:8000/v1/chat/completions").mock(
        return_value=Response(200, json=SIMPLE_RESPONSE)
    )
    messages = [Message(role="user", content="Hi")]
    await vllm_client.complete(messages, temperature=0.1)

    request_body = json.loads(route.calls[0].request.content)
    assert request_body["temperature"] == 0.1


@pytest.mark.asyncio
@respx.mock
async def test_complete_with_max_tokens(sglang_client: SGLangClient) -> None:
    route = respx.post("http://gpu:30000/v1/chat/completions").mock(
        return_value=Response(200, json=SIMPLE_RESPONSE)
    )
    messages = [Message(role="user", content="Hi")]
    await sglang_client.complete(messages, max_tokens=256)

    request_body = json.loads(route.calls[0].request.content)
    assert request_body["max_tokens"] == 256
