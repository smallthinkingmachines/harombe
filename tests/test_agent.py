"""Tests for agent loop."""

from typing import Any

import pytest

from harombe.agent.loop import Agent, AgentState
from harombe.llm.client import CompletionResponse, Message, ToolCall
from harombe.tools.base import Tool, ToolParameter, ToolSchema


class MockLLM:
    """Mock LLM client for testing."""

    def __init__(self, responses: list[CompletionResponse]):
        """Initialize with predefined responses.

        Args:
            responses: List of responses to return in order
        """
        self.responses = responses
        self.call_count = 0
        self.calls: list[dict[str, Any]] = []

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        """Return next predefined response."""
        self.calls.append(
            {
                "messages": messages,
                "tools": tools,
                "temperature": temperature,
            }
        )

        response = self.responses[self.call_count]
        self.call_count += 1

        # If tools=None, strip any tool calls from response (realistic LLM behavior)
        if tools is None and response.tool_calls:
            return CompletionResponse(
                content=response.content or "I cannot use tools right now.",
                tool_calls=None,
                finish_reason="stop",
            )

        return response

    async def stream_complete(self, *args, **kwargs):
        """Not implemented for mock."""
        raise NotImplementedError


@pytest.mark.asyncio
async def test_agent_simple_response():
    """Test agent with simple response (no tools)."""
    mock_llm = MockLLM(
        [CompletionResponse(content="Hello! I'm here to help.", finish_reason="stop")]
    )

    agent = Agent(llm=mock_llm, tools=[], max_steps=10)
    result = await agent.run("Hi there")

    assert result == "Hello! I'm here to help."
    assert mock_llm.call_count == 1


@pytest.mark.asyncio
async def test_agent_single_tool_call():
    """Test agent making a single tool call."""

    # Create a mock tool
    async def mock_search(query: str) -> str:
        return f"Search results for: {query}"

    search_tool = Tool(
        schema=ToolSchema(
            name="search",
            description="Search for information",
            parameters=[ToolParameter(name="query", type="string", description="Search query")],
        ),
        fn=mock_search,
    )

    # LLM responses: 1) tool call, 2) final answer
    mock_llm = MockLLM(
        [
            CompletionResponse(
                content="",
                tool_calls=[ToolCall(id="call_1", name="search", arguments={"query": "Python"})],
                finish_reason="tool_calls",
            ),
            CompletionResponse(
                content="Based on the search results, Python is a programming language.",
                finish_reason="stop",
            ),
        ]
    )

    agent = Agent(llm=mock_llm, tools=[search_tool], max_steps=10)
    result = await agent.run("Tell me about Python")

    assert "programming language" in result
    assert mock_llm.call_count == 2


@pytest.mark.asyncio
async def test_agent_multiple_tool_calls():
    """Test agent making multiple sequential tool calls."""

    async def add(a: int, b: int) -> str:
        return str(a + b)

    async def multiply(a: int, b: int) -> str:
        return str(a * b)

    add_tool = Tool(
        schema=ToolSchema(
            name="add",
            description="Add numbers",
            parameters=[
                ToolParameter(name="a", type="integer", description="First number"),
                ToolParameter(name="b", type="integer", description="Second number"),
            ],
        ),
        fn=add,
    )

    multiply_tool = Tool(
        schema=ToolSchema(
            name="multiply",
            description="Multiply numbers",
            parameters=[
                ToolParameter(name="a", type="integer", description="First number"),
                ToolParameter(name="b", type="integer", description="Second number"),
            ],
        ),
        fn=multiply,
    )

    # Sequence: add(5,3) -> multiply(result, 2) -> final answer
    mock_llm = MockLLM(
        [
            CompletionResponse(
                content="",
                tool_calls=[ToolCall(id="call_1", name="add", arguments={"a": 5, "b": 3})],
            ),
            CompletionResponse(
                content="",
                tool_calls=[ToolCall(id="call_2", name="multiply", arguments={"a": 8, "b": 2})],
            ),
            CompletionResponse(content="The result is 16."),
        ]
    )

    agent = Agent(llm=mock_llm, tools=[add_tool, multiply_tool], max_steps=10)
    result = await agent.run("What is (5+3)*2?")

    assert "16" in result
    assert mock_llm.call_count == 3


@pytest.mark.asyncio
async def test_agent_dangerous_tool_confirmation():
    """Test dangerous tool confirmation mechanism."""

    async def dangerous_op(action: str) -> str:
        return f"Executed: {action}"

    dangerous_tool = Tool(
        schema=ToolSchema(
            name="dangerous",
            description="Dangerous operation",
            parameters=[ToolParameter(name="action", type="string", description="Action")],
            dangerous=True,
        ),
        fn=dangerous_op,
    )

    mock_llm = MockLLM(
        [
            CompletionResponse(
                content="",
                tool_calls=[
                    ToolCall(id="call_1", name="dangerous", arguments={"action": "delete"})
                ],
            ),
            CompletionResponse(content="Operation completed."),
        ]
    )

    # Test with auto-deny (no callback)
    agent = Agent(
        llm=mock_llm,
        tools=[dangerous_tool],
        confirm_dangerous=True,
        confirm_callback=None,
    )
    await agent.run("Do something dangerous")

    # Should be cancelled
    assert "[CANCELLED]" in mock_llm.calls[1]["messages"][-1].content


@pytest.mark.asyncio
async def test_agent_dangerous_tool_user_approves():
    """Test dangerous tool with user approval."""

    async def dangerous_op(action: str) -> str:
        return f"Executed: {action}"

    dangerous_tool = Tool(
        schema=ToolSchema(
            name="dangerous",
            description="Dangerous operation",
            parameters=[ToolParameter(name="action", type="string", description="Action")],
            dangerous=True,
        ),
        fn=dangerous_op,
    )

    # Callback that always approves
    def approve_callback(name: str, desc: str, args: dict[str, Any]) -> bool:
        return True

    mock_llm = MockLLM(
        [
            CompletionResponse(
                content="",
                tool_calls=[
                    ToolCall(id="call_1", name="dangerous", arguments={"action": "delete"})
                ],
            ),
            CompletionResponse(content="Operation completed."),
        ]
    )

    agent = Agent(
        llm=mock_llm,
        tools=[dangerous_tool],
        confirm_dangerous=True,
        confirm_callback=approve_callback,
    )
    await agent.run("Do something dangerous")

    # Should execute
    assert "Executed" in mock_llm.calls[1]["messages"][-1].content


@pytest.mark.asyncio
async def test_agent_max_steps():
    """Test that agent stops at max steps and forces final answer."""
    # Create list of tool call responses
    responses = [
        CompletionResponse(
            content="",
            tool_calls=[ToolCall(id=f"call_{i}", name="search", arguments={"query": f"q{i}"})],
        )
        for i in range(15)
    ]
    responses.append(CompletionResponse(content="Final answer after max steps."))

    mock_llm = MockLLM(responses)

    async def mock_search(query: str) -> str:
        return f"Results for {query}"

    search_tool = Tool(
        schema=ToolSchema(
            name="search",
            description="Search",
            parameters=[ToolParameter(name="query", type="string", description="Query")],
        ),
        fn=mock_search,
    )

    agent = Agent(llm=mock_llm, tools=[search_tool], max_steps=3)
    result = await agent.run("Keep searching")

    # With max_steps=3:
    # - Step 1: LLM call with tools -> tool call response -> execute tool
    # - Step 2: LLM call with tools -> tool call response -> execute tool
    # - Step 3: LLM call WITHOUT tools -> mock strips tool_calls, returns content -> loop exits
    # Total: 3 calls
    assert mock_llm.call_count == 3
    # The result should be the fallback message since tools were stripped
    assert "cannot use tools" in result.lower()


@pytest.mark.asyncio
async def test_agent_state():
    """Test agent state management."""
    state = AgentState(system_prompt="You are helpful")

    assert len(state.messages) == 1
    assert state.messages[0].role == "system"

    state.add_user_message("Hello")
    assert len(state.messages) == 2
    assert state.messages[1].role == "user"
    assert state.messages[1].content == "Hello"

    response = CompletionResponse(
        content="Hi there",
        tool_calls=[ToolCall(id="call_1", name="test", arguments={})],
    )
    state.add_assistant_message(response)
    assert len(state.messages) == 3
    assert state.messages[2].role == "assistant"
    assert state.messages[2].tool_calls is not None

    state.add_tool_result("call_1", "test", "result")
    assert len(state.messages) == 4
    assert state.messages[3].role == "tool"
    assert state.messages[3].tool_call_id == "call_1"
