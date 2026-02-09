"""Tests for agent with memory integration."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from harombe.agent.loop import Agent
from harombe.llm.client import CompletionResponse, Message
from harombe.memory.manager import MemoryManager


@pytest.fixture
def memory_manager():
    """Create a temporary memory manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        yield MemoryManager(storage_path=db_path)


@pytest.fixture
def mock_llm():
    """Create a mock LLM client."""
    llm = AsyncMock()
    llm.complete = AsyncMock()
    return llm


@pytest.mark.asyncio
async def test_agent_without_memory(mock_llm):
    """Test agent works without memory (backward compatibility)."""
    mock_llm.complete.return_value = CompletionResponse(
        content="Hello! How can I help?", tool_calls=None
    )

    agent = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
    )

    response = await agent.run("Hello")
    assert response == "Hello! How can I help?"
    assert mock_llm.complete.called


@pytest.mark.asyncio
async def test_agent_with_memory_new_session(mock_llm, memory_manager):
    """Test agent with memory creates new session."""
    mock_llm.complete.return_value = CompletionResponse(content="Hi there!", tool_calls=None)

    session_id = "test-session-1"
    memory_manager.create_session(
        session_id=session_id,
        system_prompt="You are helpful.",
    )

    agent = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=session_id,
    )

    response = await agent.run("Hello")
    assert response == "Hi there!"

    # Check messages were saved
    history = memory_manager.load_history(session_id)
    assert len(history) >= 2  # At least user + assistant messages
    assert any(msg.role == "user" and msg.content == "Hello" for msg in history)
    assert any(msg.role == "assistant" and msg.content == "Hi there!" for msg in history)


@pytest.mark.asyncio
async def test_agent_loads_conversation_history(mock_llm, memory_manager):
    """Test agent loads previous conversation history."""
    session_id = "test-session-2"
    memory_manager.create_session(
        session_id=session_id,
        system_prompt="You are helpful.",
    )

    # Simulate previous conversation
    memory_manager.save_message(session_id, Message(role="user", content="What is 2+2?"))
    memory_manager.save_message(session_id, Message(role="assistant", content="2+2 equals 4."))

    # Mock response that shows it has context
    mock_llm.complete.return_value = CompletionResponse(
        content="Yes, I remember telling you that 2+2 equals 4.",
        tool_calls=None,
    )

    agent = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=session_id,
    )

    await agent.run("Do you remember what I asked before?")

    # Check that LLM was called with history
    call_args = mock_llm.complete.call_args
    messages = call_args.kwargs["messages"]

    # Should have loaded previous messages plus new user message
    assert len(messages) >= 3
    assert any(msg.content == "What is 2+2?" for msg in messages)
    assert any(msg.content == "2+2 equals 4." for msg in messages)
    assert any(msg.content == "Do you remember what I asked before?" for msg in messages)


@pytest.mark.asyncio
async def test_agent_memory_persistence_across_runs(mock_llm, memory_manager):
    """Test conversation persists across multiple agent runs."""
    session_id = "test-session-3"
    memory_manager.create_session(
        session_id=session_id,
        system_prompt="You are helpful.",
    )

    # First run
    mock_llm.complete.return_value = CompletionResponse(
        content="My name is Alice.", tool_calls=None
    )

    agent1 = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=session_id,
    )

    await agent1.run("What is your name?")

    # Second run (new agent instance, same session)
    mock_llm.complete.return_value = CompletionResponse(content="Yes, I'm Alice!", tool_calls=None)

    agent2 = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=session_id,
    )

    await agent2.run("Are you Alice?")

    # Check complete history
    history = memory_manager.load_history(session_id)

    user_messages = [msg for msg in history if msg.role == "user"]
    assert len(user_messages) == 2
    assert user_messages[0].content == "What is your name?"
    assert user_messages[1].content == "Are you Alice?"


@pytest.mark.asyncio
async def test_agent_without_session_id_no_memory(mock_llm, memory_manager):
    """Test agent with memory manager but no session ID doesn't save."""
    mock_llm.complete.return_value = CompletionResponse(content="Hello!", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=None,  # No session ID
    )

    await agent.run("Hi")

    # No session should be created automatically
    sessions = memory_manager.list_sessions()
    assert len(sessions) == 0


@pytest.mark.asyncio
async def test_agent_empty_session_starts_fresh(mock_llm, memory_manager):
    """Test agent with new session starts with clean state."""
    session_id = "test-session-4"
    memory_manager.create_session(
        session_id=session_id,
        system_prompt="You are helpful.",
    )

    mock_llm.complete.return_value = CompletionResponse(content="Hi!", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        system_prompt="You are helpful.",
        memory_manager=memory_manager,
        session_id=session_id,
    )

    await agent.run("Hello")

    # First message should be from this run
    history = memory_manager.load_history(session_id)
    user_msgs = [m for m in history if m.role == "user"]
    assert len(user_msgs) == 1
    assert user_msgs[0].content == "Hello"
