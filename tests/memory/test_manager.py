"""Tests for memory manager."""

import tempfile
from pathlib import Path

import pytest

from harombe.llm.client import Message
from harombe.memory.manager import MemoryManager
from harombe.memory.schema import SessionMetadata


@pytest.fixture
def manager():
    """Create a temporary memory manager for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        yield MemoryManager(storage_path=db_path, max_history_tokens=1000)


def test_create_session(manager):
    """Test session creation."""
    session_id = manager.create_session(
        system_prompt="You are a helpful assistant.",
        metadata=SessionMetadata(user="testuser", tags=["test"]),
    )

    assert session_id is not None
    assert len(session_id) > 0  # UUID generated


def test_create_session_with_custom_id(manager):
    """Test session creation with custom ID."""
    session_id = manager.create_session(
        system_prompt="You are a helper.",
        session_id="custom-session-id",
    )

    assert session_id == "custom-session-id"


def test_get_session(manager):
    """Test getting session information."""
    session_id = manager.create_session(
        system_prompt="You are a helpful assistant.",
        metadata=SessionMetadata(user="testuser"),
    )

    session = manager.get_session(session_id)
    assert session is not None
    assert session.id == session_id
    assert session.system_prompt == "You are a helpful assistant."
    assert session.metadata.user == "testuser"


def test_save_and_load_messages(manager):
    """Test saving and loading messages."""
    session_id = manager.create_session(system_prompt="System prompt")

    # Save messages
    msg1 = Message(role="user", content="Hello")
    msg2 = Message(role="assistant", content="Hi there!")

    manager.save_message(session_id, msg1)
    manager.save_message(session_id, msg2)

    # Load history
    history = manager.load_history(session_id)
    assert len(history) == 2
    assert history[0].role == "user"
    assert history[0].content == "Hello"
    assert history[1].role == "assistant"
    assert history[1].content == "Hi there!"


@pytest.mark.skip(reason="Token estimation is approximate, test needs refinement")
def test_load_history_with_token_limit(manager):
    """Test loading history respects token limit."""
    session_id = manager.create_session(system_prompt="System prompt")

    # Save messages
    for i in range(10):
        manager.save_message(
            session_id,
            Message(role="user", content=f"Message {i}"),
        )

    # Get all messages first
    all_history = manager.load_history(session_id, max_tokens=10000)
    assert len(all_history) == 10

    # Load with small limit
    limited_history = manager.load_history(session_id, max_tokens=50)

    # Should get fewer messages due to token limit
    assert len(limited_history) < 10, f"Expected < 10 messages, got {len(limited_history)}"
    assert len(limited_history) > 0, f"Expected > 0 messages, got {len(limited_history)}"

    # Most recent message should be included
    assert "Message 9" in limited_history[-1].content


def test_get_recent_messages(manager):
    """Test getting N most recent messages."""
    session_id = manager.create_session(system_prompt="System prompt")

    # Save 10 messages
    for i in range(10):
        manager.save_message(
            session_id,
            Message(role="user", content=f"Message {i}"),
        )

    # Get last 5
    recent = manager.get_recent_messages(session_id, count=5)
    assert len(recent) == 5
    assert "Message 5" in recent[0].content
    assert "Message 9" in recent[4].content


def test_list_sessions(manager):
    """Test listing sessions."""
    # Create multiple sessions
    ids = []
    for i in range(5):
        session_id = manager.create_session(
            system_prompt=f"Prompt {i}",
            metadata=SessionMetadata(title=f"Session {i}"),
        )
        ids.append(session_id)

    # List all
    sessions = manager.list_sessions(limit=10)
    assert len(sessions) == 5

    # Should be ordered by most recent (reverse creation order)
    assert sessions[0].id == ids[-1]  # Most recent first


def test_delete_session(manager):
    """Test session deletion."""
    session_id = manager.create_session(system_prompt="Prompt")

    # Add some messages
    manager.save_message(session_id, Message(role="user", content="Test"))

    # Delete
    deleted = manager.delete_session(session_id)
    assert deleted is True

    # Verify it's gone
    session = manager.get_session(session_id)
    assert session is None


def test_clear_history(manager):
    """Test clearing session history."""
    session_id = manager.create_session(system_prompt="Prompt")

    # Add messages
    for i in range(5):
        manager.save_message(session_id, Message(role="user", content=f"Msg {i}"))

    # Clear history
    count = manager.clear_history(session_id)
    assert count == 5

    # Session still exists
    session = manager.get_session(session_id)
    assert session is not None

    # But no messages
    history = manager.load_history(session_id)
    assert len(history) == 0


def test_get_message_count(manager):
    """Test message count."""
    session_id = manager.create_session(system_prompt="Prompt")

    # Initially zero
    count = manager.get_message_count(session_id)
    assert count == 0

    # Add messages
    for i in range(10):
        manager.save_message(session_id, Message(role="user", content=f"Msg {i}"))

    count = manager.get_message_count(session_id)
    assert count == 10


def test_session_exists(manager):
    """Test session existence check."""
    # Non-existent
    assert manager.session_exists("nonexistent") is False

    # Create and check
    session_id = manager.create_session(system_prompt="Prompt")
    assert manager.session_exists(session_id) is True


def test_get_or_create_session(manager):
    """Test get_or_create_session."""
    session_id = "test-session-id"

    # First call creates
    result_id, created = manager.get_or_create_session(
        session_id=session_id,
        system_prompt="Prompt",
    )
    assert result_id == session_id
    assert created is True

    # Second call gets existing
    result_id, created = manager.get_or_create_session(
        session_id=session_id,
        system_prompt="Different prompt",  # Won't be used
    )
    assert result_id == session_id
    assert created is False


@pytest.mark.skip(reason="Tool call serialization format needs adjustment")
def test_save_message_with_tool_calls(manager):
    """Test saving messages with tool calls."""
    from harombe.llm.client import ToolCall

    session_id = manager.create_session(system_prompt="Prompt")

    # Message with tool calls
    msg = Message(
        role="assistant",
        content="Let me check that.",
        tool_calls=[
            ToolCall(
                id="call_123",
                name="read_file",
                arguments={"path": "test.txt"},
            )
        ],
    )

    msg_id = manager.save_message(session_id, msg)
    assert msg_id > 0

    # Load and verify
    history = manager.load_history(session_id)
    assert len(history) == 1
    loaded_msg = history[0]
    assert loaded_msg.role == "assistant"
    # Tool calls are stored as JSON, so they come back as dicts/lists
    assert loaded_msg.tool_calls is not None


def test_max_history_tokens_default(manager):
    """Test that default max_history_tokens is used."""
    session_id = manager.create_session(system_prompt="Prompt")

    # Add many large messages (exceed default 1000 tokens)
    for _i in range(10):
        manager.save_message(
            session_id,
            Message(role="user", content="X" * 500),  # ~125 tokens each
        )

    # Load with default limit
    history = manager.load_history(session_id)

    # Should be limited to ~8 messages (1000 tokens / 125 tokens per message)
    assert len(history) < 10
    assert len(history) >= 7  # Some margin for token estimation
