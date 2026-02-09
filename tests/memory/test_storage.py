"""Tests for memory storage backend."""

import tempfile
from pathlib import Path

import pytest

from harombe.memory.schema import MessageRecord, SessionMetadata
from harombe.memory.storage import MemoryStorage


@pytest.fixture
def storage():
    """Create a temporary storage instance for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        yield MemoryStorage(db_path)


def test_initialize_db(storage):
    """Test database initialization creates tables."""
    assert storage.db_path.exists()


def test_create_session(storage):
    """Test session creation."""
    session = storage.create_session(
        session_id="test-session-1",
        system_prompt="You are a helpful assistant.",
        metadata=SessionMetadata(user="testuser", tags=["test"]),
    )

    assert session.id == "test-session-1"
    assert session.system_prompt == "You are a helpful assistant."
    assert session.metadata.user == "testuser"
    assert "test" in session.metadata.tags


def test_get_session(storage):
    """Test session retrieval."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="You are a helper.",
    )

    session = storage.get_session("test-session-1")
    assert session is not None
    assert session.id == "test-session-1"
    assert session.system_prompt == "You are a helper."


def test_get_nonexistent_session(storage):
    """Test getting a session that doesn't exist."""
    session = storage.get_session("nonexistent")
    assert session is None


def test_save_and_load_messages(storage):
    """Test saving and loading messages."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="System prompt",
    )

    # Save messages
    msg1 = MessageRecord(
        session_id="test-session-1",
        role="user",
        content="Hello",
    )
    msg2 = MessageRecord(
        session_id="test-session-1",
        role="assistant",
        content="Hi there!",
    )

    id1 = storage.save_message(msg1)
    id2 = storage.save_message(msg2)

    assert id1 > 0
    assert id2 > id1

    # Load messages
    messages = storage.load_messages("test-session-1")
    assert len(messages) == 2
    assert messages[0].role == "user"
    assert messages[0].content == "Hello"
    assert messages[1].role == "assistant"
    assert messages[1].content == "Hi there!"


def test_load_messages_with_limit(storage):
    """Test loading messages with limit and offset."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="System prompt",
    )

    # Save multiple messages
    for i in range(10):
        storage.save_message(
            MessageRecord(
                session_id="test-session-1",
                role="user",
                content=f"Message {i}",
            )
        )

    # Load with limit
    messages = storage.load_messages("test-session-1", limit=5)
    assert len(messages) == 5
    assert messages[0].content == "Message 0"

    # Load with offset
    messages = storage.load_messages("test-session-1", limit=5, offset=5)
    assert len(messages) == 5
    assert messages[0].content == "Message 5"


def test_get_message_count(storage):
    """Test message count."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="System prompt",
    )

    # Initially zero
    count = storage.get_message_count("test-session-1")
    assert count == 0

    # Add messages
    for i in range(5):
        storage.save_message(
            MessageRecord(
                session_id="test-session-1",
                role="user",
                content=f"Message {i}",
            )
        )

    count = storage.get_message_count("test-session-1")
    assert count == 5


def test_list_sessions(storage):
    """Test listing sessions."""
    # Create multiple sessions
    for i in range(5):
        storage.create_session(
            session_id=f"session-{i}",
            system_prompt="Prompt",
        )

    # List all
    sessions = storage.list_sessions(limit=10)
    assert len(sessions) == 5

    # List with limit
    sessions = storage.list_sessions(limit=3)
    assert len(sessions) == 3


def test_delete_session(storage):
    """Test session deletion."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="Prompt",
    )

    # Verify it exists
    session = storage.get_session("test-session-1")
    assert session is not None

    # Delete it
    deleted = storage.delete_session("test-session-1")
    assert deleted is True

    # Verify it's gone
    session = storage.get_session("test-session-1")
    assert session is None


def test_delete_nonexistent_session(storage):
    """Test deleting a session that doesn't exist."""
    deleted = storage.delete_session("nonexistent")
    assert deleted is False


def test_clear_messages(storage):
    """Test clearing messages from a session."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="Prompt",
    )

    # Add messages
    for i in range(5):
        storage.save_message(
            MessageRecord(
                session_id="test-session-1",
                role="user",
                content=f"Message {i}",
            )
        )

    # Clear messages
    count = storage.clear_messages("test-session-1")
    assert count == 5

    # Verify messages are gone
    messages = storage.load_messages("test-session-1")
    assert len(messages) == 0

    # Session still exists
    session = storage.get_session("test-session-1")
    assert session is not None


def test_update_session_activity(storage):
    """Test session activity timestamp updates."""
    storage.create_session(
        session_id="test-session-1",
        system_prompt="Prompt",
    )

    session1 = storage.get_session("test-session-1")
    original_updated = session1.updated_at

    # Save a message (should update activity)
    storage.save_message(
        MessageRecord(
            session_id="test-session-1",
            role="user",
            content="Test",
        )
    )

    session2 = storage.get_session("test-session-1")
    assert session2.updated_at > original_updated
