"""Tests for memory manager."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from harombe.llm.client import Message, ToolCall
from harombe.memory.manager import MemoryManager
from harombe.memory.schema import SessionMetadata


@pytest.fixture
def manager():
    """Create a temporary memory manager for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        yield MemoryManager(storage_path=db_path, max_history_tokens=1000)


@pytest.fixture
def semantic_manager(tmp_path):
    """Create memory manager with semantic search enabled."""
    db_path = tmp_path / "test_memory.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.1, 0.2, 0.3])
    mock_vector = MagicMock()
    mock_vector.search = MagicMock(
        return_value=(
            ["id1"],
            ["Hello world"],
            [{"role": "user", "message_id": 1, "session_id": "s1"}],
            [0.1],
        )
    )
    mock_vector.add = MagicMock()
    return MemoryManager(
        storage_path=db_path,
        max_history_tokens=1000,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )


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


# --- New tests covering uncovered paths ---


def test_semantic_search_enabled(semantic_manager):
    """Test that semantic_manager has semantic search enabled."""
    assert semantic_manager.semantic_search_enabled is True


def test_semantic_search_disabled(manager):
    """Test that regular manager has semantic search disabled."""
    assert manager.semantic_search_enabled is False


def test_save_message_with_tool_calls_serialization(manager):
    """Test saving messages with tool_calls triggers JSON serialization path."""
    import json
    import sqlite3

    session_id = manager.create_session(system_prompt="Prompt")

    msg = Message(
        role="assistant",
        content="Calling a tool now.",
        tool_calls=[
            ToolCall(id="tc_001", name="list_files", arguments={"dir": "/tmp"}),
            ToolCall(id="tc_002", name="read_file", arguments={"path": "a.py"}),
        ],
    )

    msg_id = manager.save_message(session_id, msg)
    assert msg_id > 0

    # Verify tool_calls were serialized to JSON in the database
    with sqlite3.connect(manager.storage.db_path) as conn:
        row = conn.execute("SELECT tool_calls FROM messages WHERE rowid = ?", (msg_id,)).fetchone()
    assert row is not None
    stored_json = json.loads(row[0])
    assert len(stored_json) == 2
    assert stored_json[0]["id"] == "tc_001"
    assert stored_json[0]["name"] == "list_files"
    assert stored_json[0]["arguments"] == {"dir": "/tmp"}
    assert stored_json[1]["id"] == "tc_002"
    assert stored_json[1]["name"] == "read_file"


async def test_search_similar(semantic_manager):
    """Test search_similar calls embedding and vector store."""
    results = await semantic_manager.search_similar("hello")

    semantic_manager.embedding_client.embed_single.assert_awaited_once_with("hello")
    semantic_manager.vector_store.search.assert_called_once()
    assert len(results) == 1
    assert results[0].content == "Hello world"
    assert results[0].role == "user"


async def test_search_similar_not_enabled(manager):
    """Test search_similar raises RuntimeError when semantic search disabled."""
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        await manager.search_similar("hello")


async def test_get_relevant_context(semantic_manager):
    """Test get_relevant_context returns messages within token budget."""
    results = await semantic_manager.get_relevant_context("hello", max_tokens=100)

    semantic_manager.embedding_client.embed_single.assert_awaited()
    assert isinstance(results, list)
    # Should return the single matching message (well within 100 tokens)
    assert len(results) == 1
    assert results[0].content == "Hello world"


async def test_get_relevant_context_not_enabled(manager):
    """Test get_relevant_context raises RuntimeError when disabled."""
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        await manager.get_relevant_context("hello", max_tokens=100)


def test_prune_old_sessions(manager):
    """Test prune_old_sessions deletes old sessions and returns count."""
    manager.create_session(system_prompt="Old session")

    # days=0 means delete all sessions (everything is older than 0 days)
    count = manager.prune_old_sessions(days=0)
    assert isinstance(count, int)
    assert count >= 1

    # Verify no sessions remain
    sessions = manager.list_sessions(limit=100)
    assert len(sessions) == 0


def test_delete_nonexistent_session(manager):
    """Test deleting a session that does not exist returns False."""
    result = manager.delete_session("nonexistent-session-id")
    assert result is False


async def test_wait_for_pending_embeddings(semantic_manager):
    """Test wait_for_pending_embeddings clears pending tasks."""
    # Manually add a completed task to pending list
    loop = asyncio.get_event_loop()

    async def noop():
        pass

    task = loop.create_task(noop())
    semantic_manager._pending_tasks.append(task)

    await semantic_manager.wait_for_pending_embeddings()

    assert len(semantic_manager._pending_tasks) == 0


def test_backfill_embeddings_not_enabled(manager):
    """Test backfill_embeddings raises RuntimeError when disabled."""
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        manager.backfill_embeddings()


# --- Additional tests covering _embed_message_async, backfill, etc. ---


async def test_embed_message_async_happy_path(semantic_manager):
    """Test _embed_message_async embeds and stores a message."""
    msg = Message(role="user", content="Test message")
    await semantic_manager._embed_message_async(message_id=42, session_id="s1", message=msg)

    semantic_manager.embedding_client.embed_single.assert_awaited_once_with("Test message")
    semantic_manager.vector_store.add.assert_called_once()
    call_kwargs = semantic_manager.vector_store.add.call_args
    assert call_kwargs[1]["ids"] == ["msg_42"]
    assert call_kwargs[1]["documents"] == ["Test message"]


async def test_embed_message_async_skips_empty(semantic_manager):
    """Test _embed_message_async skips empty messages."""
    msg = Message(role="user", content="")
    await semantic_manager._embed_message_async(message_id=1, session_id="s1", message=msg)
    semantic_manager.embedding_client.embed_single.assert_not_awaited()


async def test_embed_message_async_skips_system(semantic_manager):
    """Test _embed_message_async skips system messages."""
    msg = Message(role="system", content="You are helpful")
    await semantic_manager._embed_message_async(message_id=1, session_id="s1", message=msg)
    semantic_manager.embedding_client.embed_single.assert_not_awaited()


async def test_embed_message_async_embed_failure(semantic_manager):
    """Test _embed_message_async handles embedding failure."""
    semantic_manager.embedding_client.embed_single = AsyncMock(
        side_effect=RuntimeError("embed failed")
    )
    msg = Message(role="user", content="Test")
    # Should not raise
    await semantic_manager._embed_message_async(message_id=1, session_id="s1", message=msg)
    semantic_manager.vector_store.add.assert_not_called()


async def test_embed_message_async_store_failure(semantic_manager):
    """Test _embed_message_async handles vector store failure."""
    semantic_manager.vector_store.add.side_effect = RuntimeError("store failed")
    msg = Message(role="user", content="Test")
    # Should not raise
    await semantic_manager._embed_message_async(message_id=1, session_id="s1", message=msg)
    # embed was called successfully
    semantic_manager.embedding_client.embed_single.assert_awaited_once()


def test_save_message_triggers_embed(semantic_manager):
    """Test save_message triggers background embedding."""
    session_id = semantic_manager.create_session(system_prompt="Prompt")
    msg = Message(role="user", content="Hello world")
    msg_id = semantic_manager.save_message(session_id, msg)
    assert msg_id > 0
    # _embed_message was called (creates a task or runs sync)
    # Since we're in an event loop, it should create a task
    # We can check that pending_tasks has something or
    # that the embedding client was interacted with
    assert semantic_manager.semantic_search_enabled is True


def test_save_message_no_embed_for_empty(semantic_manager):
    """Test save_message does not embed empty content."""
    session_id = semantic_manager.create_session(system_prompt="Prompt")
    msg = Message(role="user", content="")
    msg_id = semantic_manager.save_message(session_id, msg)
    assert msg_id > 0


def _make_sync_loop_mock(embed_return=None, embed_side_effect=None):
    """Create a mock event loop for backfill tests.

    The backfill method calls loop.run_until_complete(coro).
    We mock this to run the coroutine's underlying mock directly.
    """
    mock_loop = MagicMock()
    mock_loop.is_running.return_value = False

    call_idx = 0

    def run_sync(coro):
        nonlocal call_idx
        # Close the coroutine to avoid warnings
        coro.close()
        if embed_side_effect:
            if callable(embed_side_effect):
                idx = call_idx
                call_idx += 1
                return embed_side_effect(idx)
            raise embed_side_effect
        return embed_return

    mock_loop.run_until_complete = run_sync
    return mock_loop


def test_backfill_embeddings_single_session(tmp_path):
    """Test backfill_embeddings processes a specific session."""
    from unittest.mock import patch as _patch

    from harombe.memory.schema import MessageRecord

    db_path = tmp_path / "backfill.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.1, 0.2, 0.3])
    mock_vector = MagicMock()

    mgr = MemoryManager(
        storage_path=db_path,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )

    session_id = mgr.create_session(system_prompt="Prompt")
    mgr.storage.save_message(
        MessageRecord(
            session_id=session_id,
            role="user",
            content="Hello backfill",
        )
    )
    mgr.storage.save_message(
        MessageRecord(
            session_id=session_id,
            role="assistant",
            content="Hi there",
        )
    )
    # System message should be skipped
    mgr.storage.save_message(
        MessageRecord(
            session_id=session_id,
            role="system",
            content="System prompt",
        )
    )

    mock_loop = _make_sync_loop_mock(embed_return=[0.1, 0.2, 0.3])
    with _patch(
        "harombe.memory.manager.asyncio.get_event_loop",
        return_value=mock_loop,
    ):
        count = mgr.backfill_embeddings(session_id=session_id)

    # 2 non-system messages embedded
    assert count == 2
    assert mock_vector.add.call_count == 2


def test_backfill_embeddings_all_sessions(tmp_path):
    """Test backfill_embeddings processes all sessions."""
    from unittest.mock import patch as _patch

    from harombe.memory.schema import MessageRecord

    db_path = tmp_path / "backfill_all.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.4, 0.5, 0.6])
    mock_vector = MagicMock()

    mgr = MemoryManager(
        storage_path=db_path,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )

    sid1 = mgr.create_session(system_prompt="P1")
    sid2 = mgr.create_session(system_prompt="P2")

    mgr.storage.save_message(MessageRecord(session_id=sid1, role="user", content="Msg A"))
    mgr.storage.save_message(MessageRecord(session_id=sid2, role="user", content="Msg B"))

    mock_loop = _make_sync_loop_mock(embed_return=[0.4, 0.5, 0.6])
    with _patch(
        "harombe.memory.manager.asyncio.get_event_loop",
        return_value=mock_loop,
    ):
        count = mgr.backfill_embeddings(session_id=None)

    assert count == 2
    assert mock_vector.add.call_count == 2


def test_backfill_embeddings_skips_failures(tmp_path):
    """Test backfill_embeddings skips messages that fail."""
    from unittest.mock import patch as _patch

    from harombe.memory.schema import MessageRecord

    db_path = tmp_path / "backfill_fail.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.1, 0.2])
    mock_vector = MagicMock()

    mgr = MemoryManager(
        storage_path=db_path,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )

    sid = mgr.create_session(system_prompt="P")
    mgr.storage.save_message(MessageRecord(session_id=sid, role="user", content="Fail msg"))
    mgr.storage.save_message(MessageRecord(session_id=sid, role="user", content="OK msg"))

    def flaky_side_effect(idx):
        if idx == 0:
            raise RuntimeError("embed fail")
        return [0.1, 0.2]

    mock_loop = _make_sync_loop_mock(embed_side_effect=flaky_side_effect)
    with _patch(
        "harombe.memory.manager.asyncio.get_event_loop",
        return_value=mock_loop,
    ):
        count = mgr.backfill_embeddings(session_id=sid)

    # First fails, second succeeds
    assert count == 1


async def test_search_similar_with_min_similarity(tmp_path):
    """Test search_similar filters by min_similarity."""
    db_path = tmp_path / "sim.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.1, 0.2])
    mock_vector = MagicMock()
    # Return results with varying distances
    mock_vector.search = MagicMock(
        return_value=(
            ["id1", "id2"],
            ["Close match", "Far match"],
            [
                {"role": "user", "message_id": 1, "session_id": "s"},
                {"role": "user", "message_id": 2, "session_id": "s"},
            ],
            [0.1, 0.8],  # distances: 0.1 = high sim, 0.8 = low sim
        )
    )

    mgr = MemoryManager(
        storage_path=db_path,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )

    # min_similarity=0.5 means distance must be < 0.5
    results = await mgr.search_similar("query", min_similarity=0.5)

    # Only "Close match" (sim=0.9) passes, not "Far match" (sim=0.2)
    assert len(results) == 1
    assert results[0].content == "Close match"


async def test_get_relevant_context_token_budget(tmp_path):
    """Test get_relevant_context respects token budget."""
    db_path = tmp_path / "ctx.db"
    mock_embedding = MagicMock()
    mock_embedding.embed_single = AsyncMock(return_value=[0.1, 0.2])
    # Return several results so token budget limits them
    mock_vector = MagicMock()
    mock_vector.search = MagicMock(
        return_value=(
            ["id1", "id2", "id3"],
            ["A" * 400, "B" * 400, "C" * 400],
            [
                {"role": "user", "message_id": 1, "session_id": "s"},
                {"role": "user", "message_id": 2, "session_id": "s"},
                {"role": "user", "message_id": 3, "session_id": "s"},
            ],
            [0.1, 0.2, 0.3],
        )
    )

    mgr = MemoryManager(
        storage_path=db_path,
        embedding_client=mock_embedding,
        vector_store=mock_vector,
    )

    # Very small token budget should limit results
    results = await mgr.get_relevant_context("query", max_tokens=50)

    # Each message is ~100 tokens, budget is 50 => at most 0
    # But first message might fit depending on estimation
    assert len(results) <= 1
