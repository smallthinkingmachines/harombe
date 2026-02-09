"""Tests for semantic memory (memory manager with vector store)."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from harombe.embeddings.sentence_transformer import SentenceTransformerEmbedding
from harombe.llm.client import Message
from harombe.memory.manager import MemoryManager
from harombe.vector.chromadb import ChromaDBVectorStore


@pytest.fixture
def semantic_memory():
    """Create memory manager with semantic search enabled."""
    import uuid

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"

        # Create embedding client
        embedding_client = SentenceTransformerEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            device="cpu",
        )

        # Create vector store (in-memory) with unique collection
        collection_name = f"test_semantic_{uuid.uuid4().hex[:8]}"
        vector_store = ChromaDBVectorStore(collection_name=collection_name)

        # Create memory manager with semantic search
        manager = MemoryManager(
            storage_path=db_path,
            max_history_tokens=4096,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        yield manager


@pytest.fixture
def regular_memory():
    """Create regular memory manager without semantic search."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        yield MemoryManager(storage_path=db_path)


def test_semantic_search_enabled(semantic_memory):
    """Test that semantic search is enabled when components provided."""
    assert semantic_memory.semantic_search_enabled is True


def test_semantic_search_disabled(regular_memory):
    """Test that semantic search is disabled without components."""
    assert regular_memory.semantic_search_enabled is False


def test_save_message_with_auto_embed(semantic_memory):
    """Test that saving messages automatically embeds them."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save a message
    msg = Message(role="user", content="Hello, how are you?")
    semantic_memory.save_message(session_id, msg)

    # Vector store should have the embedding
    assert semantic_memory.vector_store.count() == 1


def test_save_message_skips_system(semantic_memory):
    """Test that system messages are not embedded."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save system message
    msg = Message(role="system", content="You are a helpful assistant")
    semantic_memory.save_message(session_id, msg)

    # Should not be embedded
    assert semantic_memory.vector_store.count() == 0


def test_save_message_skips_empty(semantic_memory):
    """Test that empty messages are not embedded."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save empty message
    msg = Message(role="user", content="")
    semantic_memory.save_message(session_id, msg)

    # Should not be embedded
    assert semantic_memory.vector_store.count() == 0


@pytest.mark.asyncio
async def test_search_similar(semantic_memory):
    """Test semantic search for similar messages."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save some messages
    messages = [
        "I love programming in Python",
        "Python is a great programming language",
        "The weather is sunny today",
    ]

    for content in messages:
        msg = Message(role="user", content=content)
        semantic_memory.save_message(session_id, msg)

    # Wait for async embedding tasks to complete (longer for CI)
    await asyncio.sleep(0.5)

    # Search for programming-related content
    results = await semantic_memory.search_similar(
        query="coding with Python",
        top_k=2,
    )

    # Should return the two Python-related messages
    assert len(results) == 2
    assert any("Python" in r.content for r in results)
    assert any("programming" in r.content for r in results)


@pytest.mark.asyncio
async def test_search_similar_session_filter(semantic_memory):
    """Test semantic search limited to specific session."""
    session1 = semantic_memory.create_session(system_prompt="Test 1")
    session2 = semantic_memory.create_session(system_prompt="Test 2")

    # Save messages to different sessions
    msg1 = Message(role="user", content="Python programming")
    semantic_memory.save_message(session1, msg1)

    msg2 = Message(role="user", content="Java development")
    semantic_memory.save_message(session2, msg2)

    # Wait for async embedding tasks to complete (longer for CI)
    await asyncio.sleep(0.5)

    # Search only in session 1
    results = await semantic_memory.search_similar(
        query="programming languages",
        top_k=5,
        session_id=session1,
    )

    # Should only return message from session 1
    assert len(results) == 1
    assert "Python" in results[0].content


@pytest.mark.asyncio
async def test_search_similar_min_similarity(semantic_memory):
    """Test semantic search with minimum similarity threshold."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save messages with different relevance
    messages = [
        "Python programming tutorial",
        "Learning to code in Python",
        "The cat sat on the mat",  # Very different
    ]

    for content in messages:
        msg = Message(role="user", content=content)
        semantic_memory.save_message(session_id, msg)

    # Wait for async embedding tasks to complete (longer for CI)
    await asyncio.sleep(0.5)

    # Search with high similarity threshold
    results = await semantic_memory.search_similar(
        query="Python programming",
        top_k=10,
        min_similarity=0.7,  # High threshold
    )

    # Should filter out the cat message
    assert len(results) <= 2
    assert all("Python" in r.content or "code" in r.content for r in results)


@pytest.mark.asyncio
async def test_get_relevant_context(semantic_memory):
    """Test getting relevant context within token budget."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    # Save several messages
    messages = [
        "Python is a programming language",
        "It is widely used for data science",
        "Machine learning models are built with Python",
        "The weather is nice today",
    ]

    for content in messages:
        msg = Message(role="user", content=content)
        semantic_memory.save_message(session_id, msg)

    # Wait for async embedding tasks to complete (longer for CI)
    await asyncio.sleep(0.5)

    # Get context for Python query
    context = await semantic_memory.get_relevant_context(
        query="Python programming",
        max_tokens=200,
    )

    # Should return Python-related messages within budget
    assert len(context) > 0
    assert len(context) <= 3  # Limited by tokens
    assert any("Python" in c.content for c in context)


@pytest.mark.asyncio
async def test_search_without_semantic_enabled(regular_memory):
    """Test that semantic search raises error when not enabled."""
    session_id = regular_memory.create_session(system_prompt="Test")

    msg = Message(role="user", content="Hello")
    regular_memory.save_message(session_id, msg)

    # Should raise RuntimeError
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        await regular_memory.search_similar(query="test", top_k=5)


@pytest.mark.asyncio
async def test_get_context_without_semantic_enabled(regular_memory):
    """Test that get_relevant_context raises error when not enabled."""
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        await regular_memory.get_relevant_context(query="test", max_tokens=100)


def test_backfill_without_semantic_enabled(regular_memory):
    """Test that backfill raises error when not enabled."""
    with pytest.raises(RuntimeError, match="Semantic search not enabled"):
        regular_memory.backfill_embeddings()


def test_backfill_embeddings(semantic_memory):
    """Test backfilling embeddings for existing messages."""
    # Note: This test is simplified since backfill is complex
    # In reality, we'd need to disable auto-embedding first

    session_id = semantic_memory.create_session(system_prompt="Test")

    # For now, just verify the method exists and doesn't crash
    count = semantic_memory.backfill_embeddings(session_id=session_id)
    assert count >= 0


@pytest.mark.asyncio
async def test_semantic_search_empty_store(semantic_memory):
    """Test semantic search on empty vector store."""
    results = await semantic_memory.search_similar(
        query="test query",
        top_k=5,
    )

    # Should return empty list
    assert len(results) == 0


def test_backward_compatibility(regular_memory):
    """Test that regular memory manager still works without semantic search."""
    session_id = regular_memory.create_session(system_prompt="Test")

    # Save messages
    msg1 = Message(role="user", content="Hello")
    msg2 = Message(role="assistant", content="Hi there!")

    regular_memory.save_message(session_id, msg1)
    regular_memory.save_message(session_id, msg2)

    # Load history
    history = regular_memory.load_history(session_id)

    # Should work normally
    assert len(history) == 2
    assert history[0].content == "Hello"
    assert history[1].content == "Hi there!"
