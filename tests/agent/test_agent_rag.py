"""Tests for agent with RAG (Retrieval-Augmented Generation)."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from harombe.agent.loop import Agent
from harombe.embeddings.sentence_transformer import SentenceTransformerEmbedding
from harombe.llm.client import CompletionResponse, Message
from harombe.memory.manager import MemoryManager
from harombe.vector.chromadb import ChromaDBVectorStore


@pytest.fixture
def mock_llm():
    """Create a mock LLM client."""
    llm = AsyncMock()
    llm.complete = AsyncMock()
    return llm


@pytest.fixture
def semantic_memory():
    """Create memory manager with semantic search."""
    import uuid

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"

        embedding_client = SentenceTransformerEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            device="cpu",
        )

        collection_name = f"test_rag_{uuid.uuid4().hex[:8]}"
        vector_store = ChromaDBVectorStore(collection_name=collection_name)

        manager = MemoryManager(
            storage_path=db_path,
            max_history_tokens=4096,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        yield manager


@pytest.mark.asyncio
async def test_agent_without_rag(mock_llm, semantic_memory):
    """Test that agent works without RAG (backward compatibility)."""
    mock_llm.complete.return_value = CompletionResponse(
        content="Hello! How can I help?", tool_calls=None
    )

    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=False,  # RAG disabled
    )

    response = await agent.run("Hello")
    assert response == "Hello! How can I help?"


@pytest.mark.asyncio
async def test_agent_with_rag_no_context(mock_llm, semantic_memory):
    """Test agent with RAG when no relevant context exists."""
    mock_llm.complete.return_value = CompletionResponse(
        content="I don't have context for that.", tool_calls=None
    )

    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
        rag_top_k=3,
        rag_min_similarity=0.7,
    )

    # No messages in history yet
    response = await agent.run("Hello")
    assert response == "I don't have context for that."

    # Should have been called with user message (no context to inject)
    call_args = mock_llm.complete.call_args
    messages = call_args.kwargs["messages"]
    user_msg = [m for m in messages if m.role == "user"][-1]
    assert "RELEVANT CONTEXT" not in user_msg.content


@pytest.mark.asyncio
async def test_agent_with_rag_injects_context(mock_llm, semantic_memory):
    """Test that agent with RAG injects relevant context."""
    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    # Populate memory with some messages
    semantic_memory.save_message(
        session_id, Message(role="user", content="Python is a programming language")
    )
    semantic_memory.save_message(
        session_id, Message(role="assistant", content="Yes, Python is great for data science")
    )
    semantic_memory.save_message(
        session_id, Message(role="user", content="How do I install numpy?")
    )
    semantic_memory.save_message(
        session_id, Message(role="assistant", content="Use pip install numpy")
    )

    # Wait a moment for embeddings to be processed (longer for CI)
    await asyncio.sleep(0.5)

    # Now ask a related question
    mock_llm.complete.return_value = CompletionResponse(
        content="You can install packages with pip.", tool_calls=None
    )

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
        rag_top_k=3,
        rag_min_similarity=0.5,  # Lower threshold for test
    )

    response = await agent.run("How do I install Python packages?")
    assert response == "You can install packages with pip."

    # Check that context was injected
    call_args = mock_llm.complete.call_args
    messages = call_args.kwargs["messages"]
    user_msg = [m for m in messages if m.role == "user"][-1]

    # Should have context section
    assert "RELEVANT CONTEXT" in user_msg.content
    assert "USER QUESTION" in user_msg.content


@pytest.mark.asyncio
async def test_rag_context_formatting(mock_llm, semantic_memory):
    """Test that RAG context is properly formatted."""
    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    # Add a message
    semantic_memory.save_message(
        session_id, Message(role="assistant", content="Python is easy to learn")
    )

    await asyncio.sleep(0.5)

    mock_llm.complete.return_value = CompletionResponse(content="Response", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
        rag_top_k=5,
        rag_min_similarity=0.3,
    )

    await agent.run("Tell me about Python")

    # Verify format
    call_args = mock_llm.complete.call_args
    messages = call_args.kwargs["messages"]
    user_msg = [m for m in messages if m.role == "user"][-1]

    assert "---" in user_msg.content  # Separator
    assert "[ASSISTANT]" in user_msg.content  # Role label
    assert "USER QUESTION:" in user_msg.content


@pytest.mark.asyncio
async def test_rag_saves_original_message(mock_llm, semantic_memory):
    """Test that RAG saves original message without context."""
    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    # Add existing message
    semantic_memory.save_message(session_id, Message(role="user", content="Python programming"))

    await asyncio.sleep(0.5)

    mock_llm.complete.return_value = CompletionResponse(content="Response", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
    )

    await agent.run("What is Python?")

    # Check saved messages
    history = semantic_memory.load_history(session_id)
    user_messages = [m for m in history if m.role == "user"]

    # Latest user message should be the original (without RAG context)
    last_user_msg = user_messages[-1]
    assert last_user_msg.content == "What is Python?"
    assert "RELEVANT CONTEXT" not in last_user_msg.content


@pytest.mark.asyncio
async def test_rag_with_top_k_limit(mock_llm, semantic_memory):
    """Test that RAG respects top_k limit."""
    session_id = semantic_memory.create_session(system_prompt="You are helpful.")

    # Add many messages
    for i in range(10):
        semantic_memory.save_message(
            session_id, Message(role="user", content=f"Python message {i}")
        )

    await asyncio.sleep(0.5)

    mock_llm.complete.return_value = CompletionResponse(content="Response", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
        rag_top_k=3,  # Limit to 3
        rag_min_similarity=0.0,  # Get all matches
    )

    await agent.run("Tell me about Python")

    # Count context messages in formatted message
    call_args = mock_llm.complete.call_args
    messages = call_args.kwargs["messages"]
    user_msg = [m for m in messages if m.role == "user"][-1]

    # Should have at most 3 context messages
    context_count = user_msg.content.count("[USER]")
    assert context_count <= 3


@pytest.mark.asyncio
async def test_rag_without_semantic_memory(mock_llm):
    """Test that RAG gracefully handles no semantic memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"

        # Memory manager WITHOUT embedding/vector store
        memory = MemoryManager(storage_path=db_path)

        mock_llm.complete.return_value = CompletionResponse(content="Response", tool_calls=None)

        session_id = memory.create_session(system_prompt="Test")

        agent = Agent(
            llm=mock_llm,
            tools=[],
            memory_manager=memory,
            session_id=session_id,
            enable_rag=True,  # RAG enabled but no semantic search available
        )

        # Should work without errors
        response = await agent.run("Hello")
        assert response == "Response"


@pytest.mark.asyncio
async def test_rag_error_handling(mock_llm, semantic_memory):
    """Test that RAG errors don't break agent execution."""
    session_id = semantic_memory.create_session(system_prompt="Test")

    mock_llm.complete.return_value = CompletionResponse(content="Response", tool_calls=None)

    agent = Agent(
        llm=mock_llm,
        tools=[],
        memory_manager=semantic_memory,
        session_id=session_id,
        enable_rag=True,
    )

    # Should handle gracefully even if retrieval fails
    response = await agent.run("Test query")
    assert response == "Response"
