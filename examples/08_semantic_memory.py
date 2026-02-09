"""Example 08: Semantic Memory and RAG (Retrieval-Augmented Generation).

This example demonstrates:
1. Setting up semantic search with vector embeddings
2. Saving conversations that get automatically embedded
3. Searching for similar messages across conversations
4. Using RAG to enhance agent responses with relevant context
"""

import asyncio
import tempfile
from pathlib import Path

from harombe.agent.loop import Agent
from harombe.embeddings.sentence_transformer import SentenceTransformerEmbedding
from harombe.llm.client import Message
from harombe.llm.ollama import OllamaClient
from harombe.memory.manager import MemoryManager
from harombe.vector.chromadb import ChromaDBVectorStore


async def example_semantic_search():
    """Demonstrate basic semantic search functionality."""
    print("=" * 60)
    print("Example 1: Basic Semantic Search")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        vector_path = Path(tmpdir) / "vectors"

        # Create embedding client (local, privacy-first)
        print("\n1. Setting up embedding client...")
        embedding_client = SentenceTransformerEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            device="cpu",  # or "cuda" for GPU
        )

        # Create vector store
        print("2. Setting up vector store...")
        vector_store = ChromaDBVectorStore(
            collection_name="demo_semantic",
            persist_directory=vector_path,
        )

        # Create memory manager with semantic search
        print("3. Creating memory manager with semantic search...")
        memory = MemoryManager(
            storage_path=db_path,
            max_history_tokens=4096,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        print(f"   Semantic search enabled: {memory.semantic_search_enabled}")

        # Create a session and add some messages
        print("\n4. Adding messages to conversation history...")
        session_id = memory.create_session(system_prompt="You are a helpful assistant.")

        messages = [
            "Python is a great programming language",
            "I love building web applications with FastAPI",
            "Machine learning models are fascinating",
            "The weather is sunny today",
            "Neural networks can learn complex patterns",
            "JavaScript is useful for frontend development",
        ]

        for msg_text in messages:
            msg = Message(role="user", content=msg_text)
            memory.save_message(session_id, msg)
            print(f"   Saved: {msg_text}")

        # Search for similar messages
        print("\n5. Searching for programming-related messages...")
        results = await memory.search_similar(
            query="coding and software development",
            top_k=3,
            min_similarity=0.5,
        )

        print(f"\n   Found {len(results)} similar messages:")
        for i, result in enumerate(results, 1):
            print(f"   {i}. {result.content}")

        # Search for weather-related
        print("\n6. Searching for weather-related messages...")
        results = await memory.search_similar(
            query="climate and weather conditions",
            top_k=2,
            min_similarity=0.5,
        )

        print(f"\n   Found {len(results)} similar messages:")
        for i, result in enumerate(results, 1):
            print(f"   {i}. {result.content}")


async def example_cross_session_search():
    """Demonstrate searching across multiple conversation sessions."""
    print("\n" + "=" * 60)
    print("Example 2: Cross-Session Semantic Search")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        vector_path = Path(tmpdir) / "vectors"

        embedding_client = SentenceTransformerEmbedding(device="cpu")
        vector_store = ChromaDBVectorStore(
            collection_name="demo_cross_session",
            persist_directory=vector_path,
        )
        memory = MemoryManager(
            storage_path=db_path,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        # Create multiple sessions with different topics
        print("\n1. Creating multiple conversation sessions...")

        # Python session
        session1 = memory.create_session(system_prompt="Python expert")
        memory.save_message(
            session1,
            Message(role="user", content="How do I use async/await in Python?"),
        )
        memory.save_message(
            session1,
            Message(role="assistant", content="Use async def and await keywords..."),
        )
        print("   Created Python session")

        # JavaScript session
        session2 = memory.create_session(system_prompt="JavaScript expert")
        memory.save_message(
            session2,
            Message(role="user", content="Explain JavaScript promises"),
        )
        memory.save_message(
            session2,
            Message(role="assistant", content="Promises handle async operations..."),
        )
        print("   Created JavaScript session")

        # Cooking session
        session3 = memory.create_session(system_prompt="Cooking expert")
        memory.save_message(
            session3,
            Message(role="user", content="Best recipe for chocolate cake"),
        )
        memory.save_message(
            session3,
            Message(role="assistant", content="Start with quality cocoa powder..."),
        )
        print("   Created cooking session")

        # Search across all sessions
        print("\n2. Searching for programming content across all sessions...")
        results = await memory.search_similar(
            query="asynchronous programming patterns",
            top_k=5,
            session_id=None,  # Search all sessions
            min_similarity=0.3,
        )

        print(f"\n   Found {len(results)} relevant messages:")
        for result in results:
            print(f"   - [{result.role}]: {result.content[:60]}...")

        # Search within specific session
        print("\n3. Searching only within Python session...")
        results = await memory.search_similar(
            query="asynchronous programming patterns",
            top_k=5,
            session_id=session1,  # Limit to session1
            min_similarity=0.3,
        )

        print(f"\n   Found {len(results)} messages in Python session:")
        for result in results:
            print(f"   - [{result.role}]: {result.content[:60]}...")


async def example_rag_agent():
    """Demonstrate RAG (Retrieval-Augmented Generation) with agent."""
    print("\n" + "=" * 60)
    print("Example 3: RAG-Enabled Agent")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        vector_path = Path(tmpdir) / "vectors"

        # Setup
        print("\n1. Setting up RAG-enabled agent...")
        embedding_client = SentenceTransformerEmbedding(device="cpu")
        vector_store = ChromaDBVectorStore(
            collection_name="demo_rag",
            persist_directory=vector_path,
        )
        memory = MemoryManager(
            storage_path=db_path,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        llm = OllamaClient(
            model="qwen3:8b",
            base_url="http://localhost:11434",
        )

        session_id = memory.create_session(
            system_prompt="You are a helpful AI assistant with memory."
        )

        # Create agent WITHOUT RAG first
        print("\n2. Testing agent WITHOUT RAG...")
        agent_no_rag = Agent(
            llm=llm,
            tools=[],
            memory_manager=memory,
            session_id=session_id,
            enable_rag=False,  # RAG disabled
        )

        # Populate conversation history
        print("   Populating conversation history...")
        memory.save_message(
            session_id,
            Message(role="user", content="My favorite color is blue"),
        )
        memory.save_message(
            session_id,
            Message(role="assistant", content="I'll remember that!"),
        )
        memory.save_message(
            session_id,
            Message(role="user", content="I enjoy hiking in the mountains"),
        )
        memory.save_message(
            session_id,
            Message(role="assistant", content="Hiking is wonderful exercise!"),
        )

        # Wait for embeddings to process
        await asyncio.sleep(0.5)

        # Ask a related question without RAG
        print("\n   Asking: 'What outdoor activities do I like?'")
        print("   (Agent does NOT have RAG - won't retrieve context)")
        response = await agent_no_rag.run("What outdoor activities do I like?")
        print(f"\n   Response (no RAG): {response[:100]}...")

        # Now enable RAG
        print("\n3. Testing agent WITH RAG enabled...")
        agent_with_rag = Agent(
            llm=llm,
            tools=[],
            memory_manager=memory,
            session_id=session_id,
            enable_rag=True,  # RAG enabled!
            rag_top_k=3,
            rag_min_similarity=0.5,
        )

        print("   Asking: 'What outdoor activities do I like?'")
        print("   (Agent HAS RAG - will retrieve relevant context)")
        response = await agent_with_rag.run("What outdoor activities do I like?")
        print(f"\n   Response (with RAG): {response[:100]}...")
        print("\n   The RAG agent should mention hiking based on retrieved context!")


async def example_context_retrieval():
    """Demonstrate token-aware context retrieval."""
    print("\n" + "=" * 60)
    print("Example 4: Token-Aware Context Retrieval")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        vector_path = Path(tmpdir) / "vectors"

        embedding_client = SentenceTransformerEmbedding(device="cpu")
        vector_store = ChromaDBVectorStore(
            collection_name="demo_context",
            persist_directory=vector_path,
        )
        memory = MemoryManager(
            storage_path=db_path,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        session_id = memory.create_session(system_prompt="Test")

        # Add many messages
        print("\n1. Adding 10 messages about Python...")
        for i in range(10):
            msg = Message(
                role="user",
                content=f"Python tip {i}: This is a detailed explanation about Python feature number {i}. "
                * 10,  # Make it longer
            )
            memory.save_message(session_id, msg)

        # Get context with token budget
        print("\n2. Retrieving context with 500 token budget...")
        context = await memory.get_relevant_context(
            query="Python programming tips",
            max_tokens=500,
            session_id=session_id,
        )

        print(f"\n   Retrieved {len(context)} messages within token budget")
        for i, msg in enumerate(context, 1):
            print(f"   {i}. {msg.content[:50]}...")


async def example_backfill():
    """Demonstrate backfilling embeddings for existing conversations."""
    print("\n" + "=" * 60)
    print("Example 5: Backfilling Embeddings")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "memory.db"
        vector_path = Path(tmpdir) / "vectors"

        # First, create memory WITHOUT semantic search
        print("\n1. Creating conversations without semantic search...")
        memory_basic = MemoryManager(storage_path=db_path)

        session1 = memory_basic.create_session(system_prompt="Test")
        memory_basic.save_message(
            session1,
            Message(role="user", content="Python is great for data science"),
        )
        memory_basic.save_message(
            session1,
            Message(role="user", content="Machine learning is fascinating"),
        )

        session2 = memory_basic.create_session(system_prompt="Test")
        memory_basic.save_message(
            session2,
            Message(role="user", content="Web development with FastAPI"),
        )

        print(f"   Created {len(memory_basic.list_sessions())} sessions")

        # Now enable semantic search
        print("\n2. Enabling semantic search on existing database...")
        embedding_client = SentenceTransformerEmbedding(device="cpu")
        vector_store = ChromaDBVectorStore(
            collection_name="demo_backfill",
            persist_directory=vector_path,
        )

        memory_semantic = MemoryManager(
            storage_path=db_path,
            embedding_client=embedding_client,
            vector_store=vector_store,
        )

        print(f"   Semantic search enabled: {memory_semantic.semantic_search_enabled}")
        print(f"   Vector store count before backfill: {vector_store.count()}")

        # Backfill embeddings
        print("\n3. Backfilling embeddings for existing messages...")
        count = memory_semantic.backfill_embeddings()
        print(f"   Backfilled {count} messages")
        print(f"   Vector store count after backfill: {vector_store.count()}")

        # Now we can search
        print("\n4. Searching backfilled messages...")
        results = await memory_semantic.search_similar(
            query="artificial intelligence and data",
            top_k=3,
        )

        print(f"\n   Found {len(results)} results:")
        for result in results:
            print(f"   - {result.content}")


async def main():
    """Run all examples."""
    await example_semantic_search()
    await example_cross_session_search()
    # await example_rag_agent()  # Uncomment if Ollama is running
    await example_context_retrieval()
    await example_backfill()

    print("\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
