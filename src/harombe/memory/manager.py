"""High-level memory management for conversation sessions."""

import asyncio
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from harombe.llm.client import Message
from harombe.memory.schema import MessageRecord, SessionMetadata, SessionRecord
from harombe.memory.storage import MemoryStorage
from harombe.memory.utils import estimate_tokens

if TYPE_CHECKING:
    from harombe.embeddings.client import EmbeddingClient
    from harombe.vector.store import VectorStore


class MemoryManager:
    """High-level memory management interface with optional semantic search."""

    def __init__(
        self,
        storage_path: str | Path,
        max_history_tokens: int = 4096,
        embedding_client: "EmbeddingClient | None" = None,
        vector_store: "VectorStore | None" = None,
    ):
        """Initialize memory manager.

        Args:
            storage_path: Path to SQLite database
            max_history_tokens: Maximum tokens to load from history
            embedding_client: Optional embedding client for semantic search
            vector_store: Optional vector store for semantic search
        """
        self.storage = MemoryStorage(storage_path)
        self.max_history_tokens = max_history_tokens
        self.embedding_client = embedding_client
        self.vector_store = vector_store

        # Enable semantic search if both components provided
        self.semantic_search_enabled = embedding_client is not None and vector_store is not None

    def create_session(
        self,
        system_prompt: str,
        metadata: SessionMetadata | None = None,
        session_id: str | None = None,
    ) -> str:
        """Create a new conversation session.

        Args:
            system_prompt: System prompt for this session
            metadata: Optional session metadata
            session_id: Optional custom session ID (generates UUID if not provided)

        Returns:
            Session ID
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        self.storage.create_session(
            session_id=session_id,
            system_prompt=system_prompt,
            metadata=metadata,
        )

        return session_id

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Get session information.

        Args:
            session_id: Session identifier

        Returns:
            Session record or None if not found
        """
        return self.storage.get_session(session_id)

    def save_message(self, session_id: str, message: Message) -> int:
        """Save a message to a session.

        If semantic search is enabled, also embeds and stores in vector store.

        Args:
            session_id: Session identifier
            message: Message to save

        Returns:
            Message ID
        """
        # Convert Message to MessageRecord
        tool_calls_json = None
        if message.tool_calls:
            # Serialize tool calls to JSON
            import json

            tool_calls_json = json.dumps(
                [
                    {
                        "id": tc.id,
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                    for tc in message.tool_calls
                ]
            )

        record = MessageRecord(
            session_id=session_id,
            role=message.role,
            content=message.content,
            tool_calls=tool_calls_json,
            tool_call_id=message.tool_call_id,
            name=message.name,
        )

        message_id = self.storage.save_message(record)

        # Auto-embed if semantic search is enabled
        if self.semantic_search_enabled and message.content:
            self._embed_message(message_id, session_id, message)

        return message_id

    def _embed_message(self, message_id: int, session_id: str, message: Message) -> None:
        """Embed a message and store in vector store (internal helper).

        Args:
            message_id: Database message ID
            session_id: Session identifier
            message: Message to embed
        """
        # Skip empty messages or system messages
        if not message.content or message.role == "system":
            return

        # Generate embedding
        try:
            # Run async embedding in sync context
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context - schedule async task
                # Store reference to prevent task from being garbage collected
                task = loop.create_task(self._embed_message_async(message_id, session_id, message))
                # Add a done callback to capture any exceptions
                task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                return

            embedding = loop.run_until_complete(
                self.embedding_client.embed_single(message.content)  # type: ignore[union-attr]
            )
        except Exception:
            # Silently fail - don't break message saving
            return

        # Store in vector database
        try:
            doc_id = f"msg_{message_id}"
            metadata = {
                "session_id": session_id,
                "message_id": message_id,
                "role": message.role,
            }

            self.vector_store.add(  # type: ignore[union-attr]
                ids=[doc_id],
                embeddings=[embedding],
                documents=[message.content],
                metadata=[metadata],
            )
        except Exception:
            # Silently fail - don't break message saving
            pass

    async def _embed_message_async(
        self, message_id: int, session_id: str, message: Message
    ) -> None:
        """Embed message asynchronously (for use in async contexts).

        Args:
            message_id: Database message ID
            session_id: Session identifier
            message: Message to embed
        """
        if not message.content or message.role == "system":
            return

        try:
            embedding = await self.embedding_client.embed_single(message.content)  # type: ignore[union-attr]
        except Exception:
            return

        try:
            doc_id = f"msg_{message_id}"
            metadata = {
                "session_id": session_id,
                "message_id": message_id,
                "role": message.role,
            }

            self.vector_store.add(  # type: ignore[union-attr]
                ids=[doc_id],
                embeddings=[embedding],
                documents=[message.content],
                metadata=[metadata],
            )
        except Exception:
            pass

    def load_history(
        self,
        session_id: str,
        max_tokens: int | None = None,
    ) -> list[Message]:
        """Load conversation history for a session.

        Loads the most recent messages that fit within token limit.

        Args:
            session_id: Session identifier
            max_tokens: Maximum tokens to load (uses default if None)

        Returns:
            List of messages in chronological order
        """
        if max_tokens is None:
            max_tokens = self.max_history_tokens

        # Load all messages (we'll filter in memory)
        # For very large histories, could optimize with pagination
        all_messages = self.storage.load_messages(session_id)

        # If under limit, return all
        total_tokens = sum(estimate_tokens(msg) for msg in all_messages)
        if total_tokens <= max_tokens:
            return all_messages

        # Otherwise, take most recent messages that fit
        result: list[Message] = []
        current_tokens = 0

        # Iterate in reverse (newest first)
        for message in reversed(all_messages):
            msg_tokens = estimate_tokens(message)

            if current_tokens + msg_tokens > max_tokens:
                break

            result.insert(0, message)  # Insert at beginning to maintain order
            current_tokens += msg_tokens

        return result

    def get_recent_messages(
        self,
        session_id: str,
        count: int = 10,
    ) -> list[Message]:
        """Get the N most recent messages.

        Args:
            session_id: Session identifier
            count: Number of messages to retrieve

        Returns:
            List of recent messages in chronological order
        """
        all_messages = self.storage.load_messages(session_id)
        return all_messages[-count:] if len(all_messages) > count else all_messages

    def list_sessions(
        self,
        limit: int = 10,
        offset: int = 0,
    ) -> list[SessionRecord]:
        """List recent sessions.

        Args:
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip

        Returns:
            List of sessions ordered by most recent activity
        """
        return self.storage.list_sessions(limit=limit, offset=offset)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its messages.

        Args:
            session_id: Session identifier

        Returns:
            True if session was deleted, False if not found
        """
        return self.storage.delete_session(session_id)

    def clear_history(self, session_id: str) -> int:
        """Clear all messages from a session (but keep the session).

        Args:
            session_id: Session identifier

        Returns:
            Number of messages deleted
        """
        return self.storage.clear_messages(session_id)

    def get_message_count(self, session_id: str) -> int:
        """Get the total number of messages in a session.

        Args:
            session_id: Session identifier

        Returns:
            Message count
        """
        return self.storage.get_message_count(session_id)

    def prune_old_sessions(self, days: int = 30) -> int:
        """Delete sessions older than specified days.

        Args:
            days: Delete sessions not updated in this many days

        Returns:
            Number of sessions deleted
        """
        return self.storage.prune_old_sessions(days)

    def session_exists(self, session_id: str) -> bool:
        """Check if a session exists.

        Args:
            session_id: Session identifier

        Returns:
            True if session exists
        """
        return self.storage.get_session(session_id) is not None

    def get_or_create_session(
        self,
        session_id: str,
        system_prompt: str,
        metadata: SessionMetadata | None = None,
    ) -> tuple[str, bool]:
        """Get an existing session or create a new one.

        Args:
            session_id: Session identifier
            system_prompt: System prompt (used if creating new session)
            metadata: Session metadata (used if creating new session)

        Returns:
            Tuple of (session_id, created) where created is True if new session
        """
        if self.session_exists(session_id):
            return session_id, False

        self.create_session(
            system_prompt=system_prompt,
            metadata=metadata,
            session_id=session_id,
        )
        return session_id, True

    # Semantic search methods (require embedding_client and vector_store)

    async def search_similar(
        self,
        query: str,
        top_k: int = 5,
        session_id: str | None = None,
        min_similarity: float | None = None,
    ) -> list[Message]:
        """Search for semantically similar messages.

        Args:
            query: Query text to search for
            top_k: Number of results to return
            session_id: Optional session to limit search to
            min_similarity: Optional minimum similarity threshold (0-1)

        Returns:
            List of similar messages ordered by relevance

        Raises:
            RuntimeError: If semantic search is not enabled
        """
        if not self.semantic_search_enabled:
            msg = "Semantic search not enabled. Provide embedding_client and vector_store."
            raise RuntimeError(msg)

        # Generate query embedding
        query_embedding = await self.embedding_client.embed_single(query)  # type: ignore[union-attr]

        # Search vector store
        where = {"session_id": session_id} if session_id else None
        _ids, documents, metadatas, distances = self.vector_store.search(  # type: ignore[union-attr]
            query_embedding=query_embedding,
            top_k=top_k,
            where=where,
        )

        # Convert to Messages and filter by similarity
        results = []
        for doc, meta, distance in zip(documents, metadatas, distances, strict=False):
            # ChromaDB returns distance (lower = more similar)
            # Convert to similarity score (higher = more similar)
            similarity = 1.0 - distance

            if min_similarity is not None and similarity < min_similarity:
                continue

            # Create Message from metadata
            message = Message(
                role=meta["role"],
                content=doc,
            )
            results.append(message)

        return results

    async def get_relevant_context(
        self,
        query: str,
        max_tokens: int = 2048,
        session_id: str | None = None,
    ) -> list[Message]:
        """Get relevant context for a query, limited by token budget.

        Args:
            query: Query text
            max_tokens: Maximum tokens of context to return
            session_id: Optional session to limit search to

        Returns:
            List of relevant messages within token budget

        Raises:
            RuntimeError: If semantic search is not enabled
        """
        if not self.semantic_search_enabled:
            msg = "Semantic search not enabled. Provide embedding_client and vector_store."
            raise RuntimeError(msg)

        # Search for top candidates (over-fetch to allow token filtering)
        candidates = await self.search_similar(
            query=query,
            top_k=20,
            session_id=session_id,
        )

        # Filter by token budget
        results = []
        current_tokens = 0

        for message in candidates:
            msg_tokens = estimate_tokens(message)
            if current_tokens + msg_tokens > max_tokens:
                break
            results.append(message)
            current_tokens += msg_tokens

        return results

    def backfill_embeddings(
        self,
        session_id: str | None = None,
        batch_size: int = 100,
    ) -> int:
        """Backfill embeddings for existing messages.

        Useful when enabling semantic search on existing conversation history.

        Args:
            session_id: Optional session to limit backfill to (None = all sessions)
            batch_size: Number of messages to process at once

        Returns:
            Number of messages embedded

        Raises:
            RuntimeError: If semantic search is not enabled
        """
        if not self.semantic_search_enabled:
            msg = "Semantic search not enabled. Provide embedding_client and vector_store."
            raise RuntimeError(msg)

        # Get messages without embeddings
        # For now, just process all messages
        # TODO: Track which messages have embeddings to avoid duplicates

        sessions = [session_id] if session_id else [s.id for s in self.storage.list_sessions()]

        total_embedded = 0

        for sid in sessions:
            messages_data = self.storage.load_messages(sid)

            for message in messages_data:
                if message.role == "system" or not message.content:
                    continue

                # Get message ID from storage
                # This is a workaround - ideally we'd track message IDs better
                # For now, create a pseudo-ID
                import hashlib

                message_hash = hashlib.md5(
                    f"{sid}:{message.role}:{message.content}".encode()
                ).hexdigest()[:8]
                message_id = f"backfill_{message_hash}"

                try:
                    # Generate embedding
                    loop = asyncio.get_event_loop()
                    embedding = loop.run_until_complete(
                        self.embedding_client.embed_single(message.content)  # type: ignore[union-attr]
                    )

                    # Store in vector database
                    metadata = {
                        "session_id": sid,
                        "message_id": message_id,
                        "role": message.role,
                    }

                    self.vector_store.add(  # type: ignore[union-attr]
                        ids=[message_id],
                        embeddings=[embedding],
                        documents=[message.content],
                        metadata=[metadata],
                    )

                    total_embedded += 1
                except Exception:
                    # Skip failures
                    continue

        return total_embedded
