"""High-level memory management for conversation sessions."""

import uuid
from pathlib import Path

from harombe.llm.client import Message
from harombe.memory.schema import MessageRecord, SessionMetadata, SessionRecord
from harombe.memory.storage import MemoryStorage
from harombe.memory.utils import estimate_tokens


class MemoryManager:
    """High-level memory management interface."""

    def __init__(
        self,
        storage_path: str | Path,
        max_history_tokens: int = 4096,
    ):
        """Initialize memory manager.

        Args:
            storage_path: Path to SQLite database
            max_history_tokens: Maximum tokens to load from history
        """
        self.storage = MemoryStorage(storage_path)
        self.max_history_tokens = max_history_tokens

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

        return self.storage.save_message(record)

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
