"""SQLite storage backend for conversation memory."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from harombe.llm.client import Message
from harombe.memory.schema import MessageRecord, SessionMetadata, SessionRecord


class MemoryStorage:
    """SQLite-based storage for conversation memory."""

    def __init__(self, db_path: str | Path):
        """Initialize storage with database path.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Create tables and indexes if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    system_prompt TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    tool_calls TEXT,
                    tool_call_id TEXT,
                    name TEXT,
                    created_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                )
            """)

            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at)")

            conn.commit()

    def create_session(
        self,
        session_id: str,
        system_prompt: str,
        metadata: SessionMetadata | None = None,
    ) -> SessionRecord:
        """Create a new conversation session.

        Args:
            session_id: Unique session identifier
            system_prompt: System prompt for this session
            metadata: Optional session metadata

        Returns:
            Created session record
        """
        if metadata is None:
            metadata = SessionMetadata()

        now = datetime.utcnow()
        session = SessionRecord(
            id=session_id,
            created_at=now,
            updated_at=now,
            system_prompt=system_prompt,
            metadata=metadata,
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sessions (id, created_at, updated_at, system_prompt, metadata)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    session.id,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                    session.system_prompt,
                    session.metadata.model_dump_json(),
                ),
            )
            conn.commit()

        return session

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Get a session by ID.

        Args:
            session_id: Session identifier

        Returns:
            Session record or None if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return SessionRecord(
                id=row["id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                system_prompt=row["system_prompt"],
                metadata=SessionMetadata.model_validate_json(row["metadata"]),
            )

    def update_session_activity(self, session_id: str) -> None:
        """Update the last activity timestamp for a session.

        Args:
            session_id: Session identifier
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), session_id),
            )
            conn.commit()

    def save_message(self, message: MessageRecord) -> int:
        """Save a message to storage.

        Args:
            message: Message record to save

        Returns:
            Message ID assigned by database
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO messages
                (session_id, role, content, tool_calls, tool_call_id, name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    message.session_id,
                    message.role,
                    message.content,
                    message.tool_calls,
                    message.tool_call_id,
                    message.name,
                    message.created_at.isoformat(),
                ),
            )
            conn.commit()

            # Update session activity
            self.update_session_activity(message.session_id)

            message_id = cursor.lastrowid
            assert message_id is not None
            return message_id

    def load_messages(
        self,
        session_id: str,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Message]:
        """Load messages for a session.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return
            offset: Number of messages to skip

        Returns:
            List of messages in chronological order
        """
        query = """
            SELECT * FROM messages
            WHERE session_id = ?
            ORDER BY created_at ASC
        """

        params: list[Any] = [session_id]

        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

            messages = []
            for row in rows:
                # Parse tool_calls if present
                tool_calls = None
                if row["tool_calls"]:
                    tool_calls_data = json.loads(row["tool_calls"])
                    # Convert to ToolCall objects if needed by client code
                    tool_calls = tool_calls_data

                messages.append(
                    Message(
                        role=row["role"],
                        content=row["content"],
                        tool_calls=tool_calls,
                        tool_call_id=row["tool_call_id"],
                        name=row["name"],
                    )
                )

            return messages

    def get_message_count(self, session_id: str) -> int:
        """Get the total number of messages in a session.

        Args:
            session_id: Session identifier

        Returns:
            Message count
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE session_id = ?", (session_id,)
            )
            result = cursor.fetchone()
            return int(result[0])

    def list_sessions(self, limit: int = 10, offset: int = 0) -> list[SessionRecord]:
        """List recent sessions.

        Args:
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip

        Returns:
            List of sessions ordered by most recent activity
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM sessions
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """,
                (limit, offset),
            )
            rows = cursor.fetchall()

            sessions = []
            for row in rows:
                sessions.append(
                    SessionRecord(
                        id=row["id"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        updated_at=datetime.fromisoformat(row["updated_at"]),
                        system_prompt=row["system_prompt"],
                        metadata=SessionMetadata.model_validate_json(row["metadata"]),
                    )
                )

            return sessions

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its messages.

        Args:
            session_id: Session identifier

        Returns:
            True if session was deleted, False if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount > 0

    def prune_old_sessions(self, days: int) -> int:
        """Delete sessions older than specified days.

        Args:
            days: Delete sessions not updated in this many days

        Returns:
            Number of sessions deleted
        """
        cutoff = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)
        cutoff_dt = datetime.fromtimestamp(cutoff)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE updated_at < ?", (cutoff_dt.isoformat(),)
            )
            conn.commit()
            return cursor.rowcount

    def clear_messages(self, session_id: str) -> int:
        """Clear all messages from a session (but keep the session).

        Args:
            session_id: Session identifier

        Returns:
            Number of messages deleted
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount
