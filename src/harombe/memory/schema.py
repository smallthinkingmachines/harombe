"""Pydantic models for memory system."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SessionMetadata(BaseModel):
    """Metadata for a conversation session."""

    user: str | None = None
    tags: list[str] = Field(default_factory=list)
    title: str | None = None
    custom: dict[str, Any] = Field(default_factory=dict)


class SessionRecord(BaseModel):
    """A conversation session record."""

    id: str
    created_at: datetime
    updated_at: datetime
    system_prompt: str
    metadata: SessionMetadata = Field(default_factory=SessionMetadata)


class MessageRecord(BaseModel):
    """A message record in a session."""

    id: int | None = None  # Auto-assigned by database
    session_id: str
    role: str  # user, assistant, system, tool
    content: str | None = None
    tool_calls: str | None = None  # JSON string
    tool_call_id: str | None = None
    name: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
