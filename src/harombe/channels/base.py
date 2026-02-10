"""Base protocol for channel adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass
class ChannelMessage:
    """A message received from a channel."""

    text: str
    user_id: str
    channel_id: str
    thread_id: str | None = None
    metadata: dict[str, Any] | None = None


@runtime_checkable
class ChannelAdapter(Protocol):
    """Protocol for messaging channel adapters.

    Each adapter connects to a messaging platform, receives messages,
    runs them through an Agent, and sends back responses.
    """

    async def start(self) -> None:
        """Start listening for messages."""
        ...

    async def stop(self) -> None:
        """Stop listening and clean up."""
        ...

    async def send_message(self, channel_id: str, text: str, thread_id: str | None = None) -> None:
        """Send a message to a channel.

        Args:
            channel_id: Channel to send to
            text: Message text
            thread_id: Optional thread to reply in
        """
        ...
