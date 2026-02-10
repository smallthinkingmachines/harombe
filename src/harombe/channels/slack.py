"""Slack channel adapter using Bolt SDK.

Requires: pip install slack-bolt

Usage:
    adapter = SlackAdapter(
        bot_token="xoxb-...",
        app_token="xapp-...",
        agent=agent,
    )
    await adapter.start()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from harombe.channels.base import ChannelMessage

if TYPE_CHECKING:
    from harombe.agent.loop import Agent

logger = logging.getLogger(__name__)


class SlackAdapter:
    """Slack Bot adapter using the Bolt SDK."""

    def __init__(
        self,
        bot_token: str,
        app_token: str,
        agent: Agent,
    ) -> None:
        """Initialize Slack adapter.

        Args:
            bot_token: Slack bot token (xoxb-...)
            app_token: Slack app-level token (xapp-...) for Socket Mode
            agent: Harombe agent to handle messages
        """
        self.bot_token = bot_token
        self.app_token = app_token
        self.agent = agent
        self._app = None
        self._handler = None

    async def start(self) -> None:
        """Start listening for Slack messages via Socket Mode."""
        try:
            from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
            from slack_bolt.async_app import AsyncApp
        except ImportError as err:
            raise RuntimeError(
                "Slack integration requires slack-bolt. " "Install with: pip install slack-bolt"
            ) from err

        self._app = AsyncApp(token=self.bot_token)

        @self._app.event("app_mention")
        async def handle_mention(event, say):
            await self._handle_message(event, say)

        @self._app.event("message")
        async def handle_dm(event, say):
            # Only respond to DMs (no subtype means it's a regular message)
            if event.get("channel_type") == "im" and "subtype" not in event:
                await self._handle_message(event, say)

        self._handler = AsyncSocketModeHandler(self._app, self.app_token)
        logger.info("Starting Slack adapter (Socket Mode)")
        await self._handler.start_async()

    async def stop(self) -> None:
        """Stop the Slack adapter."""
        if self._handler:
            await self._handler.close_async()

    async def _handle_message(self, event: dict, say) -> None:
        """Process an incoming Slack message."""
        text = event.get("text", "").strip()
        user_id = event.get("user", "unknown")
        channel_id = event.get("channel", "")
        thread_ts = event.get("thread_ts") or event.get("ts")

        if not text:
            return

        # Remove bot mention if present
        # Slack wraps mentions as <@BOTID>
        import re

        text = re.sub(r"<@\w+>\s*", "", text).strip()

        if not text:
            return

        msg = ChannelMessage(
            text=text,
            user_id=user_id,
            channel_id=channel_id,
            thread_id=thread_ts,
        )

        logger.info("Slack message from %s: %s", user_id, text[:100])

        try:
            response = await self.agent.run(msg.text)
            await say(text=response, thread_ts=thread_ts)
        except Exception as e:
            logger.error("Error processing Slack message: %s", e)
            await say(text=f"Sorry, I encountered an error: {e}", thread_ts=thread_ts)

    async def send_message(self, channel_id: str, text: str, thread_id: str | None = None) -> None:
        """Send a message to a Slack channel."""
        if self._app:
            await self._app.client.chat_postMessage(
                channel=channel_id,
                text=text,
                thread_ts=thread_id,
            )
