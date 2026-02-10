"""Discord channel adapter using discord.py.

Requires: pip install discord.py

Usage:
    adapter = DiscordAdapter(
        bot_token="...",
        agent=agent,
    )
    await adapter.start()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from harombe.channels.base import ChannelMessage

if TYPE_CHECKING:
    from harombe.agent.loop import Agent

logger = logging.getLogger(__name__)


class DiscordAdapter:
    """Discord Bot adapter using discord.py."""

    def __init__(
        self,
        bot_token: str,
        agent: Agent,
    ) -> None:
        """Initialize Discord adapter.

        Args:
            bot_token: Discord bot token
            agent: Harombe agent to handle messages
        """
        self.bot_token = bot_token
        self.agent = agent
        self._client: Any = None

    async def start(self) -> None:
        """Start the Discord bot."""
        try:
            import discord
        except ImportError as err:
            raise RuntimeError(
                "Discord integration requires discord.py. " "Install with: pip install discord.py"
            ) from err

        intents = discord.Intents.default()
        intents.message_content = True
        self._client = discord.Client(intents=intents)

        @self._client.event  # type: ignore
        async def on_ready() -> None:
            logger.info("Discord bot connected as %s", self._client.user)

        @self._client.event  # type: ignore
        async def on_message(message: Any) -> None:
            # Don't respond to ourselves
            if message.author == self._client.user:
                return

            # Respond to mentions or DMs
            is_mention = self._client.user in message.mentions if message.guild else False
            is_dm = message.guild is None

            if not (is_mention or is_dm):
                return

            # Clean up mention text
            text = message.content
            if self._client.user:
                text = text.replace(f"<@{self._client.user.id}>", "").strip()

            if not text:
                return

            msg = ChannelMessage(
                text=text,
                user_id=str(message.author.id),
                channel_id=str(message.channel.id),
                thread_id=str(message.id) if message.reference else None,
            )

            logger.info("Discord message from %s: %s", message.author.name, text[:100])

            try:
                response = await self.agent.run(msg.text)
                # Discord has a 2000 char limit
                if len(response) > 2000:
                    for i in range(0, len(response), 2000):
                        await message.channel.send(response[i : i + 2000])
                else:
                    await message.channel.send(response)
            except Exception as e:
                logger.error("Error processing Discord message: %s", e)
                await message.channel.send(f"Sorry, I encountered an error: {e}")

        logger.info("Starting Discord adapter")
        await self._client.start(self.bot_token)

    async def stop(self) -> None:
        """Stop the Discord bot."""
        if self._client:
            await self._client.close()

    async def send_message(self, channel_id: str, text: str, thread_id: str | None = None) -> None:
        """Send a message to a Discord channel."""
        if self._client:
            channel = self._client.get_channel(int(channel_id))
            if channel:
                await channel.send(text)
