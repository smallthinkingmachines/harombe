"""Tests for Discord channel adapter."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.channels.discord import DiscordAdapter


@pytest.fixture
def discord_adapter(mock_agent):
    """Create DiscordAdapter with mock agent."""
    return DiscordAdapter(
        bot_token="fake-discord-token",
        agent=mock_agent,
    )


class TestDiscordAdapter:
    def test_init(self, mock_agent):
        adapter = DiscordAdapter(bot_token="token-123", agent=mock_agent)
        assert adapter.bot_token == "token-123"
        assert adapter.agent is mock_agent
        assert adapter._client is None

    @pytest.mark.asyncio
    async def test_start_import_error(self, discord_adapter):
        """Test start raises RuntimeError when discord.py is not installed."""
        with (
            patch.dict("sys.modules", {"discord": None}),
            pytest.raises(RuntimeError, match=r"discord\.py"),
        ):
            await discord_adapter.start()

    @pytest.mark.asyncio
    async def test_stop_no_client(self, discord_adapter):
        """Test stop when client is None."""
        await discord_adapter.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_with_client(self, discord_adapter):
        """Test stop closes client."""
        mock_client = AsyncMock()
        discord_adapter._client = mock_client

        await discord_adapter.stop()

        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_with_client(self, discord_adapter):
        """Test sending a message to a channel."""
        mock_channel = AsyncMock()
        mock_client = MagicMock()
        mock_client.get_channel.return_value = mock_channel
        discord_adapter._client = mock_client

        await discord_adapter.send_message("12345", "hello there")

        mock_client.get_channel.assert_called_once_with(12345)
        mock_channel.send.assert_called_once_with("hello there")

    @pytest.mark.asyncio
    async def test_send_message_channel_not_found(self, discord_adapter):
        """Test sending to a non-existing channel."""
        mock_client = MagicMock()
        mock_client.get_channel.return_value = None
        discord_adapter._client = mock_client

        await discord_adapter.send_message("99999", "hello")  # Should not raise

    @pytest.mark.asyncio
    async def test_send_message_no_client(self, discord_adapter):
        """Test sending when client is None."""
        await discord_adapter.send_message("12345", "hello")  # Should not raise

    @pytest.mark.asyncio
    async def test_adapter_is_channel_adapter(self, discord_adapter):
        """Test that DiscordAdapter satisfies ChannelAdapter protocol."""

        # Check structural typing
        assert hasattr(discord_adapter, "start")
        assert hasattr(discord_adapter, "stop")
        assert hasattr(discord_adapter, "send_message")

    @pytest.mark.asyncio
    async def test_init_stores_token(self, mock_agent):
        """Test that bot token is stored correctly."""
        adapter = DiscordAdapter(bot_token="my-secret-token", agent=mock_agent)
        assert adapter.bot_token == "my-secret-token"
