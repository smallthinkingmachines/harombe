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
        assert hasattr(discord_adapter, "start")
        assert hasattr(discord_adapter, "stop")
        assert hasattr(discord_adapter, "send_message")

    @pytest.mark.asyncio
    async def test_init_stores_token(self, mock_agent):
        """Test that bot token is stored correctly."""
        adapter = DiscordAdapter(bot_token="my-secret-token", agent=mock_agent)
        assert adapter.bot_token == "my-secret-token"


class TestDiscordOnMessage:
    """Tests that exercise the on_message handler inside start().

    Strategy: mock the discord module so that start() runs setup but does not
    actually connect.  Capture the on_message callback via client.event, then
    invoke it directly.
    """

    @staticmethod
    def _build_mock_discord():
        """Return (discord_module, captured_events) mocks."""
        mock_discord = MagicMock()

        # Intents
        mock_intents = MagicMock()
        mock_discord.Intents.default.return_value = mock_intents

        # Client
        captured_events: dict[str, object] = {}
        mock_client = MagicMock()
        mock_client.start = AsyncMock()  # prevents real connection

        def event_decorator(fn):
            captured_events[fn.__name__] = fn
            return fn

        mock_client.event = event_decorator
        mock_discord.Client.return_value = mock_client

        # Bot user identity
        mock_user = MagicMock()
        mock_user.id = 111
        mock_client.user = mock_user

        return mock_discord, mock_client, captured_events

    @pytest.mark.asyncio
    async def test_on_message_skips_own_messages(self, mock_agent):
        """on_message ignores messages from the bot itself."""
        mock_discord, mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        # Author == bot user
        msg = MagicMock()
        msg.author = mock_client.user
        await on_message(msg)
        mock_agent.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_message_responds_to_dm(self, mock_agent):
        """on_message responds when the message is a DM (guild is None)."""
        mock_discord, _mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = None  # DM
        msg.content = "hello bot"
        msg.reference = None
        msg.channel = AsyncMock()

        await on_message(msg)
        mock_agent.run.assert_awaited_once_with("hello bot")
        msg.channel.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_message_responds_to_mention(self, mock_agent):
        """on_message responds when the bot is mentioned."""
        mock_discord, mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = MagicMock()  # Not a DM
        msg.mentions = [mock_client.user]
        msg.content = f"<@{mock_client.user.id}> what's up"
        msg.reference = None
        msg.channel = AsyncMock()

        await on_message(msg)
        mock_agent.run.assert_awaited_once_with("what's up")

    @pytest.mark.asyncio
    async def test_on_message_ignores_non_mention_guild(self, mock_agent):
        """on_message ignores guild messages that don't mention the bot."""
        mock_discord, _mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = MagicMock()
        msg.mentions = []  # No mention
        msg.content = "random chatter"

        await on_message(msg)
        mock_agent.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_message_empty_after_mention_strip(self, mock_agent):
        """on_message returns early when text is empty after stripping the mention."""
        mock_discord, mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = None  # DM
        msg.content = f"<@{mock_client.user.id}>"  # Only mention, no text

        await on_message(msg)
        mock_agent.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_message_chunks_long_response(self, mock_agent):
        """Responses >2000 chars are sent in chunks."""
        mock_discord, _mock_client, events = self._build_mock_discord()
        mock_agent.run = AsyncMock(return_value="A" * 4500)

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = None
        msg.content = "give me a long reply"
        msg.reference = None
        msg.channel = AsyncMock()

        await on_message(msg)
        # 4500 chars -> 3 chunks: 2000, 2000, 500
        assert msg.channel.send.await_count == 3

    @pytest.mark.asyncio
    async def test_on_message_agent_error(self, mock_agent):
        """Agent error is caught and reported to the channel."""
        mock_discord, _mock_client, events = self._build_mock_discord()
        mock_agent.run = AsyncMock(side_effect=RuntimeError("boom"))

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = None
        msg.content = "trigger error"
        msg.reference = None
        msg.channel = AsyncMock()

        await on_message(msg)
        msg.channel.send.assert_awaited_once()
        error_text = msg.channel.send.call_args[0][0]
        assert "error" in error_text.lower()

    @pytest.mark.asyncio
    async def test_on_message_with_thread_reference(self, mock_agent):
        """Messages with a reference produce a thread_id in ChannelMessage."""
        mock_discord, _mock_client, events = self._build_mock_discord()

        adapter = DiscordAdapter(bot_token="tok", agent=mock_agent)
        with patch.dict("sys.modules", {"discord": mock_discord}):
            await adapter.start()

        on_message = events["on_message"]

        msg = MagicMock()
        msg.author = MagicMock()
        msg.guild = None
        msg.content = "reply in thread"
        msg.reference = MagicMock()  # truthy => thread_id set
        msg.id = 999
        msg.channel = AsyncMock()

        await on_message(msg)
        mock_agent.run.assert_awaited_once_with("reply in thread")
