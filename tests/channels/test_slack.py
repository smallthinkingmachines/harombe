"""Tests for Slack channel adapter."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.channels.slack import SlackAdapter


@pytest.fixture
def slack_adapter(mock_agent):
    """Create SlackAdapter with mock agent."""
    return SlackAdapter(
        bot_token="xoxb-fake-token",
        app_token="xapp-fake-token",
        agent=mock_agent,
    )


class TestSlackAdapter:
    def test_init(self, mock_agent):
        adapter = SlackAdapter(
            bot_token="xoxb-test",
            app_token="xapp-test",
            agent=mock_agent,
        )
        assert adapter.bot_token == "xoxb-test"
        assert adapter.app_token == "xapp-test"
        assert adapter.agent is mock_agent
        assert adapter._app is None
        assert adapter._handler is None

    @pytest.mark.asyncio
    async def test_start_imports_bolt(self, slack_adapter):
        """Test start tries to import slack-bolt."""
        with (
            patch.dict("sys.modules", {"slack_bolt": None, "slack_bolt.async_app": None}),
            pytest.raises(RuntimeError, match="slack-bolt"),
        ):
            await slack_adapter.start()

    @pytest.mark.asyncio
    async def test_stop_no_handler(self, slack_adapter):
        """Test stop when handler is None."""
        await slack_adapter.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_with_handler(self, slack_adapter):
        """Test stop closes handler."""
        mock_handler = AsyncMock()
        slack_adapter._handler = mock_handler

        await slack_adapter.stop()

        mock_handler.close_async.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_message_basic(self, slack_adapter, mock_agent):
        """Test handling a basic message."""
        event = {
            "text": "hello bot",
            "user": "U12345",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        mock_agent.run.assert_called_once_with("hello bot")
        say.assert_called_once_with(
            text="Hello from the agent!",
            thread_ts="1234567890.123456",
        )

    @pytest.mark.asyncio
    async def test_handle_message_strips_mention(self, slack_adapter, mock_agent):
        """Test that bot mentions are stripped from message text."""
        event = {
            "text": "<@U98765> what is the weather?",
            "user": "U12345",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        mock_agent.run.assert_called_once_with("what is the weather?")

    @pytest.mark.asyncio
    async def test_handle_message_empty_after_strip(self, slack_adapter, mock_agent):
        """Test that empty messages after mention strip are ignored."""
        event = {
            "text": "<@U98765>",
            "user": "U12345",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        mock_agent.run.assert_not_called()
        say.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_message_empty_text(self, slack_adapter, mock_agent):
        """Test that empty text messages are ignored."""
        event = {
            "text": "",
            "user": "U12345",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        mock_agent.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_message_agent_error(self, slack_adapter, mock_agent):
        """Test error handling when agent raises."""
        mock_agent.run = AsyncMock(side_effect=RuntimeError("agent error"))

        event = {
            "text": "trigger error",
            "user": "U12345",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        say.assert_called_once()
        assert "error" in say.call_args[1]["text"].lower()

    @pytest.mark.asyncio
    async def test_handle_message_uses_thread_ts(self, slack_adapter, mock_agent):
        """Test that thread_ts is used from event when present."""
        event = {
            "text": "reply in thread",
            "user": "U12345",
            "channel": "C12345",
            "thread_ts": "1234567890.000000",
            "ts": "1234567891.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        say.assert_called_once_with(
            text="Hello from the agent!",
            thread_ts="1234567890.000000",
        )

    @pytest.mark.asyncio
    async def test_send_message_with_app(self, slack_adapter):
        """Test send_message when app is initialized."""
        mock_app = MagicMock()
        mock_app.client.chat_postMessage = AsyncMock()
        slack_adapter._app = mock_app

        await slack_adapter.send_message("C12345", "hello", thread_id="1234.5678")

        mock_app.client.chat_postMessage.assert_called_once_with(
            channel="C12345",
            text="hello",
            thread_ts="1234.5678",
        )

    @pytest.mark.asyncio
    async def test_send_message_without_app(self, slack_adapter):
        """Test send_message when app is not initialized."""
        await slack_adapter.send_message("C12345", "hello")  # Should not raise

    @pytest.mark.asyncio
    async def test_handle_message_missing_user(self, slack_adapter, mock_agent):
        """Test handling message with missing user field."""
        event = {
            "text": "hello",
            "channel": "C12345",
            "ts": "1234567890.123456",
        }
        say = AsyncMock()

        await slack_adapter._handle_message(event, say)

        mock_agent.run.assert_called_once()
