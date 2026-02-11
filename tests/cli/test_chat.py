"""Tests for CLI chat command."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.cli.chat import _handle_slash_command, _load_plugins
from harombe.config.schema import HarombeConfig


@pytest.fixture
def config():
    """Create default HarombeConfig for tests."""
    return HarombeConfig()


class TestHandleSlashCommand:
    """Test _handle_slash_command dispatch."""

    def test_handle_slash_exit(self, config):
        """Test /exit returns True to signal exit."""
        with patch("harombe.cli.chat.console"):
            result = _handle_slash_command("/exit", config)
        assert result is True

    def test_handle_slash_quit(self, config):
        """Test /quit returns True to signal exit."""
        with patch("harombe.cli.chat.console"):
            result = _handle_slash_command("/quit", config)
        assert result is True

    def test_handle_slash_q(self, config):
        """Test /q returns True to signal exit."""
        with patch("harombe.cli.chat.console"):
            result = _handle_slash_command("/q", config)
        assert result is True

    def test_handle_slash_help(self, config):
        """Test /help prints commands and returns False."""
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/help", config)
        assert result is False
        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "Available commands" in output

    def test_handle_slash_clear(self, config):
        """Test /clear calls console.clear and returns False."""
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/clear", config)
        assert result is False
        mock_console.clear.assert_called_once()

    def test_handle_slash_model(self, config):
        """Test /model prints model info and returns False."""
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/model", config)
        assert result is False
        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert config.model.name in output

    def test_handle_slash_tools(self, config):
        """Test /tools lists tools and returns False."""
        mock_tool = MagicMock()
        mock_tool.schema.name = "test_tool"
        mock_tool.schema.description = "A test tool"
        mock_tool.schema.source = "builtin"
        mock_tool.schema.dangerous = False

        with (
            patch("harombe.cli.chat.console"),
            patch("harombe.cli.chat.get_enabled_tools_v2", return_value=[mock_tool]),
        ):
            result = _handle_slash_command("/tools", config)
        assert result is False

    def test_handle_slash_config(self, config):
        """Test /config prints configuration and returns False."""
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/config", config)
        assert result is False
        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "Configuration" in output

    def test_handle_slash_privacy_no_router(self, config):
        """Test /privacy with a non-PrivacyRouter LLM."""
        mock_llm = MagicMock()
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/privacy", config, llm=mock_llm)
        assert result is False
        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "local-only" in output

    def test_handle_slash_unknown(self, config):
        """Test unknown command prints error and returns False."""
        with patch("harombe.cli.chat.console") as mock_console:
            result = _handle_slash_command("/unknown_cmd", config)
        assert result is False
        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "Unknown command" in output


class TestChatCommand:
    """Test chat_command and helpers."""

    def test_chat_command_config_error(self):
        """Test chat_command prints error when config loading fails."""
        with (
            patch(
                "harombe.cli.chat.load_config",
                side_effect=Exception("Config not found"),
            ),
            patch("harombe.cli.chat.console") as mock_console,
        ):
            from harombe.cli.chat import chat_command

            chat_command(config_path="/nonexistent/path.yaml")

        output = " ".join(str(c) for c in mock_console.print.call_args_list)
        assert "Failed to load config" in output

    def test_load_plugins(self, config):
        """Test _load_plugins discovers and applies permissions."""
        with (
            patch("harombe.plugins.loader.PluginLoader") as mock_loader_cls,
            patch("harombe.plugins.sandbox.apply_plugin_permissions"),
        ):
            mock_loader = MagicMock()
            mock_loader.discover_all.return_value = []
            mock_loader_cls.return_value = mock_loader

            _load_plugins(config)
            mock_loader.discover_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_mcp(self, config):
        """Test _connect_mcp creates manager and connects."""
        from harombe.cli.chat import _connect_mcp

        mock_server = MagicMock()
        mock_server.name = "test"
        config.mcp.external_servers = [mock_server]

        with patch("harombe.mcp.manager.MCPManager") as mock_mgr_cls:
            mock_mgr = MagicMock()
            mock_mgr.connect_all = AsyncMock()
            mock_mgr.add_server = MagicMock()
            mock_mgr_cls.return_value = mock_mgr

            result = await _connect_mcp(config)

            mock_mgr.connect_all.assert_called_once()
            assert result is mock_mgr
