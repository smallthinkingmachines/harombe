"""Tests for CLI MCP commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from harombe.config.schema import HarombeConfig


def test_serve_stdio_transport():
    """Test serve command with stdio transport."""
    with (
        patch("harombe.config.loader.load_config") as mock_load,
        patch("harombe.tools.registry.get_enabled_tools", return_value=[]),
        patch("harombe.mcp.server.create_mcp_server") as mock_server,
        patch("harombe.mcp.transports.run_stdio_server"),
        patch("harombe.cli.mcp_cmd.asyncio.run"),
    ):
        mock_load.return_value = HarombeConfig()
        mock_server.return_value = MagicMock()

        from harombe.cli.mcp_cmd import serve_command

        serve_command(transport="stdio")


def test_serve_http_transport():
    """Test serve command with HTTP transport."""
    with patch("harombe.config.loader.load_config") as mock_load:
        mock_load.return_value = HarombeConfig()

        with (
            patch("harombe.tools.registry.get_enabled_tools", return_value=[]),
            patch("harombe.mcp.server.create_mcp_server") as mock_server,
        ):
            mock_server.return_value = MagicMock()

            with (
                patch("harombe.mcp.transports.run_streamable_http_server"),
                patch("harombe.cli.mcp_cmd.asyncio.run"),
            ):
                from harombe.cli.mcp_cmd import serve_command

                serve_command(transport="http", host="0.0.0.0", port=9200)


def test_serve_streamable_http_transport():
    """Test serve command with streamable-http transport."""
    with patch("harombe.config.loader.load_config") as mock_load:
        mock_load.return_value = HarombeConfig()

        with (
            patch("harombe.tools.registry.get_enabled_tools", return_value=[]),
            patch("harombe.mcp.server.create_mcp_server") as mock_server,
        ):
            mock_server.return_value = MagicMock()

            with (
                patch("harombe.mcp.transports.run_streamable_http_server"),
                patch("harombe.cli.mcp_cmd.asyncio.run"),
            ):
                from harombe.cli.mcp_cmd import serve_command

                serve_command(transport="streamable-http")


def test_serve_unknown_transport():
    """Test serve command with unknown transport type."""
    with patch("harombe.config.loader.load_config") as mock_load:
        mock_load.return_value = HarombeConfig()

        with (
            patch("harombe.tools.registry.get_enabled_tools", return_value=[]),
            patch("harombe.mcp.server.create_mcp_server"),
        ):
            from harombe.cli.mcp_cmd import serve_command

            # Should not raise, just print error
            serve_command(transport="grpc")


def test_serve_config_load_failure():
    """Test serve command with config load failure."""
    with patch(
        "harombe.config.loader.load_config",
        side_effect=Exception("config not found"),
    ):
        from harombe.cli.mcp_cmd import serve_command

        # Should not raise
        serve_command()


def test_serve_custom_config_path(tmp_path):
    """Test serve command with custom config path."""
    config_path = str(tmp_path / "custom.yaml")

    with patch("harombe.config.loader.load_config") as mock_load:
        mock_load.return_value = HarombeConfig()

        with (
            patch("harombe.tools.registry.get_enabled_tools", return_value=[]),
            patch("harombe.mcp.server.create_mcp_server") as mock_server,
        ):
            mock_server.return_value = MagicMock()

            with (
                patch("harombe.mcp.transports.run_stdio_server"),
                patch("harombe.cli.mcp_cmd.asyncio.run"),
            ):
                from harombe.cli.mcp_cmd import serve_command

                serve_command(config_path=config_path)

                mock_load.assert_called_with(Path(config_path))


def test_serve_tools_enabled_flags():
    """Test serve command respects tool configuration flags."""
    config = HarombeConfig()
    config.tools.shell = False
    config.tools.filesystem = True
    config.tools.web_search = False

    with (
        patch("harombe.config.loader.load_config", return_value=config),
        patch("harombe.tools.registry.get_enabled_tools") as mock_tools,
    ):
        mock_tools.return_value = []

        with patch("harombe.mcp.server.create_mcp_server") as mock_server:
            mock_server.return_value = MagicMock()

            with (
                patch("harombe.mcp.transports.run_stdio_server"),
                patch("harombe.cli.mcp_cmd.asyncio.run"),
            ):
                from harombe.cli.mcp_cmd import serve_command

                serve_command()

                mock_tools.assert_called_once_with(
                    shell=False,
                    filesystem=True,
                    web_search=False,
                )
