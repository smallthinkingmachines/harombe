"""Tests for CLI server commands."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from harombe.cli.server_cmd import start_command, status_command, stop_command
from harombe.config.schema import HarombeConfig


def test_start_command_loads_config_and_runs():
    """Test start command loads config and starts uvicorn."""
    with patch("harombe.config.loader.load_config") as mock_load:
        config = HarombeConfig()
        config.server.host = "0.0.0.0"
        config.server.port = 9000
        mock_load.return_value = config

        with (
            patch("harombe.server.app.create_app") as mock_app,
            patch("uvicorn.run") as mock_uvicorn_run,
        ):
            mock_app.return_value = MagicMock()

            start_command(config_path=None)

            mock_uvicorn_run.assert_called_once_with(
                mock_app.return_value,
                host="0.0.0.0",
                port=9000,
                log_level="info",
            )


def test_start_command_with_custom_config_path(tmp_path):
    """Test start command with a custom config path."""
    config_path = str(tmp_path / "custom.yaml")

    with patch("harombe.config.loader.load_config") as mock_load:
        config = HarombeConfig()
        mock_load.return_value = config

        with patch("harombe.server.app.create_app") as mock_app:
            mock_app.return_value = MagicMock()

            with patch("uvicorn.run"):
                start_command(config_path=config_path)

                mock_load.assert_called_once_with(Path(config_path))


def test_start_command_config_load_failure():
    """Test start command handles config load failure gracefully."""
    with patch(
        "harombe.config.loader.load_config",
        side_effect=Exception("config not found"),
    ):
        # Should not raise, just print error
        start_command(config_path=None)


def test_stop_command():
    """Test stop command prints message."""
    # Should not raise
    stop_command()


def test_status_command():
    """Test status command prints message."""
    # Should not raise
    status_command()
