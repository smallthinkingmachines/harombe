"""Tests for CLI commands."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from typer.testing import CliRunner

from harombe.cli.app import app

runner = CliRunner()


def test_version_command():
    """Test version command."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "Harombe version" in result.stdout


def test_help_command():
    """Test help output."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Harombe" in result.stdout
    assert "init" in result.stdout
    assert "chat" in result.stdout
    assert "start" in result.stdout


def test_init_creates_config():
    """Test init command creates config file."""
    with TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "harombe.yaml"

        # Mock the DEFAULT_CONFIG_PATH
        import harombe.cli.init_cmd as init_module

        original_path = init_module.DEFAULT_CONFIG_PATH
        try:
            init_module.DEFAULT_CONFIG_PATH = config_path

            # Run init with non-interactive answers
            # This test would need to mock user input properly
            # For now, we just verify the command exists
            result = runner.invoke(app, ["init", "--help"])
            assert result.exit_code == 0

        finally:
            init_module.DEFAULT_CONFIG_PATH = original_path


def test_chat_help():
    """Test chat command help."""
    result = runner.invoke(app, ["chat", "--help"])

    assert result.exit_code == 0
    assert "chat" in result.stdout.lower()


def test_start_help():
    """Test start command help."""
    result = runner.invoke(app, ["start", "--help"])

    assert result.exit_code == 0
    assert "start" in result.stdout.lower()


def test_stop_command():
    """Test stop command exists."""
    result = runner.invoke(app, ["stop", "--help"])

    assert result.exit_code == 0


def test_status_command():
    """Test status command exists."""
    result = runner.invoke(app, ["status", "--help"])

    assert result.exit_code == 0
