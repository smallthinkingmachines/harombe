"""Tests for CLI init command."""

from unittest.mock import AsyncMock, patch

import pytest
import typer

from harombe.cli.init_cmd import _async_init, init_command
from harombe.config.schema import HarombeConfig


@pytest.mark.asyncio
async def test_async_init_non_interactive_ollama_running(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
):
    """Test non-interactive init with Ollama running."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config") as mock_save,
    ):
        await _async_init(non_interactive=True)

        mock_save.assert_called_once()
        config = mock_save.call_args[0][0]
        assert isinstance(config, HarombeConfig)
        assert config.model.name == "qwen2.5:7b"


@pytest.mark.asyncio
async def test_async_init_non_interactive_ollama_not_running(
    mock_ollama_not_running,
):
    """Test non-interactive init when Ollama is not running."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config") as mock_save,
    ):
        await _async_init(non_interactive=True)

        mock_save.assert_called_once()


@pytest.mark.asyncio
async def test_async_init_model_override(
    mock_ollama_running,
    mock_ollama_models,
):
    """Test init with model override."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config") as mock_save,
    ):
        await _async_init(non_interactive=True, model_override="llama3:8b")

        config = mock_save.call_args[0][0]
        assert config.model.name == "llama3:8b"


@pytest.mark.asyncio
async def test_async_init_model_not_in_ollama(
    mock_ollama_running,
):
    """Test init when recommended model is not in Ollama."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:14b", "GPU detected")),
        patch(
            "harombe.cli.init_cmd.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ),
        patch("harombe.cli.init_cmd.save_config"),
    ):
        await _async_init(non_interactive=True)


@pytest.mark.asyncio
async def test_async_init_no_models_available(
    mock_ollama_running,
    mock_ollama_no_models,
):
    """Test init when Ollama has no models."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config"),
    ):
        await _async_init(non_interactive=True)


def test_init_command_config_exists(tmp_path):
    """Test init refuses to overwrite existing config without --force."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: test\n")

    with patch("harombe.cli.init_cmd.DEFAULT_CONFIG_PATH", config_path), pytest.raises(typer.Exit):
        init_command(force=False, non_interactive=True)


def test_init_command_force_overwrite(tmp_path):
    """Test init with --force overwrites existing config."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: test\n")

    with (
        patch("harombe.cli.init_cmd.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.init_cmd.asyncio.run") as mock_run,
    ):
        init_command(force=True, non_interactive=True)
        mock_run.assert_called_once()


def test_init_command_no_existing_config(tmp_path):
    """Test init creates config when none exists."""
    config_path = tmp_path / "nonexistent.yaml"

    with (
        patch("harombe.cli.init_cmd.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.init_cmd.asyncio.run") as mock_run,
    ):
        init_command(force=False, non_interactive=True)
        mock_run.assert_called_once()


@pytest.mark.asyncio
async def test_async_init_interactive_decline_continue(
    mock_ollama_not_running,
):
    """Test interactive init where user declines to continue without Ollama."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.Confirm.ask", return_value=False),
        pytest.raises(typer.Exit),
    ):
        await _async_init(non_interactive=False)


@pytest.mark.asyncio
async def test_async_init_interactive_continue_without_ollama(
    mock_ollama_not_running,
):
    """Test interactive init where user continues without Ollama."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.Confirm.ask", return_value=True),
        patch("harombe.cli.init_cmd.save_config"),
        # Second Confirm.ask for "Customize settings?" returns False
        patch(
            "harombe.cli.init_cmd.Confirm.ask",
            side_effect=[True, False],
        ),
    ):
        await _async_init(non_interactive=False)


@pytest.mark.asyncio
async def test_async_init_interactive_customize_settings(
    mock_ollama_running,
    mock_ollama_models,
):
    """Test interactive init with customized settings."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config") as mock_save,
        patch(
            "harombe.cli.init_cmd.Confirm.ask",
            return_value=True,
        ),
        patch(
            "harombe.cli.init_cmd.Prompt.ask",
            side_effect=["custom-model:latest", "0.5", "15"],
        ),
    ):
        await _async_init(non_interactive=False)

        config = mock_save.call_args[0][0]
        assert config.model.name == "custom-model:latest"
        assert config.model.temperature == 0.5
        assert config.agent.max_steps == 15


@pytest.mark.asyncio
async def test_async_init_interactive_invalid_temperature(
    mock_ollama_running,
    mock_ollama_models,
):
    """Test interactive init with invalid temperature input."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config"),
        patch("harombe.cli.init_cmd.Confirm.ask", return_value=True),
        patch(
            "harombe.cli.init_cmd.Prompt.ask",
            side_effect=["qwen2.5:7b", "not-a-number", "10"],
        ),
    ):
        await _async_init(non_interactive=False)


@pytest.mark.asyncio
async def test_async_init_interactive_invalid_max_steps(
    mock_ollama_running,
    mock_ollama_models,
):
    """Test interactive init with invalid max steps input."""
    with (
        patch("harombe.cli.init_cmd.recommend_model", return_value=("qwen2.5:7b", "GPU detected")),
        patch("harombe.cli.init_cmd.save_config"),
        patch("harombe.cli.init_cmd.Confirm.ask", return_value=True),
        patch(
            "harombe.cli.init_cmd.Prompt.ask",
            side_effect=["qwen2.5:7b", "0.7", "not-a-number"],
        ),
    ):
        await _async_init(non_interactive=False)
