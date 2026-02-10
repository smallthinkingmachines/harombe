"""Tests for CLI doctor command."""

from unittest.mock import AsyncMock, patch

import pytest

from harombe.cli.doctor import _async_doctor


@pytest.mark.asyncio
async def test_doctor_all_healthy(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
    mock_gpu_detected,
):
    """Test doctor with all checks passing."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config") as mock_load,
    ):
        from harombe.config.schema import HarombeConfig

        cfg = HarombeConfig()
        cfg.model.name = "qwen2.5:7b"
        mock_load.return_value = cfg

        # Should not raise
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_ollama_not_running(
    tmp_path,
    mock_ollama_not_running,
    mock_gpu_detected,
):
    """Test doctor when Ollama is not running."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config"),
    ):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_no_config_file(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
    mock_gpu_detected,
):
    """Test doctor with missing config file."""
    missing_path = tmp_path / "nonexistent.yaml"

    with patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", missing_path):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_invalid_config(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
    mock_gpu_detected,
):
    """Test doctor with invalid config file."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config", side_effect=Exception("parse error")),
    ):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_no_gpu(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
    mock_no_gpu,
):
    """Test doctor with CPU only (no GPU)."""
    missing_path = tmp_path / "nonexistent.yaml"

    with patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", missing_path):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_apple_silicon(
    tmp_path,
    mock_ollama_running,
    mock_ollama_models,
    mock_apple_silicon,
):
    """Test doctor with Apple Silicon GPU."""
    missing_path = tmp_path / "nonexistent.yaml"

    with patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", missing_path):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_no_models(
    tmp_path,
    mock_ollama_running,
    mock_ollama_no_models,
    mock_gpu_detected,
):
    """Test doctor when Ollama has no models installed."""
    missing_path = tmp_path / "nonexistent.yaml"

    with patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", missing_path):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_model_not_available(
    tmp_path,
    mock_ollama_running,
    mock_gpu_detected,
):
    """Test doctor when configured model is not in Ollama."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: missing-model:latest\n")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config") as mock_load,
    ):
        from harombe.config.schema import HarombeConfig

        cfg = HarombeConfig()
        cfg.model.name = "missing-model:latest"
        mock_load.return_value = cfg

        with patch(
            "harombe.cli.doctor.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ):
            await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_model_available(
    tmp_path,
    mock_ollama_running,
    mock_gpu_detected,
):
    """Test doctor when configured model IS available in Ollama."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config") as mock_load,
    ):
        from harombe.config.schema import HarombeConfig

        cfg = HarombeConfig()
        cfg.model.name = "qwen2.5:7b"
        mock_load.return_value = cfg

        with patch(
            "harombe.cli.doctor.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b", "llama3:8b"],
        ):
            await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_many_models(
    tmp_path,
    mock_ollama_running,
    mock_gpu_detected,
):
    """Test doctor display with more than 3 models (triggers truncation)."""
    missing_path = tmp_path / "nonexistent.yaml"

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", missing_path),
        patch(
            "harombe.cli.doctor.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["model1", "model2", "model3", "model4", "model5"],
        ),
    ):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_config_check_with_load_error(
    tmp_path,
    mock_ollama_running,
    mock_gpu_detected,
):
    """Test doctor when config exists but secondary load_config fails for model check."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    call_count = 0

    def load_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            from harombe.config.schema import HarombeConfig

            cfg = HarombeConfig()
            cfg.model.name = "qwen2.5:7b"
            return cfg
        raise Exception("load failed second time")

    with (
        patch("harombe.cli.doctor.DEFAULT_CONFIG_PATH", config_path),
        patch("harombe.cli.doctor.load_config", side_effect=load_side_effect),
        patch(
            "harombe.cli.doctor.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ),
    ):
        await _async_doctor()
