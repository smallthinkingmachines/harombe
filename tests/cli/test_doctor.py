"""Tests for CLI doctor command."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.cli.doctor import _async_doctor

MODULE = "harombe.cli.doctor"


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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config") as mock_load,
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config"),
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

    with patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path):
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config", side_effect=Exception("parse error")),
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

    with patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path):
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

    with patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path):
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

    with patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path):
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config") as mock_load,
    ):
        from harombe.config.schema import HarombeConfig

        cfg = HarombeConfig()
        cfg.model.name = "missing-model:latest"
        mock_load.return_value = cfg

        with patch(
            f"{MODULE}.get_ollama_models",
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config") as mock_load,
    ):
        from harombe.config.schema import HarombeConfig

        cfg = HarombeConfig()
        cfg.model.name = "qwen2.5:7b"
        mock_load.return_value = cfg

        with patch(
            f"{MODULE}.get_ollama_models",
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path),
        patch(
            f"{MODULE}.get_ollama_models",
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
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config", side_effect=load_side_effect),
        patch(
            f"{MODULE}.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ),
    ):
        await _async_doctor()


@pytest.mark.asyncio
async def test_doctor_command_sync_wrapper():
    """Test that doctor_command calls asyncio.run with _async_doctor."""
    with patch(f"{MODULE}.asyncio") as mock_asyncio:
        with patch(f"{MODULE}.console"):
            from harombe.cli.doctor import doctor_command

            doctor_command()

        mock_asyncio.run.assert_called_once()


@pytest.mark.asyncio
async def test_doctor_all_healthy_console_output(tmp_path):
    """Verify no issues/warnings appear when everything is healthy."""
    config_path = tmp_path / "harombe.yaml"
    config_path.write_text("model:\n  name: qwen2.5:7b\n")

    printed: list[str] = []

    def capture_print(*args, **kwargs):
        printed.append(" ".join(str(a) for a in args))

    from harombe.config.schema import HarombeConfig

    cfg = HarombeConfig()
    cfg.model.name = "qwen2.5:7b"

    with (
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", config_path),
        patch(f"{MODULE}.load_config", return_value=cfg),
        patch(f"{MODULE}.console") as mock_console,
        patch(
            f"{MODULE}.check_ollama_running",
            new_callable=AsyncMock,
            return_value=True,
        ),
        patch(
            f"{MODULE}.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ),
        patch(f"{MODULE}.detect_gpu", return_value=("apple_silicon", 19.2)),
    ):
        mock_console.print = MagicMock(side_effect=capture_print)
        await _async_doctor()

    all_output = " ".join(printed)
    # "All checks passed" is inside a Panel object; verify no issues appeared
    assert "Issues Found" not in all_output
    assert "Warnings" not in all_output


@pytest.mark.asyncio
async def test_doctor_ollama_not_running_console_output(tmp_path):
    """Verify 'Issues Found' appears when Ollama is not running."""
    missing_path = tmp_path / "nonexistent.yaml"

    printed: list[str] = []

    def capture_print(*args, **kwargs):
        printed.append(" ".join(str(a) for a in args))

    with (
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path),
        patch(f"{MODULE}.console") as mock_console,
        patch(
            f"{MODULE}.check_ollama_running",
            new_callable=AsyncMock,
            return_value=False,
        ),
        patch(f"{MODULE}.detect_gpu", return_value=("nvidia", 8.0)),
    ):
        mock_console.print = MagicMock(side_effect=capture_print)
        await _async_doctor()

    all_output = " ".join(printed)
    assert "Issues Found" in all_output


@pytest.mark.asyncio
async def test_doctor_warnings_only_console_output(tmp_path):
    """When there are only warnings (no issues), verify the 'No critical issues' message."""
    missing_path = tmp_path / "nonexistent.yaml"

    printed: list[str] = []

    def capture_print(*args, **kwargs):
        printed.append(" ".join(str(a) for a in args))

    with (
        patch(f"{MODULE}.DEFAULT_CONFIG_PATH", missing_path),
        patch(f"{MODULE}.console") as mock_console,
        patch(
            f"{MODULE}.check_ollama_running",
            new_callable=AsyncMock,
            return_value=True,
        ),
        patch(
            f"{MODULE}.get_ollama_models",
            new_callable=AsyncMock,
            return_value=["qwen2.5:7b"],
        ),
        patch(f"{MODULE}.detect_gpu", return_value=("cpu", 0.0)),
    ):
        mock_console.print = MagicMock(side_effect=capture_print)
        await _async_doctor()

    all_output = " ".join(printed)
    assert "Warnings" in all_output
    assert "No critical issues" in all_output
