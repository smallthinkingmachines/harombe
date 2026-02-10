"""Shared fixtures for CLI tests."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def tmp_config_path(tmp_path: Path) -> Path:
    """Provide a temporary config file path."""
    return tmp_path / "harombe.yaml"


@pytest.fixture
def mock_ollama_running():
    """Mock Ollama as running."""
    with patch(
        "harombe.hardware.detect.check_ollama_running",
        new_callable=AsyncMock,
        return_value=True,
    ) as m:
        yield m


@pytest.fixture
def mock_ollama_not_running():
    """Mock Ollama as not running."""
    with patch(
        "harombe.hardware.detect.check_ollama_running",
        new_callable=AsyncMock,
        return_value=False,
    ) as m:
        yield m


@pytest.fixture
def mock_ollama_models():
    """Mock Ollama models list."""
    with patch(
        "harombe.hardware.detect.get_ollama_models",
        new_callable=AsyncMock,
        return_value=["qwen2.5:7b", "llama3:8b", "codellama:7b", "mistral:7b"],
    ) as m:
        yield m


@pytest.fixture
def mock_ollama_no_models():
    """Mock Ollama with no models."""
    with patch(
        "harombe.hardware.detect.get_ollama_models",
        new_callable=AsyncMock,
        return_value=[],
    ) as m:
        yield m


@pytest.fixture
def mock_gpu_detected():
    """Mock GPU detection with NVIDIA GPU."""
    with patch(
        "harombe.hardware.detect.detect_gpu",
        return_value=("nvidia", 8.0),
    ) as m:
        yield m


@pytest.fixture
def mock_no_gpu():
    """Mock no GPU detection (CPU only)."""
    with patch(
        "harombe.hardware.detect.detect_gpu",
        return_value=("cpu", 0.0),
    ) as m:
        yield m


@pytest.fixture
def mock_apple_silicon():
    """Mock Apple Silicon detection."""
    with patch(
        "harombe.hardware.detect.detect_gpu",
        return_value=("apple_silicon", 9.6),
    ) as m:
        yield m
