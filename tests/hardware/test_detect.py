"""Tests for hardware detection module."""

import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.config.defaults import select_model_for_vram
from harombe.hardware.detect import (
    _get_amd_vram,
    _get_apple_unified_memory,
    _get_nvidia_vram,
    check_ollama_running,
    detect_gpu,
    get_ollama_models,
    recommend_model,
)

# -- detect_gpu -----------------------------------------------------------------


def test_detect_gpu_apple_silicon():
    with (
        patch("harombe.hardware.detect.platform") as mock_platform,
        patch("harombe.hardware.detect._get_apple_unified_memory", return_value=19.2),
    ):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "arm64"
        gpu_type, vram = detect_gpu()
    assert gpu_type == "apple_silicon"
    assert vram == pytest.approx(19.2)


def test_detect_gpu_darwin_intel():
    with (
        patch("harombe.hardware.detect.platform") as mock_platform,
        patch("harombe.hardware.detect._get_nvidia_vram", return_value=0.0),
        patch("harombe.hardware.detect._get_amd_vram", return_value=0.0),
    ):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "x86_64"
        gpu_type, vram = detect_gpu()
    assert gpu_type == "cpu"
    assert vram == 0.0


def test_detect_gpu_nvidia():
    with (
        patch("harombe.hardware.detect.platform") as mock_platform,
        patch("harombe.hardware.detect._get_nvidia_vram", return_value=8.0),
    ):
        mock_platform.system.return_value = "Linux"
        gpu_type, vram = detect_gpu()
    assert gpu_type == "nvidia"
    assert vram == 8.0


def test_detect_gpu_amd():
    with (
        patch("harombe.hardware.detect.platform") as mock_platform,
        patch("harombe.hardware.detect._get_nvidia_vram", return_value=0.0),
        patch("harombe.hardware.detect._get_amd_vram", return_value=8.0),
    ):
        mock_platform.system.return_value = "Linux"
        gpu_type, vram = detect_gpu()
    assert gpu_type == "amd"
    assert vram == 8.0


def test_detect_gpu_cpu_fallback():
    with (
        patch("harombe.hardware.detect.platform") as mock_platform,
        patch("harombe.hardware.detect._get_nvidia_vram", return_value=0.0),
        patch("harombe.hardware.detect._get_amd_vram", return_value=0.0),
    ):
        mock_platform.system.return_value = "Linux"
        gpu_type, vram = detect_gpu()
    assert gpu_type == "cpu"
    assert vram == 0.0


# -- _get_apple_unified_memory ---------------------------------------------------


def test_get_apple_unified_memory_success():
    result = subprocess.CompletedProcess(args=[], returncode=0, stdout="34359738368\n")
    with patch("harombe.hardware.detect.subprocess.run", return_value=result):
        gb = _get_apple_unified_memory()
    expected = 34359738368 / (1024**3) * 0.6
    assert gb == pytest.approx(expected)


def test_get_apple_unified_memory_failure():
    with patch("harombe.hardware.detect.subprocess.run", side_effect=Exception("fail")):
        assert _get_apple_unified_memory() == 8.0


# -- _get_nvidia_vram ------------------------------------------------------------


def test_get_nvidia_vram_success():
    result = subprocess.CompletedProcess(args=[], returncode=0, stdout="8192\n")
    with patch("harombe.hardware.detect.subprocess.run", return_value=result):
        assert _get_nvidia_vram() == pytest.approx(8.0)


def test_get_nvidia_vram_not_found():
    with patch(
        "harombe.hardware.detect.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        assert _get_nvidia_vram() == 0.0


# -- _get_amd_vram ---------------------------------------------------------------


def test_get_amd_vram_success():
    stdout = "GPU[0]\tTotal Memory\t8192 MiB\n"
    result = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout)
    with patch("harombe.hardware.detect.subprocess.run", return_value=result):
        assert _get_amd_vram() == pytest.approx(8.0)


def test_get_amd_vram_not_found():
    with patch(
        "harombe.hardware.detect.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        assert _get_amd_vram() == 0.0


# -- async helpers ---------------------------------------------------------------


async def test_get_ollama_models_success():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"models": [{"name": "qwen2.5:7b"}, {"name": "llama3:8b"}]}

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("harombe.hardware.detect.httpx.AsyncClient", return_value=mock_client):
        models = await get_ollama_models("http://localhost:11434")
    assert models == ["qwen2.5:7b", "llama3:8b"]


async def test_get_ollama_models_failure():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(side_effect=Exception("connection refused"))

    with patch("harombe.hardware.detect.httpx.AsyncClient", return_value=mock_client):
        models = await get_ollama_models("http://localhost:11434")
    assert models == []


async def test_check_ollama_running_true():
    mock_response = MagicMock()
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("harombe.hardware.detect.httpx.AsyncClient", return_value=mock_client):
        assert await check_ollama_running("http://localhost:11434") is True


async def test_check_ollama_running_false():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(side_effect=Exception("refused"))

    with patch("harombe.hardware.detect.httpx.AsyncClient", return_value=mock_client):
        assert await check_ollama_running("http://localhost:11434") is False


# -- recommend_model -------------------------------------------------------------


def test_recommend_model_cpu():
    with patch("harombe.hardware.detect.detect_gpu", return_value=("cpu", 0.0)):
        model, reason = recommend_model()
    assert model == "qwen2.5:1.5b"
    assert "No GPU" in reason


def test_recommend_model_gpu():
    with patch("harombe.hardware.detect.detect_gpu", return_value=("nvidia", 12.0)):
        model, reason = recommend_model()
    assert model == select_model_for_vram(12.0)
    assert "Nvidia" in reason
