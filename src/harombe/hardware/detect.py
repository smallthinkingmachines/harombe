"""Hardware detection for automatic model selection."""

import platform
import subprocess
from typing import Optional, Tuple

import httpx

from harombe.config.defaults import get_default_model, select_model_for_vram


def detect_gpu() -> Tuple[str, float]:
    """Detect GPU type and available VRAM.

    Returns:
        Tuple of (gpu_type, vram_gb) where gpu_type is one of:
        "apple_silicon", "nvidia", "amd", "cpu"
    """
    system = platform.system()

    # Apple Silicon detection
    if system == "Darwin":
        machine = platform.machine()
        if machine in ("arm64", "aarch64"):
            # Apple Silicon - use unified memory
            vram = _get_apple_unified_memory()
            return ("apple_silicon", vram)

    # NVIDIA GPU detection
    nvidia_vram = _get_nvidia_vram()
    if nvidia_vram > 0:
        return ("nvidia", nvidia_vram)

    # AMD GPU detection
    amd_vram = _get_amd_vram()
    if amd_vram > 0:
        return ("amd", amd_vram)

    # Fallback to CPU
    return ("cpu", 0.0)


def _get_apple_unified_memory() -> float:
    """Get Apple Silicon unified memory in GB.

    Returns:
        Unified memory size in GB
    """
    try:
        # Use sysctl to get total memory
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            bytes_total = int(result.stdout.strip())
            gb = bytes_total / (1024**3)
            # Use 60% of total memory as "available" for LLM
            return gb * 0.6

    except Exception:
        pass

    return 8.0  # Conservative fallback for Apple Silicon


def _get_nvidia_vram() -> float:
    """Get NVIDIA GPU VRAM in GB.

    Returns:
        Total VRAM in GB, or 0 if no NVIDIA GPU detected
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # nvidia-smi returns MiB
            mib = float(result.stdout.strip().split("\n")[0])
            return mib / 1024.0

    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass

    return 0.0


def _get_amd_vram() -> float:
    """Get AMD GPU VRAM in GB.

    Returns:
        Total VRAM in GB, or 0 if no AMD GPU detected
    """
    try:
        # Try rocm-smi for AMD GPUs
        result = subprocess.run(
            ["rocm-smi", "--showmeminfo", "vram"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Parse output - format varies, try to extract number
            for line in result.stdout.split("\n"):
                if "Total" in line or "VRAM" in line:
                    # Extract first number that looks like memory size
                    parts = line.split()
                    for part in parts:
                        try:
                            # Assume MiB
                            mib = float(part)
                            if 1000 < mib < 100000:  # Sanity check
                                return mib / 1024.0
                        except ValueError:
                            continue

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return 0.0


async def get_ollama_models(base_url: str = "http://localhost:11434") -> list[str]:
    """Get list of models currently available in Ollama.

    Args:
        base_url: Ollama server base URL

    Returns:
        List of model names (e.g., ["qwen2.5:7b", "llama3:8b"])
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{base_url}/api/tags")
            response.raise_for_status()

            data = response.json()
            models = [model["name"] for model in data.get("models", [])]
            return models

    except Exception:
        return []


async def check_ollama_running(base_url: str = "http://localhost:11434") -> bool:
    """Check if Ollama server is running.

    Args:
        base_url: Ollama server base URL

    Returns:
        True if Ollama is accessible, False otherwise
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{base_url}/api/tags")
            return response.status_code == 200
    except Exception:
        return False


def recommend_model() -> Tuple[str, str]:
    """Recommend a model based on detected hardware.

    Returns:
        Tuple of (model_name, reason) with human-readable explanation
    """
    gpu_type, vram_gb = detect_gpu()

    if gpu_type == "cpu":
        return (
            "qwen2.5:1.5b",
            "No GPU detected - using smallest model for CPU inference",
        )

    model = select_model_for_vram(vram_gb)

    reason = f"Detected {gpu_type.replace('_', ' ').title()} with {vram_gb:.1f}GB VRAM"
    return (model, reason)
